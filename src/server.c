#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/select.h>
#include <sys/time.h>
#include "server.h"
#include "resp.h"

typedef struct EmitCtx { int fd; } EmitCtx;
static int emit_xrange_entry_cb(void *ctx,
                                const char *id, size_t idlen,
                                const char **fkeys, const size_t *fklen,
                                const char **fvals, const size_t *fvlen,
                                size_t npairs)
{
    int fd = ((EmitCtx*)ctx)->fd;
    if (reply_array_header(fd, 2) != 0) return -1;
    if (reply_bulk(fd, id, idlen) != 0) return -1;
    if (reply_array_header(fd, npairs * 2) != 0) return -1;
    for (size_t i = 0; i < npairs; i++)
    {
        if (reply_bulk(fd, fkeys[i], fklen[i]) != 0) return -1;
        if (reply_bulk(fd, fvals[i], fvlen[i]) != 0) return -1;
    }
    return 0;
}
int server_listen(Server *srv, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
    {
        printf("Socket creation failed: %s...\n", strerror(errno));
        return -1;
    }
    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        printf("SO_REUSEADDR failed: %s \n", strerror(errno));
        close(fd);
        return -1;
    }
    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)port),
        .sin_addr = {htonl(INADDR_ANY)},
    };
    if (bind(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0)
    {
        printf("Bind failed: %s \n", strerror(errno));
        close(fd);
        return -1;
    }
    int backlog = 5;
    if (listen(fd, backlog) != 0)
    {
        printf("Listen failed: %s \n", strerror(errno));
        close(fd);
        return -1;
    }
    srv->listen_fd = fd;
    return 0;
}

int server_event_loop(Server *srv)
{
    printf("Waiting for clients...\n");

    Conn conns[FD_SETSIZE];
    for (int i = 0; i < FD_SETSIZE; i++)
    {
        conns[i].buf = NULL;
        conns[i].len = 0;
        conns[i].cap = 0;
        conns[i].active = 0;
        conns[i].blocked = 0;
    }

    fd_set master_set, read_fds;
    FD_ZERO(&master_set);
    FD_SET(srv->listen_fd, &master_set);
    int fdmax = srv->listen_fd;

    struct sockaddr_in client_addr; int client_addr_len = 0;

    while (1)
    {
        read_fds = master_set;
        struct timeval *ptv = NULL; struct timeval tv;
        int64_t next_deadline = server_next_waiter_deadline(srv);
        if (next_deadline > 0)
        {
            int64_t now = now_ms();
            int64_t diff = next_deadline - now;
            if (diff < 0) diff = 0;
            tv.tv_sec = (time_t)(diff / 1000);
            tv.tv_usec = (suseconds_t)((diff % 1000) * 1000);
            ptv = &tv;
        }
        int activity = select(fdmax + 1, &read_fds, NULL, NULL, ptv);
        if (activity < 0)
        {
            if (errno == EINTR) continue;
            printf("select() failed: %s\n", strerror(errno));
            break;
        }
        if (activity == 0)
        {
            // timeout elapsed: handle waiter timeouts
            server_timeout_waiters(srv, conns);
            continue;
        }
        for (int fd = 0; fd <= fdmax; fd++)
        {
            if (!FD_ISSET(fd, &read_fds)) continue;
            if (fd == srv->listen_fd)
            {
                client_addr_len = sizeof(client_addr);
                int cfd = accept(srv->listen_fd, (struct sockaddr *)&client_addr, &client_addr_len);
                if (cfd == -1)
                {
                    printf("Accept failed: %s\n", strerror(errno));
                    continue;
                }
                FD_SET(cfd, &master_set);
                if (cfd > fdmax) fdmax = cfd;
                conns[cfd].active = 1; conns[cfd].len = 0;
                if (conns[cfd].cap == 0)
                {
                    conns[cfd].cap = 8192;
                    conns[cfd].buf = malloc(conns[cfd].cap);
                    if (!conns[cfd].buf)
                    {
                        printf("malloc failed for connection buffer\n");
                        close(cfd); FD_CLR(cfd, &master_set); conns[cfd].active = 0;
                    }
                }
                continue;
            }
            // existing client
            if (conns[fd].blocked)
            {
                // Skip reading from blocked client (waiting on BLPOP)
                continue;
            }
            char rbuf[4096];
            ssize_t r = read(fd, rbuf, sizeof(rbuf));
            if (r > 0)
            {
                Conn *c = &conns[fd];
                if (!c->active) c->active = 1;
                if (ensure_capacity(&conns[fd], c->len + (size_t)r) != 0)
                {
                    printf("Buffer alloc failed (fd=%d)\n", fd);
                    close(fd); FD_CLR(fd, &master_set); c->active = 0; continue;
                }
                memcpy(c->buf + c->len, rbuf, (size_t)r);
                c->len += (size_t)r;
                if (process_conn(fd, c, &srv->db) != 0)
                {
                    close(fd); FD_CLR(fd, &master_set); c->active = 0; continue;
                }
                // After processing commands, try serving any waiters that can be fulfilled
                server_serve_waiters(srv, conns);
            }
            else if (r == 0)
            {
                server_remove_waiter_by_fd(srv, &conns[fd], fd);
                close(fd); FD_CLR(fd, &master_set); conns[fd].active = 0;
            }
            else
            {
                printf("Read failed (fd=%d): %s\n", fd, strerror(errno));
                server_remove_waiter_by_fd(srv, &conns[fd], fd);
                close(fd); FD_CLR(fd, &master_set); conns[fd].active = 0;
            }
        }
    }

    return 0;
}

void server_add_waiter(Server *srv, Conn *c, int fd, const char *key, size_t klen, int64_t deadline_ms)
{
    if (!srv) return;
    BlockedWaiter *w = (BlockedWaiter *)calloc(1, sizeof(BlockedWaiter));
    if (!w) return;
    w->fd = fd;
    w->key = (char *)malloc(klen);
    if (!w->key && klen > 0) { free(w); return; }
    if (klen > 0) memcpy(w->key, key, klen);
    w->klen = klen;
    w->deadline_ms = deadline_ms;
    w->type = WAIT_LIST_BLPOP;
    w->next = NULL;

    // append to tail to preserve FIFO across all waiters
    if (!srv->waiters)
        srv->waiters = w;
    else
    {
        BlockedWaiter *t = srv->waiters;
        while (t->next) t = t->next;
        t->next = w;
    }
    if (c) c->blocked = 1;
}

void server_add_stream_waiter(Server *srv, Conn *c, int fd, const char *key, size_t klen,
                              uint64_t start_ms, uint64_t start_seq, int64_t deadline_ms)
{
    if (!srv) return;
    BlockedWaiter *w = (BlockedWaiter *)calloc(1, sizeof(BlockedWaiter));
    if (!w) return;
    w->fd = fd;
    w->key = (char *)malloc(klen);
    if (!w->key && klen > 0) { free(w); return; }
    if (klen > 0) memcpy(w->key, key, klen);
    w->klen = klen;
    w->deadline_ms = deadline_ms;
    w->type = WAIT_STREAM_XREAD;
    w->start_ms = start_ms; w->start_seq = start_seq;
    w->next = NULL;

    if (!srv->waiters)
        srv->waiters = w;
    else
    {
        BlockedWaiter *t = srv->waiters;
        while (t->next) t = t->next;
        t->next = w;
    }
    if (c) c->blocked = 1;
}

void server_remove_waiter_by_fd(Server *srv, Conn *c, int fd)
{
    if (!srv) return;
    BlockedWaiter *prev = NULL, *cur = srv->waiters;
    while (cur)
    {
        if (cur->fd == fd)
        {
            BlockedWaiter *to_del = cur;
            cur = cur->next;
            if (prev) prev->next = cur; else srv->waiters = cur;
            free(to_del->key);
            free(to_del);
            if (c) c->blocked = 0;
            // do not break; remove all entries for fd just in case
            continue;
        }
        prev = cur; cur = cur->next;
    }
}

static int send_bulk_pair(int fd, const char *k, size_t klen, const char *v, size_t vlen)
{
    char h[64];
    int hl = snprintf(h, sizeof(h), "*2\r\n");
    if (hl <= 0 || (size_t)hl >= sizeof(h)) return -1;
    if (send_all(fd, h, (size_t)hl) != 0) return -1;
    hl = snprintf(h, sizeof(h), "$%zu\r\n", klen);
    if (hl <= 0 || (size_t)hl >= sizeof(h)) return -1;
    if (send_all(fd, h, (size_t)hl) != 0) return -1;
    if (send_all(fd, k, klen) != 0) return -1;
    if (send_all(fd, "\r\n", 2) != 0) return -1;
    hl = snprintf(h, sizeof(h), "$%zu\r\n", vlen);
    if (hl <= 0 || (size_t)hl >= sizeof(h)) return -1;
    if (send_all(fd, h, (size_t)hl) != 0) return -1;
    if (send_all(fd, v, vlen) != 0) return -1;
    if (send_all(fd, "\r\n", 2) != 0) return -1;
    return 0;
}

void server_serve_waiters(Server *srv, Conn *conns)
{
    if (!srv) return;
    BlockedWaiter *prev = NULL;
    BlockedWaiter *cur = srv->waiters;
    while (cur)
    {
        if (cur->type == WAIT_LIST_BLPOP)
        {
            int wrongtype = 0;
            char *v = NULL; size_t vlen = 0;
            int rc = db_list_lpop(&srv->db, cur->key, cur->klen, &v, &vlen, &wrongtype);
            if (rc == 0 && v)
            {
                if (send_bulk_pair(cur->fd, cur->key, cur->klen, v, vlen) != 0)
                {
                    // ignore send error
                }
                free(v);
                if (conns) conns[cur->fd].blocked = 0;
                BlockedWaiter *to_del = cur;
                cur = cur->next;
                if (prev) prev->next = cur; else srv->waiters = cur;
                free(to_del->key); free(to_del);
                continue;
            }
            prev = cur; cur = cur->next;
        }
        else if (cur->type == WAIT_STREAM_XREAD)
        {
            // See if any entries available strictly greater than the provided id (inclusive start already computed)
            size_t cnt = 0; int wrongtype = 0;
            if (db_stream_xrange_count(&srv->db, cur->key, cur->klen,
                                       cur->start_ms, cur->start_seq,
                                       UINT64_MAX, UINT64_MAX,
                                       &cnt, &wrongtype) != 0)
            {
                // wrongtype or error: treat as not ready
                prev = cur; cur = cur->next; continue;
            }
            if (cnt > 0)
            {
                // Prepare response: array of 1 stream
                if (reply_array_header(cur->fd, 1) == 0 &&
                    reply_array_header(cur->fd, 2) == 0 &&
                    reply_bulk(cur->fd, cur->key, cur->klen) == 0 &&
                    reply_array_header(cur->fd, cnt) == 0)
                {
                    wrongtype = 0;
                    EmitCtx ectx = { cur->fd };
                    db_stream_xrange_emit(&srv->db, cur->key, cur->klen,
                                          cur->start_ms, cur->start_seq,
                                          UINT64_MAX, UINT64_MAX,
                                          emit_xrange_entry_cb, &ectx, &wrongtype);
                }
                if (conns) conns[cur->fd].blocked = 0;
                int fd_done = cur->fd;
                BlockedWaiter *to_del = cur;
                cur = cur->next;
                if (prev) prev->next = cur; else srv->waiters = cur;
                free(to_del->key); free(to_del);
                // Remove any other waiters for this fd (e.g., multi-stream XREAD)
                server_remove_waiter_by_fd(srv, NULL, fd_done);
                continue;
            }
            // nothing yet
            prev = cur; cur = cur->next;
        }
        else
        {
            prev = cur; cur = cur->next;
        }
    }
}

void server_timeout_waiters(Server *srv, Conn *conns)
{
    if (!srv) return;
    int64_t now = now_ms();
    BlockedWaiter *prev = NULL, *cur = srv->waiters;
    while (cur)
    {
        if (cur->deadline_ms > 0 && cur->deadline_ms <= now)
        {
            const char nullarr[] = "*-1\r\n";
            if (send_all(cur->fd, nullarr, sizeof(nullarr) - 1) != 0)
            {
                // ignore send error
            }
            if (conns) conns[cur->fd].blocked = 0;
            BlockedWaiter *to_del = cur;
            cur = cur->next;
            if (prev) prev->next = cur; else srv->waiters = cur;
            free(to_del->key); free(to_del);
            continue;
        }
        prev = cur; cur = cur->next;
    }
}

int64_t server_next_waiter_deadline(Server *srv)
{
    if (!srv) return 0;
    int64_t next = 0;
    for (BlockedWaiter *w = srv->waiters; w; w = w->next)
    {
        if (w->deadline_ms <= 0) continue;
        if (next == 0 || w->deadline_ms < next) next = w->deadline_ms;
    }
    return next;
}
