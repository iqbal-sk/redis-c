#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <stdint.h>

// Simple in-memory key-value store
typedef struct Entry {
    char *key; size_t klen;
    char *val; size_t vlen;
    int64_t expires_at_ms; // 0 means no expiry
    struct Entry *next;
} Entry;

#define NBUCKETS 4096
static Entry *g_buckets[NBUCKETS] = {0};

static unsigned long hash_bytes(const char *s, size_t len)
{
    unsigned long h = 5381;
    for (size_t i = 0; i < len; i++)
        h = ((h << 5) + h) + (unsigned char)s[i]; // h*33 + c
    return h;
}

static Entry *kv_find(const char *key, size_t klen)
{
    unsigned long h = hash_bytes(key, klen) % NBUCKETS;
    for (Entry *e = g_buckets[h]; e; e = e->next)
    {
        if (e->klen == klen && memcmp(e->key, key, klen) == 0)
            return e;
    }
    return NULL;
}

static int64_t now_ms()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + (int64_t)(tv.tv_usec / 1000);
}

static void kv_delete_internal(unsigned long bucket, Entry *prev, Entry *e)
{
    if (prev) prev->next = e->next; else g_buckets[bucket] = e->next;
    free(e->key);
    free(e->val);
    free(e);
}

static void kv_del(const char *key, size_t klen)
{
    unsigned long b = hash_bytes(key, klen) % NBUCKETS;
    Entry *prev = NULL; Entry *cur = g_buckets[b];
    while (cur)
    {
        if (cur->klen == klen && memcmp(cur->key, key, klen) == 0)
        {
            kv_delete_internal(b, prev, cur);
            return;
        }
        prev = cur; cur = cur->next;
    }
}

static void kv_set(const char *key, size_t klen, const char *val, size_t vlen, int64_t expires_at_ms)
{
    unsigned long b = hash_bytes(key, klen) % NBUCKETS;
    Entry *e = g_buckets[b];
    for (; e; e = e->next)
    {
        if (e->klen == klen && memcmp(e->key, key, klen) == 0)
        {
            // Replace existing value
            char *nval = malloc(vlen);
            if (!nval) return; // best effort
            memcpy(nval, val, vlen);
            free(e->val);
            e->val = nval;
            e->vlen = vlen;
            e->expires_at_ms = expires_at_ms;
            return;
        }
    }
    // New entry
    Entry *ne = calloc(1, sizeof(Entry));
    if (!ne) return;
    ne->key = malloc(klen);
    ne->val = malloc(vlen);
    if (!ne->key || (!ne->val && vlen > 0))
    {
        free(ne->key); free(ne->val); free(ne);
        return;
    }
    memcpy(ne->key, key, klen);
    memcpy(ne->val, val, vlen);
    ne->klen = klen;
    ne->vlen = vlen;
    ne->expires_at_ms = expires_at_ms;
    ne->next = g_buckets[b];
    g_buckets[b] = ne;
}

static int kv_get(const char *key, size_t klen, const char **out_val, size_t *out_vlen)
{
    Entry *e = kv_find(key, klen);
    if (!e) return -1;
    if (e->expires_at_ms > 0)
    {
        int64_t now = now_ms();
        if (now >= e->expires_at_ms)
        {
            // Expired: delete and treat as missing
            kv_del(key, klen);
            return -1;
        }
    }
    *out_val = e->val;
    *out_vlen = e->vlen;
    return 0;
}

// Simple per-connection buffer management for RESP parsing
typedef struct
{
    char *buf;
    size_t len;
    size_t cap;
    int active;
} Conn;

static int ensure_capacity(Conn *c, size_t need)
{
    if (c->cap >= need)
        return 0;
    size_t ncap = c->cap ? c->cap : 8192;
    while (ncap < need)
        ncap *= 2;
    char *nbuf = realloc(c->buf, ncap);
    if (!nbuf)
        return -1;
    c->buf = nbuf;
    c->cap = ncap;
    return 0;
}

static int send_all(int fd, const char *data, size_t len)
{
    size_t off = 0;
    while (off < len)
    {
        ssize_t w = write(fd, data + off, len - off);
        if (w <= 0)
            return -1;
        off += (size_t)w;
    }
    return 0;
}

// RESP parsing helpers (minimal for arrays of bulk strings)
static int parse_crlf_int(const char *s, size_t len, long *out, size_t *consumed)
{
    if (len < 3) return -1; // at least one digit + CRLF
    int neg = 0;
    size_t i = 0;
    if (s[i] == '-') { neg = 1; i++; }
    if (i >= len) return -1;
    long val = 0;
    int any = 0;
    for (; i + 1 < len; i++)
    {
        char ch = s[i];
        if (ch == '\r')
        {
            if (s[i+1] != '\n') return -1;
            i += 2; // include CRLF
            if (!any) return -1;
            *out = neg ? -val : val;
            *consumed = i;
            return 0;
        }
        if (ch < '0' || ch > '9') return -1;
        any = 1;
        val = val * 10 + (ch - '0');
    }
    return -1;
}

static int strncasecmp_local(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == '\0') return 0;
    }
    return 0;
}

static int skip_bulk_items(const char *p, size_t rem, size_t *pos, long items)
{
    for (long i = 0; i < items; i++)
    {
        if (*pos >= rem || p[*pos] != '$') return -1;
        long blen = 0; size_t bu = 0;
        if (parse_crlf_int(p + *pos + 1, rem - *pos - 1, &blen, &bu) != 0) return -1;
        *pos += 1 + bu;
        if (blen >= 0)
        {
            if ((size_t)blen + 2 > rem - *pos) return -1;
            *pos += (size_t)blen + 2;
        }
        // if blen == -1 (null), nothing more to skip for this bulk
    }
    return 0;
}

static int process_conn(int fd, Conn *c)
{
    // Try to parse multiple RESP commands from the buffer
    size_t offset = 0;
    while (1)
    {
        if (c->len - offset < 1)
            break; // need more
        const char *p = c->buf + offset;
        size_t rem = c->len - offset;
        if (p[0] != '*')
        {
            // Not an array start; wait for more or ignore until CRLF
            // For simplicity, consume until next line end if present
            char *eol = memchr(p, '\n', rem);
            if (!eol) break; // need more
            offset = (size_t)(eol - (c->buf + offset)) + offset + 1; // consume a line
            continue;
        }
        // Parse array length
        if (rem < 2) break;
        long arrlen = 0; size_t used = 0;
        if (parse_crlf_int(p + 1, rem - 1, &arrlen, &used) != 0)
            break; // incomplete or invalid
        size_t pos = 1 + used;
        if (arrlen < 1) { // invalid, consume parsed portion
            offset += pos; continue;
        }

        // Parse first bulk (command)
        if (pos >= rem || p[pos] != '$') break;
        long blen = 0; size_t bu = 0;
        if (parse_crlf_int(p + pos + 1, rem - pos - 1, &blen, &bu) != 0) break;
        pos += 1 + bu;
        if (blen < 0) { offset += pos; continue; }
        if ((size_t)blen + 2 > rem - pos) break; // need more data
        const char *cmd = p + pos;
        size_t cmdlen = (size_t)blen;
        pos += (size_t)blen;
        if (pos + 2 > rem) break;
        if (p[pos] != '\r' || p[pos+1] != '\n') { offset += pos + 2; continue; }
        pos += 2;

        // Prepare for argument (if any). Handle PING, ECHO, SET, GET
        if (arrlen == 1 && cmdlen == 4 && strncasecmp_local(cmd, "PING", 4) == 0)
        {
            const char pong[] = "+PONG\r\n";
            if (send_all(fd, pong, sizeof(pong) - 1) != 0) return -1;
            offset += pos;
            continue;
        }
        else if (arrlen == 2 && cmdlen == 4 && strncasecmp_local(cmd, "ECHO", 4) == 0)
        {
            // Parse the next bulk string as the message
            if (pos >= rem || p[pos] != '$') break;
            long arglen = 0; size_t abu = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &arglen, &abu) != 0) break;
            pos += 1 + abu;
            if (arglen < 0) { offset += pos; continue; }
            if ((size_t)arglen + 2 > rem - pos) break; // need more
            const char *arg = p + pos;
            size_t argsz = (size_t)arglen;
            pos += argsz;
            if (pos + 2 > rem) break;
            if (p[pos] != '\r' || p[pos+1] != '\n') { offset += pos + 2; continue; }
            pos += 2;

            // Compose bulk string response
            char header[64];
            int hl = snprintf(header, sizeof(header), "$%zu\r\n", argsz);
            if (hl <= 0 || (size_t)hl >= sizeof(header)) return -1;
            if (send_all(fd, header, (size_t)hl) != 0) return -1;
            if (send_all(fd, arg, argsz) != 0) return -1;
            if (send_all(fd, "\r\n", 2) != 0) return -1;

            offset += pos;
            continue;
        }
        else if (arrlen >= 3 && cmdlen == 3 && strncasecmp_local(cmd, "SET", 3) == 0)
        {
            // Parse key
            if (pos >= rem || p[pos] != '$') break;
            long klen = 0; size_t bu1 = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &klen, &bu1) != 0) break;
            pos += 1 + bu1;
            if (klen < 0) { offset += pos; continue; }
            if ((size_t)klen + 2 > rem - pos) break;
            const char *kptr = p + pos; size_t ksz = (size_t)klen;
            pos += ksz;
            if (pos + 2 > rem) break;
            if (p[pos] != '\r' || p[pos+1] != '\n') { offset += pos + 2; continue; }
            pos += 2;

            // Parse value
            if (pos >= rem || p[pos] != '$') break;
            long vlen = 0; size_t bu2 = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &vlen, &bu2) != 0) break;
            pos += 1 + bu2;
            if (vlen < 0) { offset += pos; continue; }
            if ((size_t)vlen + 2 > rem - pos) break;
            const char *vptr = p + pos; size_t vsz = (size_t)vlen;
            pos += vsz;
            if (pos + 2 > rem) break;
            if (p[pos] != '\r' || p[pos+1] != '\n') { offset += pos + 2; continue; }
            pos += 2;

            // Optional options: EX <sec> | PX <ms>
            int have_ttl = 0;
            int64_t expires_at = 0;
            long remaining = arrlen - 3; // options count
            while (remaining >= 2)
            {
                if (pos >= rem || p[pos] != '$') break;
                long onamelen = 0; size_t buo = 0; // option name length
                if (parse_crlf_int(p + pos + 1, rem - pos - 1, &onamelen, &buo) != 0) break;
                pos += 1 + buo;
                if (onamelen < 0) { offset += pos; continue; }
                if ((size_t)onamelen + 2 > rem - pos) break;
                const char *oname = p + pos; size_t onamensz = (size_t)onamelen;
                pos += onamensz;
                if (pos + 2 > rem) break;
                if (p[pos] != '\r' || p[pos+1] != '\n') { offset += pos + 2; continue; }
                pos += 2;

                if (pos >= rem || p[pos] != '$') break;
                long oval_len = 0; size_t buv = 0;
                if (parse_crlf_int(p + pos + 1, rem - pos - 1, &oval_len, &buv) != 0) break;
                pos += 1 + buv;
                if (oval_len < 0) { offset += pos; continue; }
                if ((size_t)oval_len + 2 > rem - pos) break;
                const char *oval = p + pos; size_t oval_sz = (size_t)oval_len;
                pos += oval_sz;
                if (pos + 2 > rem) break;
                if (p[pos] != '\r' || p[pos+1] != '\n') { offset += pos + 2; continue; }
                pos += 2;

                // Parse numeric TTL
                long ttl_num = 0;
                // Convert oval bytes to integer
                {
                    long tmp = 0; int neg = 0; int any = 0;
                    for (size_t i = 0; i < oval_sz; i++)
                    {
                        char ch = oval[i];
                        if (i == 0 && ch == '-') { neg = 1; continue; }
                        if (ch < '0' || ch > '9') { any = 0; break; }
                        any = 1; tmp = tmp * 10 + (ch - '0');
                    }
                    if (!any || neg) { ttl_num = -1; }
                    else ttl_num = tmp;
                }

                if (onamensz == 2 && strncasecmp_local(oname, "EX", 2) == 0)
                {
                    if (ttl_num <= 0) { const char err[] = "-ERR syntax error\r\n"; if (send_all(fd, err, sizeof(err)-1)!=0) return -1; offset += pos; continue; }
                    expires_at = now_ms() + (int64_t)ttl_num * 1000;
                    have_ttl = 1;
                }
                else if (onamensz == 2 && strncasecmp_local(oname, "PX", 2) == 0)
                {
                    if (ttl_num <= 0) { const char err[] = "-ERR syntax error\r\n"; if (send_all(fd, err, sizeof(err)-1)!=0) return -1; offset += pos; continue; }
                    expires_at = now_ms() + (int64_t)ttl_num;
                    have_ttl = 1;
                }
                else
                {
                    const char err[] = "-ERR syntax error\r\n";
                    if (send_all(fd, err, sizeof(err) - 1) != 0) return -1;
                    goto after_set_response; // break out to cleanup
                }

                remaining -= 2;
            }

            // Store key/value
            kv_set(kptr, ksz, vptr, vsz, have_ttl ? expires_at : 0);

            const char ok[] = "+OK\r\n";
            if (send_all(fd, ok, sizeof(ok) - 1) != 0) return -1;
after_set_response:
            offset += pos;
            continue;
        }
        else if (arrlen == 2 && cmdlen == 3 && strncasecmp_local(cmd, "GET", 3) == 0)
        {
            // Parse key
            if (pos >= rem || p[pos] != '$') break;
            long klen = 0; size_t bu1 = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &klen, &bu1) != 0) break;
            pos += 1 + bu1;
            if (klen < 0) { offset += pos; continue; }
            if ((size_t)klen + 2 > rem - pos) break;
            const char *kptr = p + pos; size_t ksz = (size_t)klen;
            pos += ksz;
            if (pos + 2 > rem) break;
            if (p[pos] != '\r' || p[pos+1] != '\n') { offset += pos + 2; continue; }
            pos += 2;

            const char *vptr = NULL; size_t vsz = 0;
            if (kv_get(kptr, ksz, &vptr, &vsz) == 0)
            {
                char header[64];
                int hl = snprintf(header, sizeof(header), "$%zu\r\n", vsz);
                if (hl <= 0 || (size_t)hl >= sizeof(header)) return -1;
                if (send_all(fd, header, (size_t)hl) != 0) return -1;
                if (send_all(fd, vptr, vsz) != 0) return -1;
                if (send_all(fd, "\r\n", 2) != 0) return -1;
            }
            else
            {
                const char nullbulk[] = "$-1\r\n";
                if (send_all(fd, nullbulk, sizeof(nullbulk) - 1) != 0) return -1;
            }
            offset += pos;
            continue;
        }
        else
        {
            // Unknown or unsupported command; send simple error and consume
            const char err[] = "-ERR unknown command\r\n";
            if (send_all(fd, err, sizeof(err) - 1) != 0) return -1;
            // Try to skip the rest of the array elements to resync
            long to_skip = arrlen - 1;
            if (to_skip > 0)
            {
                if (skip_bulk_items(p, rem, &pos, to_skip) != 0)
                {
                    // Incomplete, wait for more data
                    break;
                }
            }
            offset += pos;
            continue;
        }
    }
    // Remove consumed bytes
    if (offset > 0)
    {
        if (offset < c->len)
            memmove(c->buf, c->buf + offset, c->len - offset);
        c->len -= offset;
    }
    return 0;
}

int main()
{
	// Disable output buffering
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	// You can use print statements as follows for debugging, they'll be visible when running tests.
	printf("Logs from your program will appear here!\n");

	// Uncomment this block to pass the first stage
	//
	int server_fd, client_addr_len;
	struct sockaddr_in client_addr;

	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1)
	{
		printf("Socket creation failed: %s...\n", strerror(errno));
		return 1;
	}

	// Since the tester restarts your program quite often, setting SO_REUSEADDR
	// ensures that we don't run into 'Address already in use' errors
	int reuse = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
	{
		printf("SO_REUSEADDR failed: %s \n", strerror(errno));
		return 1;
	}

	struct sockaddr_in serv_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(6379),
		.sin_addr = {htonl(INADDR_ANY)},
	};

	if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0)
	{
		printf("Bind failed: %s \n", strerror(errno));
		return 1;
	}

	int connection_backlog = 5;
	if (listen(server_fd, connection_backlog) != 0)
	{
		printf("Listen failed: %s \n", strerror(errno));
		return 1;
	}

    printf("Waiting for clients...\n");

    Conn conns[FD_SETSIZE];
    for (int i = 0; i < FD_SETSIZE; i++)
    {
        conns[i].buf = NULL;
        conns[i].len = 0;
        conns[i].cap = 0;
        conns[i].active = 0;
    }

    // Use select()-based event loop to handle multiple clients
    fd_set master_set, read_fds;
    FD_ZERO(&master_set);
    FD_SET(server_fd, &master_set);
    int fdmax = server_fd;

    while (1)
    {
        read_fds = master_set; // copy
        int activity = select(fdmax + 1, &read_fds, NULL, NULL, NULL);
        if (activity < 0)
        {
            if (errno == EINTR)
                continue;
            printf("select() failed: %s\n", strerror(errno));
            break;
        }

        for (int fd = 0; fd <= fdmax; fd++)
        {
            if (!FD_ISSET(fd, &read_fds))
                continue;

            if (fd == server_fd)
            {
                // New client connection
                client_addr_len = sizeof(client_addr);
                int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
                if (client_fd == -1)
                {
                    printf("Accept failed: %s\n", strerror(errno));
                    continue;
                }
                FD_SET(client_fd, &master_set);
                if (client_fd > fdmax)
                    fdmax = client_fd;
                printf("Client connected (fd=%d)\n", client_fd);
                // init per-connection buffer
                conns[client_fd].active = 1;
                conns[client_fd].len = 0;
                if (conns[client_fd].cap == 0)
                {
                    conns[client_fd].cap = 8192;
                    conns[client_fd].buf = malloc(conns[client_fd].cap);
                    if (!conns[client_fd].buf)
                    {
                        printf("malloc failed for connection buffer\n");
                        close(client_fd);
                        FD_CLR(client_fd, &master_set);
                        conns[client_fd].active = 0;
                    }
                }
            }
            else
            {
                // Data from existing client
                char rbuf[4096];
                ssize_t r = read(fd, rbuf, sizeof(rbuf));
                if (r > 0)
                {
                    Conn *c = &conns[fd];
                    if (!c->active)
                        c->active = 1;
                    if (ensure_capacity(c, c->len + (size_t)r) != 0)
                    {
                        printf("Buffer alloc failed (fd=%d)\n", fd);
                        close(fd);
                        FD_CLR(fd, &master_set);
                        c->active = 0;
                        continue;
                    }
                    memcpy(c->buf + c->len, rbuf, (size_t)r);
                    c->len += (size_t)r;
                    if (process_conn(fd, c) != 0)
                    {
                        // On processing error, close connection
                        close(fd);
                        FD_CLR(fd, &master_set);
                        c->active = 0;
                    }
                }
                else if (r == 0)
                {
                    // Client closed
                    printf("Client disconnected (fd=%d)\n", fd);
                    close(fd);
                    FD_CLR(fd, &master_set);
                    conns[fd].active = 0;
                }
                else
                {
                    // Read error
                    printf("Read failed (fd=%d): %s\n", fd, strerror(errno));
                    close(fd);
                    FD_CLR(fd, &master_set);
                    conns[fd].active = 0;
                }
            }
        }
    }

    close(server_fd);

    return 0;
}
