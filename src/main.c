#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/select.h>

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

        // Prepare for argument (if any). Only handle PING (no args) and ECHO (1 arg)
        if (arrlen == 1 && cmdlen == 4 && strncasecmp_local(cmd, "PING", 4) == 0)
        {
            const char pong[] = "+PONG\r\n";
            if (send_all(fd, pong, sizeof(pong) - 1) != 0) return -1;
            offset += pos;
            continue;
        }
        else if (arrlen >= 2 && cmdlen == 4 && strncasecmp_local(cmd, "ECHO", 4) == 0)
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
        else
        {
            // Unknown or unsupported command; send simple error and consume
            const char err[] = "-ERR unknown command\r\n";
            if (send_all(fd, err, sizeof(err) - 1) != 0) return -1;
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
