#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/select.h>
#include "server.h"

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
    }

    fd_set master_set, read_fds;
    FD_ZERO(&master_set);
    FD_SET(srv->listen_fd, &master_set);
    int fdmax = srv->listen_fd;

    struct sockaddr_in client_addr; int client_addr_len = 0;

    while (1)
    {
        read_fds = master_set;
        int activity = select(fdmax + 1, &read_fds, NULL, NULL, NULL);
        if (activity < 0)
        {
            if (errno == EINTR) continue;
            printf("select() failed: %s\n", strerror(errno));
            break;
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
            }
            else if (r == 0)
            {
                close(fd); FD_CLR(fd, &master_set); conns[fd].active = 0;
            }
            else
            {
                printf("Read failed (fd=%d): %s\n", fd, strerror(errno));
                close(fd); FD_CLR(fd, &master_set); conns[fd].active = 0;
            }
        }
    }

    return 0;
}

