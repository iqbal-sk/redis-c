#pragma once
#include "common.h"
#include "commands.h"
#include "db.h"

typedef struct Server {
    int listen_fd;
    DB db;
    struct BlockedWaiter *waiters;
} Server;

int server_listen(Server *srv, int port);
int server_event_loop(Server *srv);

typedef struct BlockedWaiter {
    int fd;
    char *key; size_t klen;
    int64_t deadline_ms; // 0 => infinite
    struct BlockedWaiter *next;
} BlockedWaiter;

void server_add_waiter(Server *srv, Conn *c, int fd, const char *key, size_t klen, int64_t deadline_ms);
void server_remove_waiter_by_fd(Server *srv, Conn *c, int fd);
void server_timeout_waiters(Server *srv, Conn *conns);
void server_serve_waiters(Server *srv, Conn *conns);
int64_t server_next_waiter_deadline(Server *srv);
