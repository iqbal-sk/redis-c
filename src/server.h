#pragma once
#include "common.h"
#include "commands.h"
#include "db.h"

typedef struct Server {
    int listen_fd;
    int listen_port;
    DB db;
    struct BlockedWaiter *waiters;
    int is_replica; // 0 => master, 1 => replica
    char replid[41];
    long long repl_offset;
    // Replication (outbound) connection
    int repl_fd; // -1 if not connected
    char master_host[256];
    int master_port;
    int repl_handshake_step; // 0=idle, 1=sent PING, 2=sent REPLCONF port, 3=sent REPLCONF capa, 4=sent PSYNC
    // Master side: single replica connection (legacy) and list for future multi-replica support
    int slave_fd; // -1 if no replica connected (legacy single-replica path)
    int *replica_fds;
    size_t nreplicas;
    size_t replicas_cap;
} Server;

int server_listen(Server *srv, int port);
int server_event_loop(Server *srv);
int server_connect_master(Server *srv, const char *host, int port);
// Replica tracking (master side)
void server_add_replica_fd(Server *srv, int fd);
void server_remove_replica_fd(Server *srv, int fd);
int server_get_one_replica_fd(Server *srv); // returns a single replica fd (first), -1 if none

typedef enum WaitType {
    WAIT_LIST_BLPOP = 1,
    WAIT_STREAM_XREAD = 2
} WaitType;

typedef struct BlockedWaiter {
    int fd;
    char *key; size_t klen;
    int64_t deadline_ms; // 0 => infinite
    WaitType type;
    // For XREAD
    uint64_t start_ms; uint64_t start_seq; // inclusive start id
    struct BlockedWaiter *next;
} BlockedWaiter;

void server_add_waiter(Server *srv, Conn *c, int fd, const char *key, size_t klen, int64_t deadline_ms);
void server_add_stream_waiter(Server *srv, Conn *c, int fd, const char *key, size_t klen,
                              uint64_t start_ms, uint64_t start_seq, int64_t deadline_ms);
void server_remove_waiter_by_fd(Server *srv, Conn *c, int fd);
void server_timeout_waiters(Server *srv, Conn *conns);
void server_serve_waiters(Server *srv, Conn *conns);
int64_t server_next_waiter_deadline(Server *srv);
