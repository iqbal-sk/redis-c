#pragma once
#include "common.h"
#include "db.h"
#include "resp.h"

typedef struct QArg { char *ptr; size_t len; } QArg;
typedef struct QueuedCmd { char *cmd; size_t cmdlen; size_t nargs; QArg *args; } QueuedCmd;

typedef struct Conn {
    char *buf;
    size_t len;
    size_t cap;
    int active;
    int blocked;
    int in_multi;
    QueuedCmd *q;
    size_t qcount;
    size_t qcap;
} Conn;

int ensure_capacity(Conn *c, size_t need);
int process_conn(int fd, Conn *c, DB *db);

// Forward declare Server to avoid circular include
struct Server;
void commands_set_server(struct Server *srv);
