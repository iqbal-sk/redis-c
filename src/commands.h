#pragma once
#include "common.h"
#include "db.h"
#include "resp.h"

typedef struct Conn {
    char *buf;
    size_t len;
    size_t cap;
    int active;
    int blocked;
} Conn;

int ensure_capacity(Conn *c, size_t need);
int process_conn(int fd, Conn *c, DB *db);

// Forward declare Server to avoid circular include
struct Server;
void commands_set_server(struct Server *srv);
