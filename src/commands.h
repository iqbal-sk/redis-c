#pragma once
#include "common.h"
#include "db.h"
#include "resp.h"

typedef struct Conn {
    char *buf;
    size_t len;
    size_t cap;
    int active;
} Conn;

int ensure_capacity(Conn *c, size_t need);
int process_conn(int fd, Conn *c, DB *db);

