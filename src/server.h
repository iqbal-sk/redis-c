#pragma once
#include "common.h"
#include "commands.h"
#include "db.h"

typedef struct Server {
    int listen_fd;
    DB db;
} Server;

int server_listen(Server *srv, int port);
int server_event_loop(Server *srv);

