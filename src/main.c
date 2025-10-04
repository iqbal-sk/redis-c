#include "server.h"

int main()
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    printf("Logs from your program will appear here!\n");

    Server srv = {0};
    if (db_init(&srv.db, 4096) != 0)
    {
        fprintf(stderr, "DB init failed\n");
        return 1;
    }
    if (server_listen(&srv, 6379) != 0)
    {
        db_free(&srv.db);
        return 1;
    }
    int rc = server_event_loop(&srv);
    close(srv.listen_fd);
    db_free(&srv.db);
    return rc;
}

