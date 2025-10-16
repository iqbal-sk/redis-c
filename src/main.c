#include "server.h"

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    printf("Logs from your program will appear here!\n");

    int port = 6379;
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--port") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Missing value for --port\n");
                return 1;
            }
            char *end = NULL;
            long p = strtol(argv[i + 1], &end, 10);
            if (end == argv[i + 1] || *end != '\0' || p <= 0 || p > 65535)
            {
                fprintf(stderr, "Invalid port: %s\n", argv[i + 1]);
                return 1;
            }
            port = (int)p;
            i++;
        }
        else
        {
            // ignore unknown flags for now
        }
    }

    Server srv = {0};
    if (db_init(&srv.db, 4096) != 0)
    {
        fprintf(stderr, "DB init failed\n");
        return 1;
    }
    if (server_listen(&srv, port) != 0)
    {
        db_free(&srv.db);
        return 1;
    }
    // Provide server pointer to command layer (for BLPOP waiters)
    commands_set_server(&srv);
    int rc = server_event_loop(&srv);
    close(srv.listen_fd);
    db_free(&srv.db);
    return rc;
}
