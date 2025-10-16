#include "server.h"

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    printf("Logs from your program will appear here!\n");

    int port = 6379;
    int is_replica = 0;
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
        else if (strcmp(argv[i], "--replicaof") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Missing value for --replicaof\n");
                return 1;
            }
            // Accept either: --replicaof host port  OR  --replicaof "host port"
            const char *arg1 = argv[++i];
            const char *host = NULL; const char *portstr = NULL;
            const char *space = strchr(arg1, ' ');
            if (space)
            {
                // Split arg1 into host and port (copy into a temp buffer)
                size_t hlen = (size_t)(space - arg1);
                char *tmp = (char*)malloc(hlen + 1);
                if (!tmp) { fprintf(stderr, "OOM parsing --replicaof\n"); return 1; }
                memcpy(tmp, arg1, hlen); tmp[hlen] = '\0';
                host = tmp;
                portstr = space + 1;
                // Validate port part has only digits
            }
            else
            {
                if (i + 1 >= argc)
                {
                    fprintf(stderr, "Missing port in --replicaof\n");
                    return 1;
                }
                host = arg1;
                portstr = argv[++i];
            }
            char *e2 = NULL; long mp = strtol(portstr, &e2, 10);
            if (e2 == portstr || *e2 != '\0' || mp <= 0 || mp > 65535)
            {
                fprintf(stderr, "Invalid replica port: %s\n", portstr);
                return 1;
            }
            // For this stage, we only need the role; ignore host/port storage for now.
            is_replica = 1;
            // Free temp host copy if allocated via split with space
            if (space) free((void*)host);
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
    srv.is_replica = is_replica;
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
