#include "server.h"

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    printf("Logs from your program will appear here!\n");

    int port = 6379;
    int is_replica = 0;
    char master_host[256] = {0};
    int master_port = 0;
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
                size_t hlen = (size_t)(space - arg1);
                if (hlen >= sizeof(master_host)) hlen = sizeof(master_host) - 1;
                memcpy(master_host, arg1, hlen); master_host[hlen] = '\0';
                portstr = space + 1;
            }
            else
            {
                if (i + 1 >= argc)
                {
                    fprintf(stderr, "Missing port in --replicaof\n");
                    return 1;
                }
                strncpy(master_host, arg1, sizeof(master_host) - 1);
                master_host[sizeof(master_host) - 1] = '\0';
                portstr = argv[++i];
            }
            char *e2 = NULL; long mp = strtol(portstr, &e2, 10);
            if (e2 == portstr || *e2 != '\0' || mp <= 0 || mp > 65535)
            {
                fprintf(stderr, "Invalid replica port: %s\n", portstr);
                return 1;
            }
            is_replica = 1;
            master_port = (int)mp;
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
    // Initialize replication id & offset (static for this stage)
    const char *rid = "8371b4fb1155b71f4a04d3e1bc3e18c4a990aeeb";
    strncpy(srv.replid, rid, sizeof(srv.replid) - 1);
    srv.replid[sizeof(srv.replid) - 1] = '\0';
    srv.repl_offset = 0;
    srv.repl_fd = -1;
    srv.slave_fd = -1;
    srv.listen_port = port;
    srv.replica_fds = NULL;
    srv.nreplicas = 0;
    srv.replicas_cap = 0;
    if (is_replica)
    {
        // Connect to master and send initial PING
        server_connect_master(&srv, master_host, master_port);
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
