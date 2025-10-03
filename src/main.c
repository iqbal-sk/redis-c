#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/select.h>

int main()
{
	// Disable output buffering
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	// You can use print statements as follows for debugging, they'll be visible when running tests.
	printf("Logs from your program will appear here!\n");

	// Uncomment this block to pass the first stage
	//
	int server_fd, client_addr_len;
	struct sockaddr_in client_addr;

	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1)
	{
		printf("Socket creation failed: %s...\n", strerror(errno));
		return 1;
	}

	// Since the tester restarts your program quite often, setting SO_REUSEADDR
	// ensures that we don't run into 'Address already in use' errors
	int reuse = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
	{
		printf("SO_REUSEADDR failed: %s \n", strerror(errno));
		return 1;
	}

	struct sockaddr_in serv_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(6379),
		.sin_addr = {htonl(INADDR_ANY)},
	};

	if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0)
	{
		printf("Bind failed: %s \n", strerror(errno));
		return 1;
	}

	int connection_backlog = 5;
	if (listen(server_fd, connection_backlog) != 0)
	{
		printf("Listen failed: %s \n", strerror(errno));
		return 1;
	}

    printf("Waiting for clients...\n");

    // Use select()-based event loop to handle multiple clients
    fd_set master_set, read_fds;
    FD_ZERO(&master_set);
    FD_SET(server_fd, &master_set);
    int fdmax = server_fd;

    const char *response = "+PONG\r\n";

    while (1)
    {
        read_fds = master_set; // copy
        int activity = select(fdmax + 1, &read_fds, NULL, NULL, NULL);
        if (activity < 0)
        {
            if (errno == EINTR)
                continue;
            printf("select() failed: %s\n", strerror(errno));
            break;
        }

        for (int fd = 0; fd <= fdmax; fd++)
        {
            if (!FD_ISSET(fd, &read_fds))
                continue;

            if (fd == server_fd)
            {
                // New client connection
                client_addr_len = sizeof(client_addr);
                int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
                if (client_fd == -1)
                {
                    printf("Accept failed: %s\n", strerror(errno));
                    continue;
                }
                FD_SET(client_fd, &master_set);
                if (client_fd > fdmax)
                    fdmax = client_fd;
                printf("Client connected (fd=%d)\n", client_fd);
            }
            else
            {
                // Data from existing client
                char buf[4096];
                ssize_t r = read(fd, buf, sizeof(buf));
                if (r > 0)
                {
                    // Respond with PONG for any received data
                    ssize_t w = write(fd, response, strlen(response));
                    if (w == -1)
                    {
                        printf("Write failed (fd=%d): %s\n", fd, strerror(errno));
                        // Close on write failure
                        close(fd);
                        FD_CLR(fd, &master_set);
                    }
                }
                else if (r == 0)
                {
                    // Client closed
                    printf("Client disconnected (fd=%d)\n", fd);
                    close(fd);
                    FD_CLR(fd, &master_set);
                }
                else
                {
                    // Read error
                    printf("Read failed (fd=%d): %s\n", fd, strerror(errno));
                    close(fd);
                    FD_CLR(fd, &master_set);
                }
            }
        }
    }

    close(server_fd);

    return 0;
}
