#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/select.h>

#define PORT        (9000)
#define BACKLOG        (1)
#define DATA_FILE    "/var/tmp/aesdsocketdata"
#define BUFFER_SIZE    (1024)

volatile sig_atomic_t server_stop = 0;

void signal_handler(int signo) {
    syslog(LOG_INFO, "Caught signal, exiting");
    server_stop = 1;
}

int main(int argc, char *argv[]) {
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    char client_ip[INET_ADDRSTRLEN];
    ssize_t bytes_received;
    int sockfd = -1;
    int clientfd = -1;
    FILE *fp = NULL;
    int result = -1;

    int as_daemon = 0;

    if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        as_daemon = 1;
    }
    
    openlog("aesdsocket", LOG_PID, LOG_USER);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        syslog(LOG_ERR, "Socket creation failed: %s", strerror(errno));
        return -1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        syslog(LOG_ERR, "Bind failed: %s", strerror(errno));
        goto cleanup;
    }

    if (as_daemon) {
        pid_t pid = fork();
        if (pid < 0) exit(-1);
        if (pid > 0) exit(EXIT_SUCCESS);

        umask(0);
        setsid();

        if (chdir("/") < 0) exit(-1);

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }    

    if (listen(sockfd, BACKLOG) != 0) {
        syslog(LOG_ERR, "Listen failed: %s", strerror(errno));
        goto cleanup;
    }

    while (!server_stop) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        int sel = select(sockfd + 1, &readfds, NULL, NULL, NULL);
        if (sel == -1) {
            if (errno == EINTR) break;
            syslog(LOG_ERR, "select failed: %s", strerror(errno));
            break;
        }
        
        if (FD_ISSET(sockfd, &readfds)) {
            clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_addr_len);
            if (clientfd == -1) {
                if (errno == EINTR) break; // Interrupted by signal
                syslog(LOG_ERR, "Accept failed: %s", strerror(errno));
                continue;
            }

            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
            syslog(LOG_INFO, "Accepted connection from %s", client_ip);

            fp = fopen(DATA_FILE, "a+");
            if (!fp) {
                syslog(LOG_ERR, "Failed to open file: %s", strerror(errno));
                close(clientfd);
                continue;
            }

            size_t total_len = 0;
            char *packet = NULL;

            while (!server_stop && (bytes_received = recv(clientfd, buffer, sizeof(buffer)-1, 0)) > 0) {
                buffer[bytes_received] = '\0';
                char *newline_pos = strchr(buffer, '\n');
                if (!newline_pos) {
                    packet = realloc(packet, total_len + bytes_received + 1);
                    if (!packet) {
                        syslog(LOG_ERR, "Memory allocation failed");
                        break;
                    }
                    memcpy(packet + total_len, buffer, bytes_received + 1);
                    total_len += bytes_received;
                    continue;
                }

                // include the newline
                size_t chunk_len = newline_pos - buffer + 1;
                packet = realloc(packet, total_len + chunk_len + 1);
                if (!packet) {
                    syslog(LOG_ERR, "Memory allocation failed");
                    break;
                }
                memcpy(packet + total_len, buffer, chunk_len);
                total_len += chunk_len;
                packet[total_len] = '\0';

                fwrite(packet, 1, total_len, fp);
                fflush(fp);

                // Send full file content
                fseek(fp, 0, SEEK_SET);
                while (!feof(fp)) {
                    size_t read_len = fread(buffer, 1, sizeof(buffer), fp);
                    if (read_len > 0) send(clientfd, buffer, read_len, 0);
                }

                free(packet);
                packet = NULL;
                total_len = 0;
            }

            free(packet);
            fclose(fp);
            fp = NULL;

            syslog(LOG_INFO, "Closed connection from %s", client_ip);
            close(clientfd);
            clientfd = -1;
        }
    }

    result = 0;
    
cleanup:
    if (clientfd != -1) close(clientfd);
    if (sockfd != -1) close(sockfd);
    if (fp) fclose(fp);
    remove(DATA_FILE);
    
    closelog();
    
    return result;
}

