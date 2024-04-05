#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>

#define SOCKET_PATH "/tmp/my_unix_socket"
#define BUFFER_SIZE 1024

void print_peer_pid(int sockfd) {
    struct ucred {
        pid_t pid;
        uid_t uid;
        gid_t gid;
    } cred;
    socklen_t len = sizeof(cred);

    if (getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == -1) {
        perror("getsockopt");
        exit(EXIT_FAILURE);
    }

    struct passwd *pw = getpwuid(cred.pid);
    printf("Sender Process PID: %d (Username: %s)\n", cred.pid, pw ? pw->pw_name : "Unknown");
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_un server_addr, client_addr;
    socklen_t client_len;
    char buffer[BUFFER_SIZE];

    // Create socket
    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Bind socket
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);
    unlink(SOCKET_PATH); // Remove any previous socket with the same name
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, 5) == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // Accept connection
    client_len = sizeof(client_addr);
    if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len)) == -1) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    // Receive message
    int bytes_received;
    if ((bytes_received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0)) == -1) {
        perror("recv");
        exit(EXIT_FAILURE);
    }
    buffer[bytes_received] = '\0'; // Null-terminate the received message

    printf("Message received: %s\n", buffer);

    // Obtain sender PID
    print_peer_pid(client_fd);

    // Close sockets
    close(client_fd);
    close(server_fd);
    unlink(SOCKET_PATH);

    return 0;
}
