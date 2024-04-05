#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>

#define SOCKET_PATH "/tmp/my_unix_socket"

int main() {
    int sockfd;
    struct sockaddr_un server_addr;
    char message[] = "Hello, receiver!";

    // Create socket
    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Connect to server
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    // Send message
    if (send(sockfd, message, strlen(message), 0) == -1) {
        perror("send");
        exit(EXIT_FAILURE);
    }

    printf("Message sent: %s\n", message);

    printf("my PID:%d\n", getpid());

    // Close socket
    close(sockfd);

    return 0;
}
