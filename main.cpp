#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#define null ((void *)0)

#define PORT 6969

int main(void) {
    int result = 0;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("ERROR: socket\n");
        return 1;
    }

    int reuseAddrOptions = 1;
    result = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseAddrOptions, sizeof(reuseAddrOptions));
    if (result == -1) {
        printf("ERROR: reuse\n");
        return 1;
    }

    struct sockaddr_in serverAddr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr = (struct in_addr){
            .s_addr = htonl(INADDR_ANY),
        },
    };

    result = bind(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    if (result == -1) {
        printf("ERROR: bind\n");
        return 1;
    }

    result = listen(sock, 10);
    if (result == -1) {
        printf("ERROR: listen\n");
        return 1;
    }

    printf("SERVER STARTED\n");

    while (1) {
        struct sockaddr_in clientAddr    = {0};
        socklen_t          clientAddrLen = sizeof(clientAddr);

        int clientSock = accept(sock, (struct sockaddr *)&clientAddr, &clientAddrLen);
        if (clientSock == -1) {
            printf("Accept failed\n");
            continue;
        }

        printf("CLIENT CONNECTED\n");

        char buffer[512] = {0};
        read(clientSock, buffer, 512);

        printf("MESSAGE: %s\n", buffer);
    }

    close(sock);
    return 0;
}
