#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <iostream>
#include <algorithm>
#include <thread>
#include <mutex>
#include <vector>

#include "protocol.cpp"

#define null ((void *)0)

#define PORT 6969

typedef struct {
    char *username;
    UserId userId;
    int socket;

    std::mutex lock;
} UserInfo;

std::vector<UserInfo *> users;
std::mutex usersLock;

unsigned int rngSeed = 916293128;
std::mutex rngSeedLock;

std::mutex logLock;

#define LOG 1

#if LOG
#define log(info, args) \
    do { \
        logLock.lock(); \
        std::cout << "[" << info->username << "#" << info->userId << "]: " << args << std::endl; \
        logLock.unlock(); \
    } while(0);
#else
#define log(info, args)
#endif

void threadRoutine(int sock) {
    UserInfo *info = (UserInfo *)calloc(sizeof(UserInfo), 1);
    info->socket = sock;

    bool notLoggedIn = true;

    while(true) {
        struct Header header;
        size_t bytesRead = read(sock, &header, sizeof(Header));
        if(bytesRead != sizeof(Header)) goto cleanup;

        switch(header.type) {
            case PACKET_CLIENT_LOGIN:
                {
                    if(!notLoggedIn) goto cleanup; // TODO: either rename or return the same userid and do nothing

                    auto packet = header.client_login;
                    info->username = (char *)calloc(sizeof(char), packet.usernameLength + 1);
                    size_t bytesRead = read(sock, info->username, packet.usernameLength);
                    if(bytesRead != packet.usernameLength) {
                        free(info->username);
                        goto cleanup;
                    }

                    bool badUsername = false;
                    if(badUsername) {
                        free(info->username);

                        struct Header response = {
                            .type = PACKET_SERVER_LOGIN,
                            .server_login = {
                                .error = ERROR_BAD_USERNAME,
                            },
                        };

                        info->lock.lock();
                            write(sock, &response, sizeof(Header));
                        info->lock.unlock();
                        continue;
                    }

                    rngSeedLock.lock();
                        uint32_t a = rand_r(&rngSeed);
                        uint32_t b = rand_r(&rngSeed);
                        info->userId = (UserId)a | ((UserId)b << 32);
                    rngSeedLock.unlock();

                    usersLock.lock();
                        users.push_back(info);
                    usersLock.unlock();

                    log(info, "Logged in");

                    struct Header response = {
                        .type = PACKET_SERVER_LOGIN,
                        .server_login = {
                            .error = ERROR_SUCCESS,
                            .userId = info->userId,
                        },
                    };

                    info->lock.lock();
                        write(info->socket, &response, sizeof(Header));
                    info->lock.unlock();
                }
                break;
            case PACKET_CLIENT_MESSAGE_ALL:
                if(notLoggedIn) goto cleanup;

                {
                    auto packet = header.client_messageAll;
                    char *message = (char *)calloc(sizeof(char), packet.messageLength + 1);
                    size_t bytesRead = read(sock, message, packet.messageLength);
                    if(bytesRead != packet.messageLength) {
                        free(message);
                        goto cleanup;
                    }

                    struct Header notification = {
                        .type = PACKET_SERVER_RECEIVE_MESSAGE,
                        .server_receiveMessage = {
                            .isGlobalMessage = true,
                            .userId = info->userId,

                            .messageLength = packet.messageLength,
                        },
                    };

                    log(info, "Broadcasted a message to everyone");

                    usersLock.lock();
                    {
                        for(auto &user : users) {
                            if(user->userId == info->userId) continue;

                            user->lock.lock();
                                write(user->socket, &notification, sizeof(Header));
                                write(user->socket, message, packet.messageLength);
                            user->lock.unlock();

                            log(user, "Received a broadcasted message");
                        }
                    }
                    usersLock.unlock();

                    free(message);

                    struct Header response = {
                        .type = PACKET_SERVER_MESSAGE,
                        .server_message = {
                            .error = ERROR_SUCCESS,
                        },
                    };

                    info->lock.lock();
                        write(info->socket, &response, sizeof(Header));
                    info->lock.unlock();
                }

                break;
            case PACKET_CLIENT_LIST_USERS:
                {
                    // NOTE: PacketClient_ListUsers contains no data

                    struct Header response;
                    UserId *array;

                    usersLock.lock();
                    {
                        response = {
                            .type = PACKET_SERVER_LIST_USERS,
                            .server_listUsers = {
                                .amount = users.size(),
                            },
                        };

                        array = (UserId *)calloc(sizeof(UserId), users.size());
                        size_t index = 0;

                        for(auto &user : users) {
                            array[index] = user->userId;
                            index += 1;
                        }
                    }
                    usersLock.unlock();

                    log(info, "Requested the user list. Amount: " << response.server_listUsers.amount);

                    info->lock.lock();
                        write(info->socket, &response, sizeof(Header));
                        write(info->socket, array, sizeof(UserId) * response.server_listUsers.amount);
                    info->lock.unlock();

                    free(array);
                }
                break;
            case PACKET_CLIENT_GET_USERNAME:
                {
                    auto packet = header.client_getUsername;

                    char *username = nullptr;
                    size_t len;

                    usersLock.lock();
                    {
                        for(auto &user : users) {
                            if(user->userId == packet.userId) {
                                len = strlen(user->username);
                                username = (char *)calloc(sizeof(char), len + 1);
                                memcpy(username, user->username, len);
                                break;
                            }
                        }
                    }
                    usersLock.unlock();

                    if(username) {
                        log(info, "Requested the username for user id " << packet.userId << ". Username: \"" << username << "\"");
                    }
                    else {
                        log(info, "Requested the username for user id " << packet.userId << ". Invalid user id");
                    }

                    info->lock.lock();
                        if(!username) {
                            struct Header response = {
                                .type = PACKET_SERVER_GET_USERNAME,
                                .server_getUsername = {
                                    .error = ERROR_UNKNOWN_USER_ID,
                                    .usernameLength = 0,
                                },
                            };

                            write(info->socket, &response, sizeof(Header));
                        }
                        else {
                            struct Header response = {
                                .type = PACKET_SERVER_GET_USERNAME,
                                .server_getUsername = {
                                    .error = ERROR_SUCCESS,
                                    .usernameLength = len,
                                },
                            };

                            write(info->socket, &response, sizeof(Header));
                            write(info->socket, username, len);
                        }
                    info->lock.unlock();

                    if(username) free(username);
                }
                break;
            case PACKET_CLIENT_MESSAGE:
                if(notLoggedIn) goto cleanup;

                {
                    auto packet = header.client_message;

                    char *message = (char *)calloc(sizeof(char), packet.messageLength + 1);
                    size_t bytesRead = read(info->socket, message, packet.messageLength);
                    if(bytesRead != packet.messageLength) {
                        free(message);
                        goto cleanup;
                    }

                    bool success = false;

                    // NOTE: i really dont like the double lock here, but we can't really do anything with it
                    usersLock.lock();
                    {
                        for(auto &user : users) {
                            if(user->userId == packet.userId) {
                                success = true;

                                user->lock.lock();
                                {
                                    struct Header notification = {
                                        .type = PACKET_SERVER_RECEIVE_MESSAGE,
                                        .server_receiveMessage = {
                                            .isGlobalMessage = false,
                                            .userId = info->userId,

                                            .messageLength = packet.messageLength,
                                        }
                                    };

                                    write(user->socket, &notification, sizeof(Header));
                                    write(user->socket, message, packet.messageLength);
                                }
                                user->lock.unlock();

                                break;
                            }
                        }
                    }
                    usersLock.unlock();

                    free(message);

                    if(success) {
                        log(info, "Sent a message to user id " << packet.userId);
                    }
                    else {
                        log(info, "Sent a message to user id " << packet.userId << ", but such user didn't exist");
                    }

                    info->lock.lock();
                    {
                        if(success) {
                            struct Header response = {
                                .type = PACKET_SERVER_MESSAGE,
                                .server_message = {
                                    .error = ERROR_SUCCESS,
                                },
                            };

                            write(info->socket, &response, sizeof(Header));
                        }
                        else {
                            struct Header response = {
                                .type = PACKET_SERVER_MESSAGE,
                                .server_message = {
                                    .error = ERROR_UNKNOWN_USER_ID,
                                },
                            };

                            write(info->socket, &response, sizeof(Header));
                        }
                    }
                    info->lock.unlock();
                }
                break;
            default:
                goto cleanup;
                break;
        }
    }

cleanup:

    if(!notLoggedIn) {
        log(info, "Shutting down");
    }

    usersLock.lock();
        users.erase(std::remove(users.begin(), users.end(), info), users.end());
    usersLock.unlock();
    free(info);

    close(sock);
    return;
}

int main(void) {
    int result = 0;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock == -1) {
        printf("ERROR: socket\n");
        return 1;
    }

    int reuseAddrOptions = 1;
    result = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseAddrOptions, sizeof(reuseAddrOptions));
    if(result == -1) {
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
    if(result == -1) {
        printf("ERROR: bind\n");
        return 1;
    }

    result = listen(sock, 10);
    if(result == -1) {
        printf("ERROR: listen\n");
        return 1;
    }

    printf("SERVER STARTED\n");

    while(true) {
        struct sockaddr_in clientAddr    = {0};
        socklen_t          clientAddrLen = sizeof(clientAddr);

        int clientSock = accept(sock, (struct sockaddr *)&clientAddr, &clientAddrLen);
        if (clientSock == -1) {
            printf("Accept failed\n");
            continue;
        }

        printf("CLIENT CONNECTED\n");

        std::thread t(threadRoutine, clientSock);
        t.detach();
    }

    close(sock);
    return 0;
}
