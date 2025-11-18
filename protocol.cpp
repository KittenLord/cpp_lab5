#ifndef __PROTOCOL
#define __PROTOCOL

#include <stdint.h>
#include <unistd.h>

typedef uint8_t PacketType;
#define PACKET_CLIENT_LOGIN 1
#define PACKET_CLIENT_MESSAGE_ALL 2
#define PACKET_CLIENT_LIST_USERS 3
#define PACKET_CLIENT_GET_USERNAME 4
#define PACKET_CLIENT_MESSAGE 5

#define PACKET_SERVER_LOGIN 101
#define PACKET_SERVER_MESSAGE 102
#define PACKET_SERVER_RECEIVE_MESSAGE 103
#define PACKET_SERVER_LIST_USERS 104
#define PACKET_SERVER_GET_USERNAME 105

typedef uint8_t ErrorType;
#define ERROR_SUCCESS 0
#define ERROR_UNKNOWN_USER_ID 1
#define ERROR_BAD_MESSAGE 2
#define ERROR_BAD_USERNAME 3

typedef uint64_t UserId;



struct PacketClient_Login {
    size_t usernameLength;
    // extra `usernameLength` bytes
};

struct PacketClient_MessageAll {
    size_t messageLength;
    // extra `messageLength` bytes
};

struct PacketClient_ListUsers {
};

struct PacketClient_GetUsername {
    UserId userId;
};

struct PacketClient_Message {
    UserId userId;
    size_t messageLength;
    // extra `messageLength` bytes
};



struct PacketServer_Login {
     ErrorType error;
     UserId userId;
};

struct PacketSercer_Message {
    ErrorType error;
};

struct PacketServer_ReceiveMessage {
    uint8_t isGlobalMessage;
    UserId userId;

    size_t messageLength;
    // extra `messageLength` bytes
};

struct PacketServer_ListUsers {
    uint64_t amount;
    // extra `amount * sizeof(UserId)` bytes
};

struct PacketServer_GetUsername {
    ErrorType error;
    size_t usernameLength;
    // extra `usernameLength` bytes
};

struct Header {
    PacketType type;
    union {
        PacketClient_Login client_login; // Ask server to assign you a user id
        PacketClient_MessageAll client_messageAll; // Broadcast a message to everyone
        PacketClient_ListUsers client_listUsers; // Get list of user ids connected to the server
        PacketClient_GetUsername client_getUsername; // Get username associated with a user id
        PacketClient_Message client_message; // Attempt to send a message to a specific user

        PacketServer_Login server_login; // RESPONSE to PacketClient_Login
        PacketSercer_Message server_message; // RESPONSE to PacketClient_Message or PacketClient_MessageAll
        PacketServer_ReceiveMessage server_receiveMessage; // Notify user of a new message
        PacketServer_ListUsers server_listUsers; // RESPONSE to PacketClient_ListUsers
        PacketServer_GetUsername server_getUsername; // RESPONSE to PacketClient_GetUsername
    };
};

#endif // __PROTOCOL
