#ifndef TCP_SERVER_H_
#define TCP_SERVER_H_

#include <stdbool.h>
#include <stdlib.h>
#include <tcp_interface.h>

typedef struct
{
    int socket;
    int port;
    char *buffer;
    void *ssl_context;
    const char *certificate;
    const char *key;
    int buffer_size;
    TCP_Callback_t cb;
} TCP_Server_t;

bool TCP_Server_Init(TCP_Server_t *server);

bool TCP_Server_Exec(TCP_Server_t *server, void *data);

bool TCP_Server_Cleanup(TCP_Server_t *server);

#endif /* TCP_SERVER_H_ */
