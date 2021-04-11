#include <tcp_client.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

static void *ssl_context_init(void);

bool TCP_Client_Init(TCP_Client_t *client)
{
    (void)client;
    SSL_library_init();
    return true;
}

bool TCP_Client_Connect(TCP_Client_t *client, void *data)
{
    SSL_CTX *ssl_context;
    SSL *ssl;
    bool status = false;
    int is_valid;
    struct sockaddr_in server;
    int send_size;
    int recv_size;

    do 
    {
        if(!client || !client->buffer || client->buffer_size <= 0)
            break;

        ssl_context = ssl_context_init();

        client->socket = socket(PF_INET, SOCK_STREAM, 0);
        if(client->socket < 0)
            break;

        server.sin_family = AF_INET;
        server.sin_port = htons(client->port);

        is_valid = inet_pton(AF_INET, client->hostname, &server.sin_addr);
        if(is_valid <= 0)
            break;

        is_valid = connect(client->socket, (struct sockaddr *)&server, sizeof(server));
        if(is_valid < 0)
            break;

        ssl = SSL_new(ssl_context);
        if(!ssl)
            break;

        SSL_set_fd(ssl, client->socket);
        if(SSL_connect(ssl) == -1)
            break;

        status = true;

    } while(false);
    
    if( status && client->cb.on_send)
    {
        client->cb.on_send(client->buffer, &send_size, data);
        SSL_write(ssl, client->buffer, (int)fmin(send_size, client->buffer_size));
        
        if(client->cb.on_receive)
        {
            recv_size = SSL_read(ssl, client->buffer, client->buffer_size);
            client->buffer[recv_size] = '\0';
            client->cb.on_receive(client->buffer, recv_size, data);
        }
    }

    SSL_free(ssl);
    shutdown(client->socket, SHUT_RDWR);
    close(client->socket);     
    SSL_CTX_free(ssl_context);   

    return false;
}

static void *ssl_context_init(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();     /* load & register all cryptos, etc. */
    SSL_load_error_strings();         /* load all error messages */
    method = (SSL_METHOD *)TLSv1_2_client_method(); /* create new server-method instance */
    ctx = SSL_CTX_new(method);        /* create new context from method */  
    return ctx;
}