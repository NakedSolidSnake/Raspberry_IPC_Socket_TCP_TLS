#include <tcp_server.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

static void *ssl_context_init(void);
bool ssl_load_certificates(SSL_CTX *ctx, char *CertFile, char *KeyFile);

bool TCP_Server_Init(TCP_Server_t *server)
{
    bool status = false;
    int is_valid;
    int enable_reuse = 1;
    struct sockaddr_in address;

    do 
    {
        if(!server || !server->buffer)
            break;

        SSL_library_init();

        server->ssl_context = ssl_context_init();
        if(!server->ssl_context)
            break;

        if(ssl_load_certificates(server->ssl_context, (char *)server->certificate, (char *)server->key) == false)
            break;

        server->socket = socket(AF_INET, SOCK_STREAM, 0);
        if(server->socket < 0)
            break;

        is_valid = setsockopt(server->socket, SOL_SOCKET, SO_REUSEADDR, (void *)&enable_reuse, sizeof(enable_reuse));
        if(is_valid < 0)
            break;

        memset(&address, 0, sizeof(address));

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_ANY);
        address.sin_port = htons(server->port);        

        is_valid = bind(server->socket, (struct sockaddr *)&address, sizeof(address));
        if(is_valid != 0)
            break;

        is_valid = listen(server->socket, 1);
        if(is_valid < 0)
            break;

        status = true;

    }while(false);

    return status;
}

bool TCP_Server_Exec(TCP_Server_t *server, void *data)
{
    SSL *ssl;
    struct sockaddr_in address;
    socklen_t addr_len = sizeof(address);
    int client_socket;
    size_t read_len;
    int write_len;    
    bool status = false;
  

    client_socket = accept(server->socket, (struct sockaddr *)&address, &addr_len);
    if(client_socket > 0)
    {
        ssl = SSL_new(server->ssl_context);
        SSL_set_fd(ssl, client_socket);

        if(SSL_accept(ssl) >= 0)
        {
            read_len = SSL_read(ssl, server->buffer, server->buffer_size);
            server->buffer[read_len] = '\0';

            if(server->cb.on_receive)
            {
                server->cb.on_receive(server->buffer, read_len, data);
            }

            if(server->cb.on_send)
            {
                server->cb.on_send(server->buffer, &write_len, data);
                SSL_write(ssl, server->buffer, (int)fmin(write_len, server->buffer_size));
            }

            status = true;
        }

        SSL_free(ssl);
        shutdown(client_socket, SHUT_RDWR);
        close(client_socket);        
    }       
    
    return status;    
}

bool TCP_Server_Cleanup(TCP_Server_t *server)
{
    bool status = false;

    close(server->socket);

    if(server->ssl_context)
    {
        SSL_CTX_free(server->ssl_context);
        status = true;        
    }

    return status;
}


static void *ssl_context_init(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();     /* load & register all cryptos, etc. */
    SSL_load_error_strings();         /* load all error messages */
    method = (SSL_METHOD *)TLSv1_2_server_method(); /* create new server-method instance */
    ctx = SSL_CTX_new(method);        /* create new context from method */    
    return ctx;
}

bool ssl_load_certificates(SSL_CTX *ctx, char *CertFile, char *KeyFile)
{
    bool status = false;
    do
    {
        if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
            break;

        if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
            break;

        if (!SSL_CTX_check_private_key(ctx))
            break;

        status = true;

    } while(false);

    return status;
}