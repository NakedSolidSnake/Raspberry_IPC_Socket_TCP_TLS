<p align="center">
  <img src="https://cdn0.sbnation.com/assets/3417793/moveoverlynnswann.gif"/>
</p>

# _TCP SSL_

## Tópicos
* [Introdução](#introdução)
* [O que é SSL?](#o-que-é-ssl)
* [Funcionamento SSL](#funcionamento-ssl)
* [Handshake SSL](#handshake-ssl)
* [Preparação do Ambiente](#preparação-do-ambiente)
* [openssl](#openssl)
* [tcpdump](#tcpdump)
* [Implementação](#implementação)
* [Biblioteca](#biblioteca)
* [tcp_interface.h](#tcp_interfaceh)
* [tcp_server.h](#tcp_serverh)
* [tcp_server.c](#tcp_serverc)
* [tcp_client.h](#tcp_clienth)
* [tcp_client.c](#tcp_clientc)
* [launch_processes](#launch_processes)
* [button_interface](#button_interface)
* [led_interface](#led_interface)
* [button_process](#button_process)
* [led_process](#led_process)
* [Compilando, Executando e Matando os processos](#compilando-executando-e-matando-os-processos)
* [Resolvendo as dependências](#resolvendo-as-dependências)
* [Gerando o certificado](#gerando-o-certificado)
* [Compilando](#compilando)
* [Clonando o projeto](#clonando-o-projeto)
* [Selecionando o modo](#selecionando-o-modo)
* [Modo PC](#modo-pc)
* [Modo RASPBERRY](#modo-raspberry)
* [Executando](#executando)
* [Interagindo com o exemplo](#interagindo-com-o-exemplo)
* [MODO PC](#modo-pc-1)
* [MODO RASPBERRY](#modo-raspberry-1)
* [Monitorando o tráfego usando o tcpdump](#monitorando-o-tráfego-usando-o-tcpdump)
* [Testando conexão com o servidor via openssl](#testando-conexão-com-o-servidor-via-openssl)
* [Matando os processos](#matando-os-processos)
* [Conclusão](#conclusão)
* [Referência](#referência)

A idéia aqui não é explicar como funciona a criptografia mas sim apresentar que é possível o seu uso.

## Introdução
No artigo anterior sobre [TCP](https://github.com/NakedSolidSnake/Raspberry_IPC_Socket_TCP) foi demonstrado como ocorre o processo de comunicação desse IPC, porém conforme descrito no artigo é possível notar que os dados trafegam de forma legível(plain text), sendo possível realizar a leitura sem maiores problemas. Existem aplicações que a exposição desses dados resulta no compromentimento da aplicação, permitindo que "curiosos" bisbilhotem. Para garantir que os dados não serão capturados e usados de forma ilícita existe uma forma de proteger os dados através da criptografia. Neste artigo será demonstrado como implementar esse IPC usando SSL para proteger as mensagens trafegadas. Esse artigo foi baseado/traduzido de acordo com esse [exemplo](https://aticleworld.com/ssl-server-client-using-openssl-in-c/).

## O que é SSL?
SSL significa _Secure Sockets Layer_ que é um protocolo usado para estabelecer uma conexão criptografada entre um servidor e um cliente. Após estabelecer a conexão, o SSL garante que os dados transmitidos entre o cliente e o servidor estão seguros.

## Funcionamento SSL
SSL usa algoritmo de criptografia assimétrica e simétrica para proteger a transmissão dos dados, este [artigo](https://cheapsslsecurity.com/blog/what-is-asymmetric-encryption-understand-with-simple-examples/) explica de forma clara como funciona a transição da forma assimétrica para a forma simétrica. Estes algoritmos usam um par de chaves sendo uma pública e outra privada. A chave pública fica disponível e conhecida por qualquer um. A chave privada é conhecida somente por uma das partes neste caso o servidor. Com o SSL a mensagem criptografada pela chave pública pode ser descriptografada somente pela chave privada, para uma explicação mai elaborada clique [aqui](https://aboutssl.org/how-https-and-ssl-works/).


## Handshake SSL
O processo de _handshake_ ocorre em alguns passos antes do início da troca de mensagens entre as partes, para melhor saber como ocorre esse processo a IBM possui um artigo bem explicativo podendo ser acessado [aqui](https://www.ibm.com/docs/pt-br/ibm-mq/8.0?topic=ssl-overview-tls-handshake).


## Preparação do Ambiente
Antes de apresentarmos o exemplo, primeiro precisaremos instalar algumas ferramentas para auxiliar na análise da comunicação. As ferramentas necessárias para esse artigo são o tcpdump e o openssl, para instalá-las basta executar os comandos abaixo:

```bash
sudo apt-get update
```

```bash
sudo apt-get install openssl
```

```bash
sudo apt-get install tcpdump
```

## openssl
OpenSSL é uma ferramente de criptografia que implementa os protocolos SSL e TLS(_Transport Layer Security_). Com essa ferramenta é possível se conectar a servidores que utilizam SSL/TLS.

## tcpdump 
O tcpdump é uma ferramenta capaz de monitorar o tráfego de dados em uma dada interface como por exemplo eth0, com ele é possível analisar os pacotes que são recebido e enviados

## Implementação
Para demonstrar o uso desse IPC, iremos utilizar o modelo Cliente/Servidor, onde o processo Cliente(_button_process_) vai enviar uma mensagem com comandos pré-determinados para o servidor, e o Servidor(_led_process_) vai ler as mensagens e verificar se possui o comando cadastrado, assim o executando.
Para melhor isolar as implementações do servidor e do cliente foi criado uma biblioteca, que abstrai a rotina de inicialização e execução do servidor, e a rotina de conexão por parte do cliente.

### Biblioteca
A biblioteca criada permite uma fácil criação do servidor, sendo o servidor orientado a eventos, ou seja, fica aguardando as mensagens chegarem.

#### tcp_interface.h
Primeiramente criamos uma interface resposável por eventos de envio e recebimento, essa funções serão chamadas quando esses eventos ocorrerem.

```c
typedef struct 
{
    int (*on_send)(char *buffer, int *size, void *user_data);  
    int (*on_receive)(char *buffer, int size, void *user_data);
} TCP_Callback_t;
```

#### tcp_server.h

Criamos também um contexto que armazena os parâmetros utilizados pelo servidor, sendo o _socket_ para armazenar a instância criada, _port_ que recebe o número que corresponde onde o serviço será disponibilizado, _buffer_ que aponta para a memória alocada previamente pelo usuário, *buffer_size* que representa o tamanho do _buffer_, a interface das funções de _callback_, *ssl_context* que receberá a instância do contexto SSL, _certificate_ que recebe o certificado e _key_ que recebe a chave usada na criptografia.

```c
typedef struct
{
    int socket;
    int port;
    char *buffer;    
    int buffer_size;
    TCP_Callback_t cb;
    void *ssl_context;
    const char *certificate;
    const char *key;
} TCP_Server_t;
```

Essa função é responsável pela a inicialização do servidor
```c
bool TCP_Server_Init(TCP_Server_t *server);
```

Essa função aguarda uma conexão e realiza a comunicação com o cliente.
```c
bool TCP_Server_Exec(TCP_Server_t *server, void *data);
```
Essa função libera o contexto alocado pelo SSL
```c
bool TCP_Server_Cleanup(TCP_Server_t *server);
```
#### tcp_server.c

No TCP_Server_Init definimos algumas variáveis para auxiliar na inicialização do servidor, sendo uma variável booleana que representa o estado da inicialização do servidor, uma variável do tipo inteiro que recebe o resultado das funções necessárias para a configuração, uma variável do tipo inteiro para habilitar o reuso da porta caso o servidor precise reiniciar e uma estrutura sockaddr_in que é usada para configurar o servidor para se comunicar através da rede.
```c
bool status = false;
int is_valid;
int enable_reuse = 1;
struct sockaddr_in address;
```
Para realizar a inicialização é criado um dummy do while, para que quando houver falha em qualquer uma das etapas, irá sair da função com status de erro, nesse ponto verificamos se o contexto e o buffer foi inicializado, que é de responsabilidade do usuário

```c
if(!server || !server->buffer)
    break;
```

Inicializamos a biblioteca do SSL e inicializamos o seu contexto
```c
SSL_library_init();

server->ssl_context = ssl_context_init();
if(!server->ssl_context)
    break;
```

Carregamos o certificado
```c
if(ssl_load_certificates(server->ssl_context, (char *)server->certificate, (char *)server->key) == false)
    break;
```

Criamos um endpoint com o perfil de se conectar via protocolo IPv4(AF_INET), do tipo stream que caracteriza o TCP(SOCK_STREAM), o último parâmetro pode ser 0 nesse caso.
```c
server->socket = socket(AF_INET, SOCK_STREAM, 0);
if(server->socket < 0)
    break;
```
Aqui permitimos o reuso do socket caso necessite reiniciar o serviço
```c
is_valid = setsockopt(server->socket, SOL_SOCKET, SO_REUSEADDR, (void *)&enable_reuse, sizeof(enable_reuse));
if(is_valid < 0)
    break;
```

Preenchemos a estrutura com parâmetros fornecidos pelo usuário como em qual porta que o serviço vai rodar.
```c
memset(&address, 0, sizeof(address));

address.sin_family = AF_INET;
address.sin_addr.s_addr = htonl(INADDR_ANY);
address.sin_port = htons(server->port);
```

Aplicamos as configurações ao socket criado
```c
is_valid = bind(server->socket, (struct sockaddr *)&address, sizeof(address));
if(is_valid != 0)
    break;
```

Por fim colocamos o socket para escutar novas conexões
```c
is_valid = listen(server->socket, 1);
if(is_valid < 0)
    break;

status = true;
```

Na função TCP_Server_Exec declaramos algumas variáveis para realizar a conexão e comunicação com o cliente

```c
SSL *ssl;
struct sockaddr_in address;
socklen_t addr_len = sizeof(address);
int client_socket;
size_t read_len;
int write_len;    
bool status = false;
```

Quando a conexão é solicitada por parte do cliente, o accept retorna o socket referente a conexão, caso for feita com sucesso
```c
client_socket = accept(server->socket, (struct sockaddr *)&address, &addr_len);
if(client_socket > 0)
```

Realizamos o _handshake_ SSL caso ocorrer com sucesso inicia a troca de mensagens
```c
ssl = SSL_new(server->ssl_context);
SSL_set_fd(ssl, client_socket);

if(SSL_accept(ssl) >= 0)
```

O Servidor aguarda a troca de mensagem, assim que receber realiza a verificação se o callback para recebimento foi preenchido caso sim, passa o conteúdo para o callback realizar o tratamento.
```c
read_len = SSL_read(ssl, server->buffer, server->buffer_size);
if(server->cb.on_receive)
{
    server->cb.on_receive(server->buffer, read_len, data);
}
```
Aqui é verificado se o callback para envio foi configurado, dessa forma o buffer é passado para que a implementação prepare a mensagem a ser enviada, e alteramos o status para true, indicando que a comunicação foi feita com sucesso.
```c
if(server->cb.on_send)
{
    server->cb.on_send(server->buffer, &write_len, data);
    SSL_write(ssl, server->buffer, (int)fmin(write_len, server->buffer_size));
}

status = true;
``` 

Liberamos o ssl alocado para o cliente e interrompemos qualquer nova transação e fechamos o socket usado, concluindo a comunicação
```c
SSL_free(ssl);
shutdown(client_socket, SHUT_RDWR);
close(client_socket);
``` 

Na função TCP_Server_Cleanup liberamos o contexto alocado no TCP_Server_Init
```c
bool status = false;

close(server->socket);

if(server->ssl_context)
{
    SSL_CTX_free(server->ssl_context);
    status = true;        
}

return status;
```

#### tcp_client.h
Criamos também um contexto que armazena os parâmetros utilizados pelo cliente, sendo o _socket_ para armazenar a instância criada, _hostname_ é o ip que da máquina que vai ser conectar, _port_ que recebe o número que corresponde qual o serviço deseja consumir, _buffer_ que aponta para a memória alocada previamente pelo usuário, *buffer_size* o representa o tamanho do _buffer_ e a interface das funções de _callback_

```c
typedef struct 
{
    int socket;
    const char *hostname;
    int port;
    char *buffer;
    size_t buffer_size;
    TCP_Callback_t cb;
} TCP_Client_t;
```

Essa função inicializa a biblioteca SSL
```c
bool TCP_Client_Init(TCP_Client_t *client);
```

Essa função realiza a conexão, envio e recebimento de mensagens para o servidor configurado
```c
bool TCP_Client_Connect(TCP_Client_t *client, void *data);
```

#### tcp_client.c
Na função TCP_Client_Init inicializamos a biblioteca SSL
```c
(void)client;
SSL_library_init();
return true;
```

Na função TCP_Client_Connect definimos algumas variáveis para auxiliar na comunicação com o servidor, sendo uma variável booleana que representa o estado da parametrização do cliente, uma variável do tipo inteiro que recebe o resultado das funções necessárias para a configuração, uma estrutura sockaddr_in que é usada para configurar o servidor no qual será conectado, e duas variáveis de quantidade de dados enviados e recebidos.

```c
SSL_CTX *ssl_context;
SSL *ssl;
bool status = false;
int is_valid;
struct sockaddr_in server;
int send_size;
int recv_size;
```
Verificamos se o contexto e o buffer do cliente foram inicializados
```c
if(!client || !client->buffer || client->buffer_size <= 0)
    break;
```

Inicializamos o contexto SSL
```c
ssl_context = ssl_context_init();
```

Criamos um endpoint com o perfil de se conectar via protocolo IPv4(AF_INET), do tipo stream que caracteriza o TCP(SOCK_STREAM), o último parâmetro pode ser 0 nesse caso.
```c
client->socket = socket(AF_INET, SOCK_STREAM, 0);
if(client->socket < 0)
    break;

```
Preenchemos a estrutura com o parâmetros pertinentes ao servidor
```c
server.sin_family = AF_INET;
server.sin_port = htons(client->port);
```

Convertemos o hostname para o endereço relativo ao servidor
```c
is_valid = inet_pton(AF_INET, client->hostname, &server.sin_addr);
if(is_valid <= 0)
    break;
```
Solicitamos a conexão com o servidor previamente configurado, caso ocorra tudo de forma correta alteramos o status para verdadeiro
```c
is_valid = connect(client->socket, (struct sockaddr *)&server, sizeof(server));
if(is_valid < 0)
    break;

status = true;
```

Adquirimos uma instância do SSL, aplicamos ao socket e realizamos um connect ao servidor
```c
ssl = SSL_new(ssl_context);
if(!ssl)
    break;

SSL_set_fd(ssl, client->socket);
if(SSL_connect(ssl) == -1)
    break;
```

Aqui verificamos se a inicialização ocorreu com sucesso e se o callback para envio foi preenchido
```c
if( status && client->cb.on_send)
```
Em caso de sucesso passamos o contexto para a implementação feita pelo usuário para preparar os dados a ser enviado para o servidor
```c
client->cb.on_send(client->buffer, &send_size, data);
SSL_write(ssl, client->buffer, (int)fmin(send_size, client->buffer_size));
```

Se o callback para o recebimento foi preenchido passamos o contexto para a implementação do usuário tratar a resposta
```c
if(client->cb.on_receive)
{
    recv_size = SSL_read(ssl, client->buffer, client->buffer_size);
    client->buffer[recv_size] = '\0';
    client->cb.on_receive(client->buffer, recv_size, data);
}
```
Por fim liberamos a instância do SSL, interrompemos qualquer nova transação, fechamos o socket, e liberamos o contexto SSL e retornamos o status
```c
SSL_free(ssl);
shutdown(client->socket, SHUT_RDWR);
close(client->socket);
SSL_CTX_free(ssl_context);

return status;
```

 A aplicação é composta por três executáveis sendo eles:
* _launch_processes_ - é responsável por lançar os processos _button_process_ e _led_process_ através da combinação _fork_ e _exec_
* _button_interface_ - é responsável por ler o GPIO em modo de leitura da Raspberry Pi e se conectar ao servidor para enviar uma mensagem de alteração de estado.
* _led_interface_ - é responsável por escutar novas conexões, recebendo comandos para aplicar em um GPIO configurado como saída

### *launch_processes*

No _main_ criamos duas variáveis para armazenar o PID do *button_process* e do *led_process*, e mais duas variáveis para armazenar o resultado caso o _exec_ venha a falhar.
```c
int pid_button, pid_led;
int button_status, led_status;
```

Em seguida criamos um processo clone, se processo clone for igual a 0, criamos um _array_ de *strings* com o nome do programa que será usado pelo _exec_, em caso o _exec_ retorne, o estado do retorno é capturado e será impresso no *stdout* e aborta a aplicação. Se o _exec_ for executado com sucesso o programa *button_process* será carregado. 
```c
pid_button = fork();

if(pid_button == 0)
{
    //start button process
    char *args[] = {"./button_process", NULL};
    button_status = execvp(args[0], args);
    printf("Error to start button process, status = %d\n", button_status);
    abort();
}   
```

O mesmo procedimento é repetido novamente, porém com a intenção de carregar o *led_process*.

```c
pid_led = fork();

if(pid_led == 0)
{
    //Start led process
    char *args[] = {"./led_process", NULL};
    led_status = execvp(args[0], args);
    printf("Error to start led process, status = %d\n", led_status);
    abort();
}
```

### *button_interface*
A implementação do Button_Run ficou simples, onde realizamos a inicialização da interface de botão, inicializamos o cliente e ficamos em loop aguardando o pressionamento do botão para alterar o estado da variável e enviar a mensagem para o servidor
```c
bool Button_Run(TCP_Client_t *client, Button_Data *button)
{
    static int state = 0;

    if(button->interface->Init(button->object) == false)
        return false;

    TCP_Client_Init(client);

    while(true)
    {
        wait_press(button);
        state ^= 0x01;
        TCP_Client_Connect(client, &state);
    }
}
```

### *led_interface*
A implementação do LED_Run ficou simples também, onde realizamos a inicialização da interface de LED, do servidor e ficamos em loop aguardando o recebimento de uma conexão.
```c
bool LED_Run(TCP_Server_t *server, LED_Data *led)
{
    if(led->interface->Init(led->object) == false)
        return false;

    TCP_Server_Init(server);

    while(true)
    {
        TCP_Server_Exec(server, led);
    }

    return false;
}
```

### *button_process*

Definimos uma lista de comandos que iremos enviar
```c
const char *states[] = 
{
    "LED ON",
    "LED OFF"
};
```

A parametrização do cliente fica por conta do processo de botão que inicializa o contexto com o buffer, seu tamanho, o endereço do hostname, o serviço que deseja consumir e os callbacks preenchidos, nesse exemplo usaremos somente o de envio, não estando interessado na recepção, e assim passamos os argumentos para Button_Run iniciar o processo.
```c
TCP_Client_t client = 
{
    .buffer = client_buffer,
    .buffer_size = BUFFER_SIZE,
    .hostname = "127.0.0.1",
    .port = 5555,
    .cb.on_send = on_send        
};

Button_Run(&client, &button);
```
A implementação no evento de envio, recuperamos o estado recebido e alteramos e indexamos com a lista de comando para enviar a mensagem
```c
static int on_send(char *buffer, int *size, void *data)
{
    int *state = (int *)data;
    memset(buffer, 0, BUFFER_SIZE);
    snprintf(buffer, strlen(states[*state]) + 1, "%s",states[*state]);
    *size = strlen(states[*state]) + 1;
    return 0;
}
```

### *led_process*
A parametrização do servidor fica por conta do processo de LED que inicializa o contexto com o buffer, seu tamanho, a porta onde vai servir, os callbacks preenchidos e o caminho do certificado nesse exemplo usaremos somente o de recebimento, e assim passamos os argumentos para LED_Run iniciar o serviço.
```c
 TCP_Server_t server = 
    {
        .port = 5555,
        .buffer = server_buffer,
        .buffer_size = sizeof(server_buffer),
        .certificate = "mycert.pem",
        .key = "mycert.pem",
        .cb.on_receive = on_receive_message
    };

    LED_Run(&server, &data);
```

A implementação no evento de recebimento da mensagem, compara a mensagem recebida com os comandos internos para o acionamento do LED, caso for igual executa a ação correspondente.

```c
static int on_receive_message(char *buffer, int size, void *user_data)
{
    LED_Data *led = (LED_Data *)user_data;

    if(strncmp("LED ON", buffer, strlen("LED ON")) == 0)
        led->interface->Set(led->object, 1);
    else if(strncmp("LED OFF", buffer, strlen("LED OFF")) == 0)
        led->interface->Set(led->object, 0);

    return 0;
}
```

## Compilando, Executando e Matando os processos

Para compilar e testar o projeto é necessário instalar a biblioteca de [hardware](https://github.com/NakedSolidSnake/Raspberry_lib_hardware) necessária para resolver as dependências de configuração de GPIO da Raspberry Pi.

## Resolvendo as dependências
Para compilar o projeto é necessário utilizar a libssl-dev que provê a API pertinente para o uso do SSL, para o Ubuntu 18:04 para instalar execute:
```bash
$ sudo apt-get install libssl1.0-dev 
```

Quanto foi testado no MINT foi usado a seguinte instalação
```bash
$ sudo apt-get install libssl-dev 
```

## Gerando o certificado
Para que o exemplo funcione é necessário a criação do certificado, para criá-lo basta executar o seguinte comando e preencher os dados solicitados após o comando:
```bash
$ openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout mycert.pem -out mycert.pem
```

Obs: O certificado deve estar no mesmo diretório que os binários.

## Compilando
Para facilitar a execução do exemplo, o exemplo proposto foi criado baseado em uma interface, onde é possível selecionar se usará o hardware da Raspberry Pi 3, ou se a interação com o exemplo vai ser através de input feito por FIFO e o output visualizado através de LOG.

### Clonando o projeto
Pra obter uma cópia do projeto execute os comandos a seguir:

```bash
$ git clone https://github.com/NakedSolidSnake/Raspberry_IPC_Socket_TCP_TLS
$ cd Raspberry_IPC_Socket_TCP_TLS
$ mkdir build && cd build
```

### Selecionando o modo
Para selecionar o modo devemos passar para o cmake uma variável de ambiente chamada de ARCH, e pode-se passar os seguintes valores, PC ou RASPBERRY, para o caso de PC o exemplo terá sua interface preenchida com os sources presentes na pasta src/platform/pc, que permite a interação com o exemplo através de FIFO e LOG, caso seja RASPBERRY usará os GPIO's descritos no [artigo](https://github.com/NakedSolidSnake/Raspberry_lib_hardware#testando-a-instala%C3%A7%C3%A3o-e-as-conex%C3%B5es-de-hardware).

#### Modo PC
```bash
$ cmake -DARCH=PC ..
$ make
```

#### Modo RASPBERRY
```bash
$ cmake -DARCH=RASPBERRY ..
$ make
```

## Executando
Para executar a aplicação execute o processo _*launch_processes*_ para lançar os processos *button_process* e *led_process* que foram determinados de acordo com o modo selecionado.

```bash
$ cd bin
$ ./launch_processes
```

Uma vez executado podemos verificar se os processos estão rodando atráves do comando 
```bash
$ ps -ef | grep _process
```

O output 
```bash
cssouza  20527  2411  0 15:01 pts/4    00:00:00 ./button_process
cssouza  20528  2411  0 15:01 pts/4    00:00:00 ./led_process
```
## Interagindo com o exemplo
Dependendo do modo de compilação selecionado a interação com o exemplo acontece de forma diferente

### MODO PC
Para o modo PC, precisamos abrir um terminal e monitorar os LOG's
```bash
$ sudo tail -f /var/log/syslog | grep LED
```

Dessa forma o terminal irá apresentar somente os LOG's referente ao exemplo.

Para simular o botão, o processo em modo PC cria uma FIFO para permitir enviar comandos para a aplicação, dessa forma todas as vezes que for enviado o número 0 irá logar no terminal onde foi configurado para o monitoramento, segue o exemplo
```bash
echo "0" > /tmp/tcp_file
```

Output do LOG quando enviado o comando algumas vezez
```bash
May 15 15:05:49 dell-cssouza LED TCP SSL[20528]: LED Status: On
May 15 15:05:49 dell-cssouza LED TCP SSL[20528]: LED Status: Off
May 15 15:05:50 dell-cssouza LED TCP SSL[20528]: LED Status: On
May 15 15:05:50 dell-cssouza LED TCP SSL[20528]: LED Status: Off
May 15 15:05:50 dell-cssouza LED TCP SSL[20528]: LED Status: On
May 15 15:05:51 dell-cssouza LED TCP SSL[20528]: LED Status: Off
```

### MODO RASPBERRY
Para o modo RASPBERRY a cada vez que o botão for pressionado irá alternar o estado do LED.

## Monitorando o tráfego usando o tcpdump
Para monitorar as mensagens que trafegam, precisamos ler uma interface, para saber quais interfaces que o computador possui usamos o comando 
```bash
$ ip a
```
Output
```bash
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s31f6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 10:65:30:22:8a:1a brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.140/24 brd 192.168.0.255 scope global dynamic noprefixroute enp0s31f6
       valid_lft 4928sec preferred_lft 4928sec
    inet6 2804:6828:c048:a300:141:b694:d3a1:2215/64 scope global temporary dynamic 
       valid_lft 295sec preferred_lft 295sec
    inet6 2804:6828:c048:a300:c0a6:57fd:54f2:3f9f/64 scope global dynamic mngtmpaddr noprefixroute 
       valid_lft 295sec preferred_lft 295sec
    inet6 fe80::3b0:2187:f4da:d8cd/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
3: wlp2s0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 7c:2a:31:df:f0:02 brd ff:ff:ff:ff:ff:ff
4: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:f1:1a:71:7b brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:f1ff:fe1a:717b/64 scope link 
       valid_lft forever preferred_lft forever
6: vboxnet0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 0a:00:27:00:00:00 brd ff:ff:ff:ff:ff:ff
    inet 172.16.11.100/24 brd 172.16.11.255 scope global vboxnet0
       valid_lft forever preferred_lft forever
    inet6 fe80::800:27ff:fe00:0/64 scope link 
       valid_lft forever preferred_lft forever
102: vethe828c7d@if101: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether c6:ea:94:5c:69:a5 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::c4ea:94ff:fe5c:69a5/64 scope link 
       valid_lft forever preferred_lft forever
```

Como podemos ver temos 7 interfaces no computador onde o comando foi executado, pode ser que a máquina que esteja usando possa ter mais interfaces ou menos interfaces. Para teste local, iremos usar a interface local denominada lo, que representa a interface de loopback.

O tcpdump possui opções que permite a visualização dos dados, não irei explicar tudo, fica de estudo para quem quiser saber mais sobre a ferramenta. Executando o comando:
```bash
sudo tcpdump -i lo -nnSX port 5555
```
Após executar o comando o tcpdump ficará fazendo sniffing da interface, tudo o que for trafegado nessa interface será apresentado, dessa forma enviamos um comando e veremos a seguinte saída:
```bash
06:00:56.026933 IP 127.0.0.1.49976 > 127.0.0.1.5555: Flags [S], seq 4063409830, win 65495, options [mss 65495,sackOK,TS val 2112801002 ecr 0,nop,wscale 7], length 0
	0x0000:  4500 003c 3f21 4000 4006 fd98 7f00 0001  E..<?!@.@.......
	0x0010:  7f00 0001 c338 15b3 f232 b6a6 0000 0000  .....8...2......
	0x0020:  a002 ffd7 fe30 0000 0204 ffd7 0402 080a  .....0..........
	0x0030:  7dee c8ea 0000 0000 0103 0307            }...........
06:00:56.026944 IP 127.0.0.1.5555 > 127.0.0.1.49976: Flags [S.], seq 4020804078, ack 4063409831, win 65483, options [mss 65495,sackOK,TS val 2112801002 ecr 2112801002,nop,wscale 7], length 0
	0x0000:  4500 003c 0000 4000 4006 3cba 7f00 0001  E..<..@.@.<.....
	0x0010:  7f00 0001 15b3 c338 efa8 99ee f232 b6a7  .......8.....2..
	0x0020:  a012 ffcb fe30 0000 0204 ffd7 0402 080a  .....0..........
	0x0030:  7dee c8ea 7dee c8ea 0103 0307            }...}.......
06:00:56.026953 IP 127.0.0.1.49976 > 127.0.0.1.5555: Flags [.], ack 4020804079, win 512, options [nop,nop,TS val 2112801002 ecr 2112801002], length 0
	0x0000:  4500 0034 3f22 4000 4006 fd9f 7f00 0001  E..4?"@.@.......
	0x0010:  7f00 0001 c338 15b3 f232 b6a7 efa8 99ef  .....8...2......
	0x0020:  8010 0200 fe28 0000 0101 080a 7dee c8ea  .....(......}...
	0x0030:  7dee c8ea                                }...
06:00:56.026987 IP 127.0.0.1.49976 > 127.0.0.1.5555: Flags [P.], seq 4063409831:4063410070, ack 4020804079, win 512, options [nop,nop,TS val 2112801002 ecr 2112801002], length 239
	0x0000:  4500 0123 3f23 4000 4006 fcaf 7f00 0001  E..#?#@.@.......
	0x0010:  7f00 0001 c338 15b3 f232 b6a7 efa8 99ef  .....8...2......
	0x0020:  8018 0200 ff17 0000 0101 080a 7dee c8ea  ............}...
	0x0030:  7dee c8ea 1603 0100 ea01 0000 e603 03fb  }...............
	0x0040:  b474 a881 d1e5 e15b 0d42 00d6 722b a672  .t.....[.B..r+.r
	0x0050:  0574 e371 ae2e c010 e9c9 7aa3 9fdf 9500  .t.q......z.....
	0x0060:  0068 c030 c02c c028 c024 c014 c00a 00a3  .h.0.,.(.$......
	0x0070:  009f 006b 006a 0039 0038 0088 0087 c032  ...k.j.9.8.....2
	0x0080:  c02e c02a c026 c00f c005 009d 003d 0035  ...*.&.......=.5
	0x0090:  0084 c02f c02b c027 c023 c013 c009 00a2  .../.+.'.#......
	0x00a0:  009e 0067 0040 0033 0032 009a 0099 0045  ...g.@.3.2.....E
	0x00b0:  0044 c031 c02d c029 c025 c00e c004 009c  .D.1.-.).%......
	0x00c0:  003c 002f 0096 0041 00ff 0100 0055 000b  .<./...A.....U..
	0x00d0:  0004 0300 0102 000a 001c 001a 0017 0019  ................
	0x00e0:  001c 001b 0018 001a 0016 000e 000d 000b  ................
	0x00f0:  000c 0009 000a 0023 0000 000d 0020 001e  .......#........
	0x0100:  0601 0602 0603 0501 0502 0503 0401 0402  ................
	0x0110:  0403 0301 0302 0303 0201 0202 0203 000f  ................
	0x0120:  0001 01                                  ...
06:00:56.033787 IP 127.0.0.1.5555 > 127.0.0.1.49976: Flags [P.], seq 4020804079:4020804907, ack 4063410070, win 512, options [nop,nop,TS val 2112801009 ecr 2112801002], length 828
	0x0000:  4500 0370 ef90 4000 4006 49f5 7f00 0001  E..p..@.@.I.....
	0x0010:  7f00 0001 15b3 c338 efa8 99ef f232 b796  .......8.....2..
	0x0020:  8018 0200 0165 0000 0101 080a 7dee c8f1  .....e......}...
	0x0030:  7dee c8ea 1603 0300 3a02 0000 3603 0302  }.......:...6...
	0x0040:  f91f 6cc6 62c9 fdfe f727 d7ed a593 fd6a  ..l.b....'.....j
	0x0050:  5b00 bc13 896a 6c45 50da f840 dda9 9600  [....jlEP..@....
	0x0060:  009d 0000 0eff 0100 0100 0023 0000 000f  ...........#....
	0x0070:  0001 0116 0303 02ef 0b00 02eb 0002 e800  ................
	0x0080:  02e5 3082 02e1 3082 024a a003 0201 0202  ..0...0..J......
	0x0090:  0900 fe7f 41f9 1431 d9fd 300d 0609 2a86  ....A..1..0...*.
	0x00a0:  4886 f70d 0101 0b05 0030 8187 310b 3009  H........0..1.0.
	0x00b0:  0603 5504 0613 0242 5231 1230 1006 0355  ..U....BR1.0...U
	0x00c0:  0408 0c09 5361 6f20 5061 756c 6f31 0b30  ....Sao.Paulo1.0
	0x00d0:  0906 0355 0407 0c02 5350 310e 300c 0603  ...U....SP1.0...
	0x00e0:  5504 0a0c 0543 6f6c 6964 310e 300c 0603  U....Colid1.0...
	0x00f0:  5504 0b0c 0553 6f6c 6964 310e 300c 0603  U....Solid1.0...
	0x0100:  5504 030c 0553 6f6c 6964 3127 3025 0609  U....Solid1'0%..
	0x0110:  2a86 4886 f70d 0109 0116 1863 7269 7374  *.H........crist
	0x0120:  6961 6e6f 7373 7465 6340 676d 6169 6c2e  ianosstec@gmail.
	0x0130:  636f 6d30 1e17 0d32 3130 3431 3131 3734  com0...210411174
	0x0140:  3435 355a 170d 3232 3034 3131 3137 3434  455Z..2204111744
	0x0150:  3535 5a30 8187 310b 3009 0603 5504 0613  55Z0..1.0...U...
	0x0160:  0242 5231 1230 1006 0355 0408 0c09 5361  .BR1.0...U....Sa
	0x0170:  6f20 5061 756c 6f31 0b30 0906 0355 0407  o.Paulo1.0...U..
	0x0180:  0c02 5350 310e 300c 0603 5504 0a0c 0543  ..SP1.0...U....C
	0x0190:  6f6c 6964 310e 300c 0603 5504 0b0c 0553  olid1.0...U....S
	0x01a0:  6f6c 6964 310e 300c 0603 5504 030c 0553  olid1.0...U....S
	0x01b0:  6f6c 6964 3127 3025 0609 2a86 4886 f70d  olid1'0%..*.H...
	0x01c0:  0109 0116 1863 7269 7374 6961 6e6f 7373  .....cristianoss
	0x01d0:  7465 6340 676d 6169 6c2e 636f 6d30 819f  tec@gmail.com0..
	0x01e0:  300d 0609 2a86 4886 f70d 0101 0105 0003  0...*.H.........
	0x01f0:  818d 0030 8189 0281 8100 a59c 2058 a828  ...0.........X.(
	0x0200:  39f7 1ca9 e3b3 69da 37e2 7534 02f9 462f  9.....i.7.u4..F/
	0x0210:  ec2f 5a50 5304 3f1e a654 3767 cee8 2941  ./ZPS.?..T7g..)A
	0x0220:  9dbe 0116 0855 66f7 7902 ec55 a50b 3014  .....Uf.y..U..0.
	0x0230:  88ba 91bb 3568 1766 095d f3f2 4089 4303  ....5h.f.]..@.C.
	0x0240:  baef 264b b0a8 510b 1bc5 798c 7e8d ac43  ..&K..Q...y.~..C
	0x0250:  58f1 c1d5 1890 fe9f 9c10 d7d5 7dc1 c297  X...........}...
	0x0260:  efcb 057a 3802 506a 85fa d111 01a8 2fc8  ...z8.Pj....../.
	0x0270:  9217 f033 222f 4b79 d047 0203 0100 01a3  ...3"/Ky.G......
	0x0280:  5330 5130 1d06 0355 1d0e 0416 0414 ad6a  S0Q0...U.......j
	0x0290:  bdb4 ba85 862c 4757 f5f2 8e72 c017 eca4  .....,GW...r....
	0x02a0:  a67b 301f 0603 551d 2304 1830 1680 14ad  .{0...U.#..0....
	0x02b0:  6abd b4ba 8586 2c47 57f5 f28e 72c0 17ec  j.....,GW...r...
	0x02c0:  a4a6 7b30 0f06 0355 1d13 0101 ff04 0530  ..{0...U.......0
	0x02d0:  0301 01ff 300d 0609 2a86 4886 f70d 0101  ....0...*.H.....
	0x02e0:  0b05 0003 8181 003c e79b ebb1 c161 429a  .......<.....aB.
	0x02f0:  b6a2 5dd5 1da1 5847 b8f8 e930 afe7 9c4d  ..]...XG...0...M
	0x0300:  56a2 0305 9238 49d7 acef e3ec f311 730e  V....8I.......s.
	0x0310:  86ee 8f84 9ac7 08d9 ca21 d55a a27b 9c11  .........!.Z.{..
	0x0320:  f773 cb26 e5ba 429c 5b1e 48ef 3faf 2240  .s.&..B.[.H.?."@
	0x0330:  0b9d af33 0bab 4fc7 6ec7 ab56 208f 8816  ...3..O.n..V....
	0x0340:  b903 e8a6 6599 35b7 0f69 5753 0a7a 026c  ....e.5..iWS.z.l
	0x0350:  5308 36e0 ca69 5fd0 618d 7170 9f1e 6872  S.6..i_.a.qp..hr
	0x0360:  d250 7e7f 8d66 2716 0303 0004 0e00 0000  .P~..f'.........
06:00:56.033797 IP 127.0.0.1.49976 > 127.0.0.1.5555: Flags [.], ack 4020804907, win 506, options [nop,nop,TS val 2112801009 ecr 2112801009], length 0
	0x0000:  4500 0034 3f24 4000 4006 fd9d 7f00 0001  E..4?$@.@.......
	0x0010:  7f00 0001 c338 15b3 f232 b796 efa8 9d2b  .....8...2.....+
	0x0020:  8010 01fa fe28 0000 0101 080a 7dee c8f1  .....(......}...
	0x0030:  7dee c8f1                                }...
06:00:56.034063 IP 127.0.0.1.49976 > 127.0.0.1.5555: Flags [P.], seq 4063410070:4063410260, ack 4020804907, win 512, options [nop,nop,TS val 2112801009 ecr 2112801009], length 190
	0x0000:  4500 00f2 3f25 4000 4006 fcde 7f00 0001  E...?%@.@.......
	0x0010:  7f00 0001 c338 15b3 f232 b796 efa8 9d2b  .....8...2.....+
	0x0020:  8018 0200 fee6 0000 0101 080a 7dee c8f1  ............}...
	0x0030:  7dee c8f1 1603 0300 8610 0000 8200 8068  }..............h
	0x0040:  3308 082b 7a48 0937 ff2a fa59 09bd 2958  3..+zH.7.*.Y..)X
	0x0050:  655c 10ed 7cb2 c467 cab1 6c76 d03d d4c8  e\..|..g..lv.=..
	0x0060:  56a1 3793 a7ed 6b9a a367 4258 5d87 ced0  V.7...k..gBX]...
	0x0070:  7b7c dc4b 7908 77fa 9bb5 f6d8 8477 6257  {|.Ky.w......wbW
	0x0080:  7da4 7cad d1ad cfdb 3246 6ce4 3b5d d84b  }.|.....2Fl.;].K
	0x0090:  cd0e c3de 5079 c37d 24f2 e568 4cd5 a2f4  ....Py.}$..hL...
	0x00a0:  c77c 7825 7d89 707e 4abc 4bc3 e885 6f5e  .|x%}.p~J.K...o^
	0x00b0:  74ad 95b8 ae12 c9f0 6890 1d95 83db d614  t.......h.......
	0x00c0:  0303 0001 0116 0303 0028 cb96 f453 6471  .........(...Sdq
	0x00d0:  ff05 f6dd b20c 9cef 8f0b 60ba b8ee 169c  ..........`.....
	0x00e0:  cfc4 380e eae8 1738 25d6 7c19 0b9f 2eb6  ..8....8%.|.....
	0x00f0:  3cce                                     <.
06:00:56.034072 IP 127.0.0.1.5555 > 127.0.0.1.49976: Flags [.], ack 4063410260, win 511, options [nop,nop,TS val 2112801009 ecr 2112801009], length 0
	0x0000:  4500 0034 ef91 4000 4006 4d30 7f00 0001  E..4..@.@.M0....
	0x0010:  7f00 0001 15b3 c338 efa8 9d2b f232 b854  .......8...+.2.T
	0x0020:  8010 01ff fe28 0000 0101 080a 7dee c8f1  .....(......}...
	0x0030:  7dee c8f1                                }...
06:00:56.034376 IP 127.0.0.1.5555 > 127.0.0.1.49976: Flags [P.], seq 4020804907:4020805133, ack 4063410260, win 512, options [nop,nop,TS val 2112801009 ecr 2112801009], length 226
	0x0000:  4500 0116 ef92 4000 4006 4c4d 7f00 0001  E.....@.@.LM....
	0x0010:  7f00 0001 15b3 c338 efa8 9d2b f232 b854  .......8...+.2.T
	0x0020:  8018 0200 ff0a 0000 0101 080a 7dee c8f1  ............}...
	0x0030:  7dee c8f1 1603 0300 aa04 0000 a600 001c  }...............
	0x0040:  2000 a06f d36a ed5b 3d96 f423 0996 df8a  ...o.j.[=..#....
	0x0050:  151b b9c2 6826 e5f9 fa1a 4610 8715 5bd7  ....h&....F...[.
	0x0060:  3166 493d a4c3 99c2 e139 eacb cff4 29c7  1fI=.....9....).
	0x0070:  4fc9 ca94 f56c b2f3 6f43 00d9 2e9f b502  O....l..oC......
	0x0080:  c8f1 0459 c937 ffa7 de37 afa0 572b 34d5  ...Y.7...7..W+4.
	0x0090:  3579 0e7d 7bee a0e3 4bae 0e02 9759 0337  5y.}{...K....Y.7
	0x00a0:  4ff4 a853 2270 da75 2e4d 3fb8 8c50 1615  O..S"p.u.M?..P..
	0x00b0:  73ec 260c 38bc 74df eca5 1754 95c7 95d8  s.&.8.t....T....
	0x00c0:  8811 cadf 4b3a bd23 9efd c918 a729 86c1  ....K:.#.....)..
	0x00d0:  e92b 03ad 8b3b 21be 12e1 8fd6 7834 2a5d  .+...;!.....x4*]
	0x00e0:  1a66 d314 0303 0001 0116 0303 0028 03cd  .f...........(..
	0x00f0:  a116 864e 2df1 f5f2 aa55 6c58 3602 9bd6  ...N-....UlX6...
	0x0100:  45e4 ee4b 2699 482f e26b 2a35 8df8 51b4  E..K&.H/.k*5..Q.
	0x0110:  e272 bcad 6e8a                           .r..n.
06:00:56.034383 IP 127.0.0.1.49976 > 127.0.0.1.5555: Flags [.], ack 4020805133, win 511, options [nop,nop,TS val 2112801009 ecr 2112801009], length 0
	0x0000:  4500 0034 3f26 4000 4006 fd9b 7f00 0001  E..4?&@.@.......
	0x0010:  7f00 0001 c338 15b3 f232 b854 efa8 9e0d  .....8...2.T....
	0x0020:  8010 01ff fe28 0000 0101 080a 7dee c8f1  .....(......}...
	0x0030:  7dee c8f1                                }...
06:00:56.034464 IP 127.0.0.1.49976 > 127.0.0.1.5555: Flags [P.], seq 4063410260:4063410297, ack 4020805133, win 512, options [nop,nop,TS val 2112801009 ecr 2112801009], length 37
	0x0000:  4500 0059 3f27 4000 4006 fd75 7f00 0001  E..Y?'@.@..u....
	0x0010:  7f00 0001 c338 15b3 f232 b854 efa8 9e0d  .....8...2.T....
	0x0020:  8018 0200 fe4d 0000 0101 080a 7dee c8f1  .....M......}...
	0x0030:  7dee c8f1 1703 0300 20cb 96f4 5364 71ff  }...........Sdq.
	0x0040:  06c3 539b 5a89 c225 c376 17c2 6f39 c8b9  ..S.Z..%.v..o9..
	0x0050:  9be0 81af d9d4 e344 e5                   .......D.
06:00:56.034473 IP 127.0.0.1.5555 > 127.0.0.1.49976: Flags [.], ack 4063410297, win 512, options [nop,nop,TS val 2112801009 ecr 2112801009], length 0
	0x0000:  4500 0034 ef93 4000 4006 4d2e 7f00 0001  E..4..@.@.M.....
	0x0010:  7f00 0001 15b3 c338 efa8 9e0d f232 b879  .......8.....2.y
	0x0020:  8010 0200 fe28 0000 0101 080a 7dee c8f1  .....(......}...
	0x0030:  7dee c8f1                                }...
06:00:56.034498 IP 127.0.0.1.49976 > 127.0.0.1.5555: Flags [F.], seq 4063410297, ack 4020805133, win 512, options [nop,nop,TS val 2112801009 ecr 2112801009], length 0
	0x0000:  4500 0034 3f28 4000 4006 fd99 7f00 0001  E..4?(@.@.......
	0x0010:  7f00 0001 c338 15b3 f232 b879 efa8 9e0d  .....8...2.y....
	0x0020:  8011 0200 fe28 0000 0101 080a 7dee c8f1  .....(......}...
	0x0030:  7dee c8f1                                }...
06:00:56.034542 IP 127.0.0.1.5555 > 127.0.0.1.49976: Flags [F.], seq 4020805133, ack 4063410298, win 512, options [nop,nop,TS val 2112801009 ecr 2112801009], length 0
	0x0000:  4500 0034 ef94 4000 4006 4d2d 7f00 0001  E..4..@.@.M-....
	0x0010:  7f00 0001 15b3 c338 efa8 9e0d f232 b87a  .......8.....2.z
	0x0020:  8011 0200 fe28 0000 0101 080a 7dee c8f1  .....(......}...
	0x0030:  7dee c8f1                                }...
06:00:56.034553 IP 127.0.0.1.49976 > 127.0.0.1.5555: Flags [.], ack 4020805134, win 512, options [nop,nop,TS val 2112801009 ecr 2112801009], length 0
	0x0000:  4500 0034 3f29 4000 4006 fd98 7f00 0001  E..4?)@.@.......
	0x0010:  7f00 0001 c338 15b3 f232 b87a efa8 9e0e  .....8...2.z....
	0x0020:  8010 0200 fe28 0000 0101 080a 7dee c8f1  .....(......}...
	0x0030:  7dee c8f1 
  ```

Podemos ver que há o processo de _handshake_ SSL seguido do envio da mensagem, diferente do artigo [TCP](https://github.com/NakedSolidSnake/Raspberry_IPC_Socket_TCP) não é possível ver a mensagem, pois está criptografada.

## Testando conexão com o servidor via openssl
A aplicação realiza a comunicação entre processos locais, para testar uma comunicação remota usaremos o openssl que permite se conectar de forma prática ao servidor que contenha certificado e enviar os comandos. Para se conectar basta usar o seguinte comando:

```bash
$ openssl s_client -connect server:port
```

Como descrito no comando ip usaremos o ip apresentado na interface enp0s31f6 que é o IP 192.168.0.140, então o comando fica
```bash
$ openssl s_client -connect 192.168.0.140:5555
```
Após a conexão é possível visualizar o envio do certificado
```bash
CONNECTED(00000005)
depth=0 C = BR, ST = Sao Paulo, L = SP, O = Colid, OU = Solid, CN = Solid, emailAddress = cristianosstec@gmail.com
verify error:num=18:self signed certificate
verify return:1
depth=0 C = BR, ST = Sao Paulo, L = SP, O = Colid, OU = Solid, CN = Solid, emailAddress = cristianosstec@gmail.com
verify return:1
---
Certificate chain
 0 s:C = BR, ST = Sao Paulo, L = SP, O = Colid, OU = Solid, CN = Solid, emailAddress = cristianosstec@gmail.com
   i:C = BR, ST = Sao Paulo, L = SP, O = Colid, OU = Solid, CN = Solid, emailAddress = cristianosstec@gmail.com
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIC4TCCAkqgAwIBAgIJAP5/QfkUMdn9MA0GCSqGSIb3DQEBCwUAMIGHMQswCQYD
VQQGEwJCUjESMBAGA1UECAwJU2FvIFBhdWxvMQswCQYDVQQHDAJTUDEOMAwGA1UE
CgwFQ29saWQxDjAMBgNVBAsMBVNvbGlkMQ4wDAYDVQQDDAVTb2xpZDEnMCUGCSqG
SIb3DQEJARYYY3Jpc3RpYW5vc3N0ZWNAZ21haWwuY29tMB4XDTIxMDQxMTE3NDQ1
NVoXDTIyMDQxMTE3NDQ1NVowgYcxCzAJBgNVBAYTAkJSMRIwEAYDVQQIDAlTYW8g
UGF1bG8xCzAJBgNVBAcMAlNQMQ4wDAYDVQQKDAVDb2xpZDEOMAwGA1UECwwFU29s
aWQxDjAMBgNVBAMMBVNvbGlkMScwJQYJKoZIhvcNAQkBFhhjcmlzdGlhbm9zc3Rl
Y0BnbWFpbC5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKWcIFioKDn3
HKnjs2naN+J1NAL5Ri/sL1pQUwQ/HqZUN2fO6ClBnb4BFghVZvd5AuxVpQswFIi6
kbs1aBdmCV3z8kCJQwO67yZLsKhRCxvFeYx+jaxDWPHB1RiQ/p+cENfVfcHCl+/L
BXo4AlBqhfrREQGoL8iSF/AzIi9LedBHAgMBAAGjUzBRMB0GA1UdDgQWBBStar20
uoWGLEdX9fKOcsAX7KSmezAfBgNVHSMEGDAWgBStar20uoWGLEdX9fKOcsAX7KSm
ezAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBADznm+uxwWFCmrai
XdUdoVhHuPjpMK/nnE1WogMFkjhJ16zv4+zzEXMOhu6PhJrHCNnKIdVaonucEfdz
yyblukKcWx5I7z+vIkALna8zC6tPx27Hq1Ygj4gWuQPopmWZNbcPaVdTCnoCbFMI
NuDKaV/QYY1xcJ8eaHLSUH5/jWYn
-----END CERTIFICATE-----
subject=C = BR, ST = Sao Paulo, L = SP, O = Colid, OU = Solid, CN = Solid, emailAddress = cristianosstec@gmail.com

issuer=C = BR, ST = Sao Paulo, L = SP, O = Colid, OU = Solid, CN = Solid, emailAddress = cristianosstec@gmail.com

---
No client certificate CA names sent
---
SSL handshake has read 1065 bytes and written 505 bytes
Verification error: self signed certificate
---
New, TLSv1.2, Cipher is AES256-GCM-SHA384
Server public key is 1024 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : AES256-GCM-SHA384
    Session-ID: 14CF6CD72A8BBF09D7400B047640DFF600B4D5BDB98A2438CAC3EC8A27FC4033
    Session-ID-ctx: 
    Master-Key: 27A9A573CEF33F42F1047D6C375A93D5A7F5214792D02D2F8455236A624D9A09D9329C104B8676CA132C1B2AB0848764
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 6f d3 6a ed 5b 3d 96 f4-23 09 96 df 8a 15 1b b9   o.j.[=..#.......
    0010 - 5f 92 97 c1 ca 6b 89 b3-16 b5 33 89 d1 3e ec a2   _....k....3..>..
    0020 - 84 aa 4c 03 ba e7 f7 99-75 bc c5 d0 b7 63 ee 5e   ..L.....u....c.^
    0030 - 2a 7e 73 cd 21 9d e2 31-4d 6b c1 d0 5e 52 e2 b6   *~s.!..1Mk..^R..
    0040 - 2c 39 26 d3 26 d2 16 f5-1f ee d9 d1 fd c2 79 df   ,9&.&.........y.
    0050 - 35 8e 31 b4 2a c0 1a 23-7d 2c 86 41 f0 f2 fb c4   5.1.*..#},.A....
    0060 - 7a 41 71 5b 5d a2 33 92-57 fc 7f bf 53 35 91 1c   zAq[].3.W...S5..
    0070 - 31 c0 d9 e2 21 e3 f3 2f-d3 65 d0 ff c7 0a a2 60   1...!../.e.....`
    0080 - c1 69 4f 01 44 7b 36 70-bc 50 20 59 d9 0c f5 62   .iO.D{6p.P Y...b
    0090 - f2 83 56 0d 31 28 10 35-bb 4b 5b e1 87 41 19 89   ..V.1(.5.K[..A..
    00a0 - b2 69 dd 97 8a fd 1b 43-20 fe ce 76 c6 c6 70 25   .i.....C ..v..p%

    Start Time: 1621102601
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: no
---
```
E enviamos o comando LED ON, note que é recebido um retorno, se visualizar no log irá apresentar que o comando foi executado, para monitorar com o tcpdump basta mudar a interface
```bash
LED ON
read:errno=0
```

## Matando os processos
Para matar os processos criados execute o script kill_process.sh
```bash
$ cd bin
$ ./kill_process.sh
```

## Conclusão
Além de ser o melhor IPC por permitir conectar dois processos em máquinas distintas, ainda é capaz de oferecer mecanismos de segurança para a transmissão de mensagens de forma segura entre as máquinas envolvidas. Para aumentar a segurança ainda é possível aplicar criptografia sobre as mensagens. Para saber mais, aqui no embarcados existe um artigo [Intel Edison – Princípios básicos de comunicação segura via Socket TCP usando OpenSSL e AES 256 em C](https://www.embarcados.com.br/intel-edison-comunicacao-segura-openssl/) escrito pelo Pedro Bertoleti onde ele explica como fazer.

## Referência
* [Link do projeto completo](https://github.com/NakedSolidSnake/Raspberry_IPC_Socket_TCP_TLS)
* [Mark Mitchell, Jeffrey Oldham, and Alex Samuel - Advanced Linux Programming](https://www.amazon.com.br/Advanced-Linux-Programming-CodeSourcery-LLC/dp/0735710430)
* [fork, exec e daemon](https://github.com/NakedSolidSnake/Raspberry_fork_exec_daemon)
* [biblioteca hardware](https://github.com/NakedSolidSnake/Raspberry_lib_hardware)
* [Exemplo OpenSSL](https://aticleworld.com/ssl-server-client-using-openssl-in-c/)

