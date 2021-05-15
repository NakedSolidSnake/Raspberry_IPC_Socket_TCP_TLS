<p align="center">
  <img src="https://cdn0.sbnation.com/assets/3417793/moveoverlynnswann.gif"/>
</p>

# _TLS_

## Tópicos
* [Introdução](#introdução)
* [Implementação](#implementação)
* [launch_processes](#launch_processes)
* [button_interface](#button_interface)
* [led_interface](#led_interface)
* [Compilando, Executando e Matando os processos](#compilando-executando-e-matando-os-processos)
* [Compilando](#compilando)
* [Clonando o projeto](#clonando-o-projeto)
* [Selecionando o modo](#selecionando-o-modo)
* [Modo PC](#modo-pc)
* [Modo RASPBERRY](#modo-raspberry)
* [Executando](#executando)
* [Interagindo com o exemplo](#interagindo-com-o-exemplo)
* [MODO PC](#modo-pc-1)
* [MODO RASPBERRY](#modo-raspberry-1)
* [Matando os processos](#matando-os-processos)
* [Conclusão](#conclusão)
* [Referência](#referência)

## Introdução
Preencher

## Implementação

Para demonstrar o uso desse IPC, iremos utilizar o modelo Produtor/Consumidor, onde o processo Produtor(_button_process_) vai escrever seu estado interno no arquivo, e o Consumidor(_led_process_) vai ler o estado interno e vai aplicar o estado para si. Aplicação é composta por três executáveis sendo eles:
* _launch_processes_ - é responsável por lançar os processos _button_process_ e _led_process_ atráves da combinação _fork_ e _exec_
* _button_interface_ - é reponsável por ler o GPIO em modo de leitura da Raspberry Pi e escrever o estado interno no arquivo
* _led_interface_ - é reponsável por ler do arquivo o estado interno do botão e aplicar em um GPIO configurado como saída

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

## *button_interface*
descrever o código
## *led_interface*
descrever o código

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

Esse certificado deve está no mesmo diretório que o binário, porém para facilitar a execução do exemplo, o exemplo possuí um certificado, ou seja, não é necessário criá-lo.

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
15:03:18.093589 IP 127.0.0.1.41246 > 127.0.0.1.5555: Flags [S], seq 3442725707, win 65495, options [mss 65495,sackOK,TS val 2058943068 ecr 0,nop,wscale 7], length 0
	0x0000:  4500 003c 6705 4000 4006 d5b4 7f00 0001  E..<g.@.@.......
	0x0010:  7f00 0001 a11e 15b3 cd33 d34b 0000 0000  .........3.K....
	0x0020:  a002 ffd7 fe30 0000 0204 ffd7 0402 080a  .....0..........
	0x0030:  7ab8 fa5c 0000 0000 0103 0307            z..\........
15:03:18.093601 IP 127.0.0.1.5555 > 127.0.0.1.41246: Flags [S.], seq 252259801, ack 3442725708, win 65483, options [mss 65495,sackOK,TS val 2058943068 ecr 2058943068,nop,wscale 7], length 0
	0x0000:  4500 003c 0000 4000 4006 3cba 7f00 0001  E..<..@.@.<.....
	0x0010:  7f00 0001 15b3 a11e 0f09 2dd9 cd33 d34c  ..........-..3.L
	0x0020:  a012 ffcb fe30 0000 0204 ffd7 0402 080a  .....0..........
	0x0030:  7ab8 fa5c 7ab8 fa5c 0103 0307            z..\z..\....
15:03:18.093611 IP 127.0.0.1.41246 > 127.0.0.1.5555: Flags [.], ack 252259802, win 512, options [nop,nop,TS val 2058943068 ecr 2058943068], length 0
	0x0000:  4500 0034 6706 4000 4006 d5bb 7f00 0001  E..4g.@.@.......
	0x0010:  7f00 0001 a11e 15b3 cd33 d34c 0f09 2dda  .........3.L..-.
	0x0020:  8010 0200 fe28 0000 0101 080a 7ab8 fa5c  .....(......z..\
	0x0030:  7ab8 fa5c                                z..\
15:03:18.093649 IP 127.0.0.1.41246 > 127.0.0.1.5555: Flags [P.], seq 3442725708:3442725947, ack 252259802, win 512, options [nop,nop,TS val 2058943068 ecr 2058943068], length 239
	0x0000:  4500 0123 6707 4000 4006 d4cb 7f00 0001  E..#g.@.@.......
	0x0010:  7f00 0001 a11e 15b3 cd33 d34c 0f09 2dda  .........3.L..-.
	0x0020:  8018 0200 ff17 0000 0101 080a 7ab8 fa5c  ............z..\
	0x0030:  7ab8 fa5c 1603 0100 ea01 0000 e603 03a9  z..\............
	0x0040:  beff 93bf 5c9e e007 5fa8 bca0 f073 25ae  ....\..._....s%.
	0x0050:  6e34 3394 5977 6048 fa6c 99d3 6a77 5a00  n43.Yw`H.l..jwZ.
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
	0x0120:  0001 01
  ```

Podemos ver que há o processo de _handshake_ seguido do envio da mensagem, como descritos a seguir:
* No instante 15:03:18.093589 IP 127.0.0.1.41246 > 127.0.0.1.5555 o cliente envia uma SYN para o server
* No instante 15:03:18.093601 IP 127.0.0.1.5555 > 127.0.0.1.41246 o servidor responde com um SYN ACK.
* No instante 15:03:18.093611 IP 127.0.0.1.41246 > 127.0.0.1.5555 o cliente envia um ACK para o servidor.
* E por fim, no instante 15:03:18.093649 IP 127.0.0.1.41246 > 127.0.0.1.5555 o cliente envia a mensagem porém diferente do artigo sobre [TCP](https://github.com/NakedSolidSnake/Raspberry_IPC_Socket_TCP) não é possível ver a mensagem, pois está encriptada.

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
Preencher

## Referência
* [Link do projeto completo](https://github.com/NakedSolidSnake/Raspberry_IPC_Socket_TCP_TLS)
* [Mark Mitchell, Jeffrey Oldham, and Alex Samuel - Advanced Linux Programming](https://www.amazon.com.br/Advanced-Linux-Programming-CodeSourcery-LLC/dp/0735710430)
* [fork, exec e daemon](https://github.com/NakedSolidSnake/Raspberry_fork_exec_daemon)
* [biblioteca hardware](https://github.com/NakedSolidSnake/Raspberry_lib_hardware)
* [Exemplo OpenSSL](https://aticleworld.com/ssl-server-client-using-openssl-in-c/)

