#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#define MAX_BUFFER_LEN 100
#define MAX_RECV_LEN 1000
int printInstructionBefore();
int printInstructionAfter();
void afterLogin(int socket_desc, char* portnum);
void* transaction(void* data);
char* ip; int port;

int main(int argc , char *argv[])
{
    /*----------create a socket-------------*/
    //a descriptor
    int socket_desc = 0;
    //Address Family - AF_INET (this is IP version 4) ,Type - SOCK_STREAM (this means connection oriented TCP protocol) ,Protocol - 0 [ or IPPROTO_IP This is IP protocol]
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    //socket創建失敗
    if (socket_desc == -1)
    {
        printf("Could not create socket\n");
    }

    /*----------connect socket to a server-------------*/
    //create a sockaddr_in structure with proper values
    struct sockaddr_in server;
    bzero(&server,sizeof(server));//初始化，將struct涵蓋的bits設為0

    //Connect to remote server
    if(argc != 3){
        printf("Input error, please input IP and portNum.\n");
        return 1;
    } else{
        ip = argv[1];
        port = atoi(argv[2]);
    }
    //function inet_addr is a very handy function to convert an IP address to a long format
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons( port );

    if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) == -1)
    {
        printf("Connect error\n");
        return 1;
    }
    
    printf("Connected to the server!\n");

    /*----------send data over socket-------------*/
    int client_serviceNum;
    char client_request[MAX_BUFFER_LEN] = {0};
    char server_reply[MAX_RECV_LEN] = {0};
    char username[100] = {0};
    char portnum[100] = {0};
    while(1){
        printInstructionBefore();
        printf("> service number:");
        scanf("%d",&client_serviceNum);

        //Register
        if(client_serviceNum ==  0){
            printf("Please enter your username for registration: ");
            scanf("%s",username);
            strcat(client_request, "REGISTER#");
            strcat(client_request, username);
            send(socket_desc, client_request, strlen(client_request), 0);
            recv(socket_desc, server_reply, MAX_RECV_LEN, 0);
            puts(server_reply);
            if(strcmp(server_reply, "210 FAIL\n") == 0){
                printf("The username has been used.\n");
            }
            if(strcmp(server_reply, "100 OK\n") == 0){
                printf("Registration completed!\n");
            }
            bzero(server_reply,sizeof(server_reply));
            bzero(client_request,sizeof(client_request));
            continue;
        }
        //Login
        else if(client_serviceNum ==  1){
            printf("Please enter your username: ");
            scanf("%s",username);
            printf("Please enter a port number(between 1024 to 65535): ");
            scanf("%s", portnum);

            while(1){
                if(atoi(portnum) < 1024 || atoi(portnum) > 65535){
                    printf("Please enter a valid port number(between 1024 to 65535): ");
                    scanf("%s", portnum);
                } else {
                    strcat(client_request, username);
                    strcat(client_request, "#");
                    strcat(client_request, portnum);
                    break;
                }
            }

            send(socket_desc, client_request, strlen(client_request), 0);
            recv(socket_desc, server_reply, MAX_RECV_LEN, 0);
            puts(server_reply);
            if(strcmp(server_reply, "220 AUTH_FAIL\n") == 0){
                printf("It is a wrong username.\n");
                bzero(server_reply,sizeof(server_reply));
                bzero(client_request,sizeof(client_request));
            } else {
                afterLogin(socket_desc, portnum);
                bzero(server_reply,sizeof(server_reply));
                bzero(client_request,sizeof(client_request));
                return 0;
            }
        }
        //Exit
        else if(client_serviceNum ==  2){
            strcat(client_request, "Exit");
            send(socket_desc, client_request, strlen(client_request), 0);
            recv(socket_desc, server_reply, MAX_RECV_LEN, 0);
            puts(server_reply);
            printf("Bye\n");
            bzero(server_reply,sizeof(server_reply));
            bzero(client_request,sizeof(client_request));
            close(socket_desc);
            break;
        }
        //Wrong service number
        else{
            printf("It is not a valid service number.\n");
            continue;
        }
    }
    return 0;
}

int printInstructionBefore()
{
    printf("Please enter the number of service(you haven't logged in yet): \n");
    printf("0: Register a new account\n");
    printf("1: Login\n");
    printf("2: Exit\n");
    printf("======================================\n");
}

int printInstructionAfter()
{
    printf("Please enter the number of service(you have logged in!): \n");
    printf("0: List account balance and accounts online\n");
    printf("1: Transaction\n");
    printf("2: Exit\n");
    printf("======================================\n");
}

void afterLogin(int socket_desc, char* portnum){
    
    // create thread for peer to peer communication
    int sockfd = 0;
    sockfd = socket(AF_INET , SOCK_STREAM , 0);
    if (sockfd == -1){
        printf("Could not create socket.\n");
    }
    
    struct sockaddr_in server;
    bzero(&server,sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(atoi(portnum));
    bind(sockfd,(struct sockaddr *)&server,sizeof(server)); //把自己家地址綁在Socket身上
    listen(sockfd,10); //設置Server(client listen to client)的監聽隊列

    int input[2] = {sockfd, socket_desc}; //listen's socket, remote server's socket
    pthread_t tid;
    if( pthread_create(&tid, NULL, &transaction, (void*) input) != 0 )
    {
        printf("Failed to create thread\n");
    }

    int client_serviceNum;
    char client_request[MAX_BUFFER_LEN] = {0};
    char server_reply[MAX_RECV_LEN] = {0};
    while(1){
        printInstructionAfter();
        printf("> service number:");
        scanf("%d",&client_serviceNum);
        //List
        if(client_serviceNum ==  0){
            strcat(client_request, "List");
            send(socket_desc, client_request, strlen(client_request), 0);
            recv(socket_desc, server_reply, MAX_RECV_LEN, 0);
            puts(server_reply);
            bzero(server_reply,sizeof(server_reply));
            bzero(client_request,sizeof(client_request));
            continue;
        }
        //transaction
        else if(client_serviceNum ==  1){
            printf("This is a list of your account balance and users online: \n");
            strcat(client_request, "List");
            send(socket_desc, client_request, strlen(client_request), 0);
            recv(socket_desc, server_reply, MAX_RECV_LEN, 0);
            puts(server_reply);

            //get payee's ip and port num
            char payee_name[100];
            int payee_port = 0;
            char payee_IP[MAX_RECV_LEN];
            printf("Please enter the payee's username: ");
            scanf("%s",payee_name);
            char* token = strstr(server_reply, payee_name);
            while(1){
                if(token == NULL){
                    printf("Please enter an online payee's username: ");
                    scanf("%s",payee_name);
                } else {
                    break;
                }
            }
            token = strtok(token, "#");
            token = strtok(NULL, "#");
            strcat(payee_IP, token);
            token = strtok(NULL, "#");
            payee_port = atoi(token);


            bzero(server_reply,sizeof(server_reply));
            bzero(client_request,sizeof(client_request));

            //connect to another payee
            int transfd = 0;
            transfd = socket(AF_INET , SOCK_STREAM , 0);
            if (transfd == -1){
                printf("Could not create socket.");
            }

            struct sockaddr_in trans;
            bzero(&trans,sizeof(trans));
            trans.sin_family = AF_INET;
            trans.sin_addr.s_addr = inet_addr(payee_IP);
            trans.sin_port = htons(payee_port);
            if (connect(transfd , (struct sockaddr *)&trans , sizeof(trans)) == -1)
            {
                printf("Connect error");
                break;
            }
            printf("Connection to other client success.\n");

            char username[100] = {0};
            char payAmount[100] = {0};
            printf("Please enter your username: ");
            scanf("%s",username);
            printf("Please enter the amount: ");
            scanf("%s",payAmount);
            strcat(client_request, username);
            strcat(client_request, "#");
            strcat(client_request, payAmount);
            strcat(client_request, "#");
            strcat(client_request, payee_name);
            send(transfd, client_request, strlen(client_request), 0);
            recv(socket_desc, server_reply, MAX_RECV_LEN, 0);
            printf("====================================\n");
            puts(server_reply);
            printf("====================================\n");
            bzero(server_reply,sizeof(server_reply));
            bzero(client_request,sizeof(client_request));

            printf("auto renew list from tracker after transfer..\n");
            strcat(client_request, "List");
            send(socket_desc, client_request, strlen(client_request), 0);
            recv(socket_desc, server_reply, MAX_RECV_LEN, 0);
            puts(server_reply);
            bzero(server_reply,sizeof(server_reply));
            bzero(client_request,sizeof(client_request));
            continue;
        }
        //Exit
        else if(client_serviceNum ==  2){
            strcat(client_request, "Exit");
            send(socket_desc, client_request, strlen(client_request), 0);
            recv(socket_desc, server_reply, MAX_RECV_LEN, 0);
            puts(server_reply);
            printf("Bye\n");
            bzero(server_reply,sizeof(server_reply));
            bzero(client_request,sizeof(client_request));
            close(socket_desc);
            break;
        }
        //Wrong service number
        else{
            printf("It is not a valid service number.\n");
            continue;
        }
    }
}

void* transaction(void * data) //Another thread. As a server(payee), connect to payer
{
    int *input = (int *) data;
    int sockfd = input[0];
    int socket_desc = input[1];
    while(1)
    {
        struct sockaddr_in client;
        int clientfd = 0;
        int addrlen = sizeof(client);
        clientfd = accept(sockfd, (struct sockaddr *) &client, &addrlen); //Server(client listen to client) 接收請求

        char receiveMessage[MAX_RECV_LEN] = {0};

        recv(clientfd,receiveMessage,sizeof(receiveMessage),0);
        send(socket_desc,receiveMessage,sizeof(receiveMessage),0);

        bzero(receiveMessage,sizeof(receiveMessage));
    }
}

