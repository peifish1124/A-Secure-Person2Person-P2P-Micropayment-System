#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string>
#include <string.h>	
#include <pthread.h>
#include <iostream>
#include <vector>
#include <unistd.h>
using namespace std;

#define MAX_BUFFER_LEN 100
#define MAX_RECV_LEN 1000

struct User{
    string name;
    string ip;
    string portNum;
    string publicKey;
    int balance;
    bool isOnline;
    int socket;
    User(string name):name(name), ip(""), portNum(""), publicKey("public key"), isOnline(false), balance(10000), socket(0){};
};

struct SocketParam{
	int newSockfd;
    char *client_ip;
	SocketParam(int newSockfd, char *client_ip): newSockfd(newSockfd), client_ip(client_ip){};
};

vector<User> userData;
int onLineCount = 0;
int connectCnt = 0;

int checkUserExist(string name){
    int index = -1;
    for(int i = 0; i < userData.size(); i++){
        if(userData[i].name == name){
            index = i;
            break;
        }
    }
    return index;
};

int contain(string message){
    int count = 0;
    for(int i = 0; i < message.size(); i++){
        if(message.at(i) == '#'){
            count++;
        }
    }
    return count;
}

//handle connection for each client
void *connection_handler(void *param)
{
	//Get the socket descriptor
    SocketParam msg = *(SocketParam*) param;
	int sock = msg.newSockfd;
    char *client_ip = msg.client_ip;

    int read_size;
    char client_message[MAX_BUFFER_LEN] = {0};
    char server_reply[MAX_RECV_LEN] = {0};
	//Receive a message from client
    string name;
	while(1)
	{
        if((read_size = recv(sock , client_message , MAX_BUFFER_LEN, 0)) > 0){
            string message(client_message);
            //register
            if(strncmp(client_message, "REGISTER", 8) == 0){
                cout << ">> messages from client: " << client_message << "\n";
                string newUser = message.substr(9);
                if(checkUserExist(newUser) < 0){
                    User member(newUser);
                    userData.push_back(member);
                    cout << "-------------------------------\n";
                    cout << "New user register, " << newUser << "!\n";
                    cout << "-------------------------------\n\n";
                    strcat(server_reply, "100 OK\n");
                    send(sock, server_reply, strlen(server_reply), 0);
                    bzero(server_reply,sizeof(server_reply));
                    bzero(client_message,sizeof(client_message));
                } else{
                    cout << "-------------------------------\n";
                    cout << "Dedicate username register,  " << newUser << "!\n";
                    cout << "-------------------------------\n\n";
                    strcat(server_reply, "201 FAIL\n");
                    send(sock, server_reply, strlen(server_reply), 0);
                    bzero(server_reply,sizeof(server_reply));
                    bzero(client_message,sizeof(client_message));
                }
            }
            //login
            else if(contain(message) == 1){
                cout << ">> messages from client: " << client_message << "\n";
                int index = message.find("#");
                name = message.substr(0, index);
                string port = message.substr(index+1);

                int pos = checkUserExist(name);
                if(pos < 0){
                    cout << "-------------------------------\n";
                    cout << "Invalid username login,  " << name << "!\n";
                    cout << "-------------------------------\n\n";
                    strcat(server_reply, "220 AUTH_FAIL\n");
                    send(sock, server_reply, strlen(server_reply), 0);
                    bzero(server_reply,sizeof(server_reply));
                    bzero(client_message,sizeof(client_message));
                } else{
                    cout << "-------------------------------\n";
                    cout << "user login,  " << name << "!\n";
                    cout << "-------------------------------\n\n";
                    userData[pos].portNum = port;
                    userData[pos].ip = client_ip;
                    userData[pos].isOnline = true;
                    userData[pos].socket = sock;
                    onLineCount++;

                    User thisOne = userData[pos];
                    strcat(server_reply, to_string(thisOne.balance).c_str()); strcat(server_reply, "\n");
                    strcat(server_reply, thisOne.publicKey.c_str()); strcat(server_reply, "\n");
                    strcat(server_reply, to_string(onLineCount).c_str()); strcat(server_reply, "\n");
                    for(int i = 0; i < userData.size(); i++){
                        if(userData[i].isOnline == true){
                            strcat(server_reply, userData[i].name.c_str()); strcat(server_reply, "#");
                            strcat(server_reply, userData[i].ip.c_str()); strcat(server_reply, "#");
                            strcat(server_reply, userData[i].portNum.c_str()); strcat(server_reply, "\n");
                        }
                    }
                    send(sock, server_reply, strlen(server_reply), 0);
                    bzero(server_reply,sizeof(server_reply));
                    bzero(client_message,sizeof(client_message));
                }  
            }
            //list
            else if(strncmp(client_message, "List", 4) == 0){
                cout << ">> messages from client: " << client_message << "\n";
                cout << "-------------------------------\n";
                cout << "user request list,  " << name << "!\n";
                cout << "-------------------------------\n\n";
                int pos = checkUserExist(name);
                User thisOne = userData[pos];
                strcat(server_reply, to_string(thisOne.balance).c_str()); strcat(server_reply, "\n");
                strcat(server_reply, thisOne.publicKey.c_str()); strcat(server_reply, "\n");
                strcat(server_reply, to_string(onLineCount).c_str()); strcat(server_reply, "\n");
                for(int i = 0; i < userData.size(); i++){
                    if(userData[i].isOnline == true){
                        strcat(server_reply, userData[i].name.c_str()); strcat(server_reply, "#");
                        strcat(server_reply, userData[i].ip.c_str()); strcat(server_reply, "#");
                        strcat(server_reply, userData[i].portNum.c_str()); strcat(server_reply, "\n");
                    }
                }
                send(sock, server_reply, strlen(server_reply), 0);
                bzero(server_reply,sizeof(server_reply));
                bzero(client_message,sizeof(client_message));   
            }
            //transaction 
            else if(contain(message) == 2){
                cout << ">> messages from client: " << client_message << "\n";
                int index1 = message.find_first_of("#");
                int index2 = message.find_last_of("#");
                string payerName = message.substr(0, index1);
                string money = message.substr(index1+1, index2-index1-1);
                string payeeName = message.substr(index2+1);

                int payerId = checkUserExist(payerName);
                int payeeId = checkUserExist(payeeName);

                userData[payerId].balance -= stoi(money);
                userData[payeeId].balance += stoi(money);
                strcat(server_reply, "Transfer OK!\n");
                send(userData[payerId].socket, server_reply, strlen(server_reply), 0);
                cout << "-------------------------------\n";
                cout << "payer: " << payerName << ",payee: " << payeeName << ",amount: " << money << "!\n";
                cout << "-------------------------------\n\n"; 
                bzero(server_reply,sizeof(server_reply));
                bzero(client_message,sizeof(client_message));
            }
            //exit(login after)
            else if(strncmp(client_message, "Exit", 4) == 0){
                cout << ">> messages from client: " << client_message << "\n";
                int pos = checkUserExist(name);
                userData[pos].portNum = "";
                userData[pos].isOnline = false;
                userData[pos].ip = "";
                userData[pos].socket = 0;
                onLineCount--;
                cout << "-------------------------------\n";
                cout << "user leave,  " << name << "!\n";
                cout << "online number, " << onLineCount << "\n";
                cout << "-------------------------------\n\n";
                strcat(server_reply, "BYE\n");
                send(sock, server_reply, strlen(server_reply), 0);
                bzero(server_reply,sizeof(server_reply));
                bzero(client_message,sizeof(client_message));
                connectCnt--;
                close(sock);
            }
            //exit(login before)
            else if(strncmp(client_message, "exit", 4) == 0){
                cout << ">> messages from client: " << client_message << "\n";
                cout << "-------------------------------\n";
                cout << "online number, " << onLineCount << "\n";
                cout << "-------------------------------\n\n";
                strcat(server_reply, "BYE\n");
                send(sock, server_reply, strlen(server_reply), 0);
                bzero(server_reply,sizeof(server_reply));
                bzero(client_message,sizeof(client_message));
                connectCnt--;
                close(sock);
            }
        } 
	}

    if(read_size == 0){
        puts("Client disconnected.");
    } else if(read_size == -1){
        puts("Receive failed.");
    }
	
	return 0;
}

int main(int argc, char *argv[]){

    int portNum = 0;
    if(argc != 2){
        cout << ("Input error, please input portNum.\n");
        return 1;
    } else{
        portNum = atoi(argv[1]);
    }

    //create a socket
    int serverSockfd = 0, clientSockfd = 0;
    serverSockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(serverSockfd == -1){ //socket 創建失敗
        cout << "Could not create socket. \n";
        return 0;
    }

    //socket connection
    struct sockaddr_in serverInfo, clientInfo;
    bzero(&serverInfo, sizeof(serverInfo));

    serverInfo.sin_family = AF_INET;
    serverInfo.sin_addr.s_addr = INADDR_ANY;
    serverInfo.sin_port = htons(portNum);

    int bindfd = 0;
    bindfd = bind(serverSockfd, (struct sockaddr *)&serverInfo, sizeof(serverInfo));
    if(bindfd == -1){
        cout << "Fail to bind. \n";
        return 0;
    }
    int listenfd = 0;
    listenfd = listen(serverSockfd, 3); //SOMAXCONN means listening without any limit
    if(listenfd == -1){
        cout << "Fail to listen. \n";
        return 0;
    }
    cout << "Waiting for connection... \n";

    //Accept and incoming connection
    int newSockfd = 0;
    socklen_t addrlen = sizeof(clientInfo);
    char client_message[MAX_BUFFER_LEN] = {0};
    char server_reply[MAX_RECV_LEN] = {0};
    while(true){
        newSockfd = accept(serverSockfd, (struct sockaddr *)&clientInfo, &addrlen);

        if(connectCnt < 3){
            strcat(server_reply, "Connected to the server!\n");
            send(newSockfd, server_reply, strlen(server_reply), 0);
            bzero(server_reply,sizeof(server_reply));

            cout << "Connection accepted.\n";
            connectCnt++;

            //Get the ip address of the connected client
            char *client_ip = inet_ntoa(clientInfo.sin_addr);
            int client_port = ntohs(clientInfo.sin_port);

            pthread_t pid;
            SocketParam param(newSockfd, client_ip);
            if( pthread_create( &pid, NULL, connection_handler, &param) < 0)
            {
                cout << ("Could not create thread.\n");
                return 0;
            }

            cout << "client IP:" << client_ip << ", client port:" << client_port << " connected.\n\n";
        } else{
            strcat(server_reply, "Exceed the connection limit of 3 clients!\n");
            send(newSockfd, server_reply, strlen(server_reply), 0);
            bzero(server_reply,sizeof(server_reply));

			close(newSockfd);
			puts("exceed the connection limit of 3 clients!\n");
        }
    }
    if(newSockfd == -1){
        cout << "accept failed.\n";
        return 0;
    }
}



