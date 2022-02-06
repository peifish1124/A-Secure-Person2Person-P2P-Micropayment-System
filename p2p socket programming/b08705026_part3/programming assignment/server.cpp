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
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <cstring>
#include <mutex>
#include <algorithm>
using namespace std;

#define MAX_BUFFER_LEN 100
#define MAX_RECV_LEN 1000
#define RSA_BLOCK_SIZE 256 - 12
#define KEY_SIZE 256
#define KEY_FILE "keys/server.key"
#define CERT_FILE "keys/server.crt"
#define CA_FILE (char*)"keys/CA.pem"
SSL_CTX* InitServerCTX()
{
    SSL_CTX *ctx;
    /* SSL 庫初始化 */
    SSL_library_init();
    /* 載入所有 SSL 演算法 */
    OpenSSL_add_all_algorithms();
    /* 載入所有 SSL 錯誤訊息 */
    SSL_load_error_strings();
    /* 以 SSL V2 和 V3 標準相容方式產生一個 SSL_CTX ，即 SSL Content Text */
    ctx = SSL_CTX_new(SSLv23_server_method());
    /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 單獨表示 V2 或 V3標準 */
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* 載入使用者的數字證書， 此證書用來發送給客戶端。 證書裡包含有公鑰 */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* 載入使用者私鑰 */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* 檢查使用者私鑰是否正確 */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
        printf("Digital certificate information:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Certificate: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificate information！\n");
}

struct User{
    string name;
    string ip;
    string portNum;
    string publicKey;
    int balance;
    bool isOnline;
    int socket;
    SSL* ssl;
    RSA *public_key;
    User(string name):name(name), ip(""), portNum(""), publicKey("public key"), isOnline(false), balance(10000), socket(0), ssl(),public_key(){};
};

struct SocketParam{
	int newSockfd;
    char *client_ip;
    SSL* ssl;
	SocketParam(int newSockfd, char *client_ip, SSL* ssl): newSockfd(newSockfd), client_ip(client_ip), ssl(ssl){};
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
    SSL* ssl = msg.ssl;

    int read_size;
    char client_message[MAX_BUFFER_LEN] = {0};
    char server_reply[MAX_RECV_LEN] = {0};
	//Receive a message from client
    string name;
	while(1)
	{
        if((read_size = SSL_read(ssl , client_message , MAX_BUFFER_LEN)) > 0){
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
                    SSL_write(ssl, server_reply, strlen(server_reply));
                    bzero(server_reply,sizeof(server_reply));
                    bzero(client_message,sizeof(client_message));
                } else{
                    cout << "-------------------------------\n";
                    cout << "Dedicate username register,  " << newUser << "!\n";
                    cout << "-------------------------------\n\n";
                    strcat(server_reply, "201 FAIL\n");
                    SSL_write(ssl, server_reply, strlen(server_reply));
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
                    SSL_write(ssl, server_reply, strlen(server_reply));
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
                    userData[pos].ssl = ssl;

                    // 存取 public key
                    X509 *cert = SSL_get_peer_certificate(ssl);
                    EVP_PKEY *public_key = X509_get_pubkey(cert);
                    RSA *rsa_publicKey = EVP_PKEY_get1_RSA(public_key);
                    userData[pos].public_key = rsa_publicKey;
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
                    SSL_write(ssl, server_reply, strlen(server_reply));
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
                X509 *cert = SSL_get_peer_certificate(thisOne.ssl);
                char *line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
                string line_string = line;
                strcat(server_reply, line_string.c_str()); strcat(server_reply, "\n");
                strcat(server_reply, to_string(onLineCount).c_str()); strcat(server_reply, "\n");
                for(int i = 0; i < userData.size(); i++){
                    if(userData[i].isOnline == true){
                        strcat(server_reply, userData[i].name.c_str()); strcat(server_reply, "#");
                        strcat(server_reply, userData[i].ip.c_str()); strcat(server_reply, "#");
                        strcat(server_reply, userData[i].portNum.c_str()); strcat(server_reply, "\n");
                    }
                }
                SSL_write(ssl, server_reply, strlen(server_reply));
                bzero(server_reply,sizeof(server_reply));
                bzero(client_message,sizeof(client_message));   
            }
            //transaction 
            else if(client_message[0] == 'T'){
                cout << ">> messages from client: " << message.substr(9) << "\n";

                unsigned char *cipher = find((unsigned char *)client_message, (unsigned char *)client_message + sizeof(client_message), '&');
                *cipher = '\0';
                cipher++;

                string plaintext = client_message;
                cout << "text after decrypt: " << plaintext << "\n";

                int del = plaintext.find("#");
                string payerName = plaintext.substr(1, del - 1);
                string rest = plaintext.substr(del + 1, string::npos);
                int del2 = rest.find("#");
                string money = rest.substr(0, del2);
                string payeeName = rest.substr(del2 + 1, string::npos);

                RSA *payee_rsa_pubkey, *payer_rsa_pubkey;

                int payerId = checkUserExist(payerName);
                int payeeId = checkUserExist(payeeName);

                payer_rsa_pubkey = userData[payerId].public_key;
                payee_rsa_pubkey = userData[payeeId].public_key;
                cout << "payer public key: \n";
                cout << payer_rsa_pubkey << "\n";
                BIO * print_out_payer=BIO_new(BIO_s_file());
                BIO_set_fp(print_out_payer,stdout,BIO_NOCLOSE);
                RSA_print(print_out_payer, payer_rsa_pubkey, 0);


                cout << "payee public key: \n";
                cout << payee_rsa_pubkey << "\n";
                BIO * print_out_payee=BIO_new(BIO_s_file());
                BIO_set_fp(print_out_payee,stdout,BIO_NOCLOSE);
                RSA_print(print_out_payee, payee_rsa_pubkey, 0);

                unsigned char *text = (unsigned char *)malloc(RSA_size(payee_rsa_pubkey));
                unsigned char *text_2 = (unsigned char *)malloc(RSA_size(payee_rsa_pubkey));

                /*** decrypt ***/
                // int err = RSA_public_decrypt(RSA_size(payee_rsa_pubkey), (unsigned char *)cipher, text, payee_rsa_pubkey, RSA_PKCS1_PADDING);
                // if (err == -1)
                // {
                //     ERR_print_errors_fp(stderr);
                // }

                // err = RSA_public_decrypt(RSA_size(payee_rsa_pubkey), (unsigned char *)cipher + RSA_size(payee_rsa_pubkey), text + RSA_BLOCK_SIZE, payee_rsa_pubkey, RSA_PKCS1_PADDING);
                // if (err == -1)
                // {
                //     ERR_print_errors_fp(stderr);
                // }

                // err = RSA_public_decrypt(RSA_size(payer_rsa_pubkey), text, text_2, payer_rsa_pubkey, RSA_PKCS1_PADDING);
                // if (err == -1)
                // {
                //     ERR_print_errors_fp(stderr);
                // }
                // cout << "text after decrypt:";
                // for (int i = 0; i < sizeof(text_2); i++)
                // {
                //     cout << text_2[i];
                // }
                // cout << "\n";

                userData[payerId].balance -= stoi(money);
                userData[payeeId].balance += stoi(money);

                strcat(server_reply, "Transfer OK!\n");
                SSL_write(userData[payerId].ssl, server_reply, strlen(server_reply));
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
                SSL_write(ssl, server_reply, strlen(server_reply));
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
                SSL_write(ssl, server_reply, strlen(server_reply));
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

    char cmd[2000] =  "openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt";
    system(cmd);
    SSL_CTX* ctx;
    SSL *ssl;
    SSL_METHOD *meth;

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
    cout << "\nWaiting for connection... \n\n";

    //Accept and incoming connection
    int newSockfd = 0;
    socklen_t addrlen = sizeof(clientInfo);
    char client_message[MAX_BUFFER_LEN] = {0};
    char server_reply[MAX_RECV_LEN] = {0};
    while(true){
        /* Create a SSL_METHOD structure (choose a SSL/TLS protocol version) */
        meth = (SSL_METHOD *)TLS_method();

        /* Create a SSL_CTX structure */
        ctx = SSL_CTX_new(meth);
        if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            exit(1);
        }

        /* Load the private-key corresponding to the server certificate */
        if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            exit(1);
        }

        /* Check if the server certificate and private-key matches */
        if (!SSL_CTX_check_private_key(ctx))
        {
            fprintf(stderr, "Private key does not match the certificate public key\n");
            exit(1);
        }

        newSockfd = accept(serverSockfd, (struct sockaddr *)&clientInfo, &addrlen);

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, newSockfd);
        /* 建立 SSL 連線 */
        if (SSL_accept(ssl) == -1)
        {
            ERR_print_errors_fp(stderr);
            close(newSockfd);
            continue;
        }
        ShowCerts(ssl);


        if(connectCnt < 3){
            strcat(server_reply, "Connected to the server!\n");
            SSL_write(ssl, server_reply, strlen(server_reply));
            bzero(server_reply,sizeof(server_reply));

            cout << "Connection accepted.\n";
            connectCnt++;

            //Get the ip address of the connected client
            char *client_ip = inet_ntoa(clientInfo.sin_addr);
            int client_port = ntohs(clientInfo.sin_port);

            pthread_t pid;
            SocketParam param(newSockfd, client_ip, ssl);
            if( pthread_create( &pid, NULL, connection_handler, &param) < 0)
            {
                cout << ("Could not create thread.\n");
                return 0;
            }

            cout << "client IP:" << client_ip << ", client port:" << client_port << " connected.\n\n";
        } else{
            strcat(server_reply, "Exceed the connection limit of 3 clients!\n");
            SSL_write(ssl, server_reply, strlen(server_reply));
            bzero(server_reply,sizeof(server_reply));

			
            /* 關閉 SSL 連線 */
            SSL_shutdown(ssl);
            /* 釋放 SSL */
            SSL_free(ssl);
            /* 關閉 socket */
            close(newSockfd);
            pthread_exit(NULL);
			puts("exceed the connection limit of 3 clients!\n");
        }
    }
    if(newSockfd == -1){
        cout << "accept failed.\n";
        return 0;
    }
}



