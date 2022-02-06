#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <cstdlib>
using namespace std;

#define MAX_BUFFER_LEN 100
#define MAX_RECV_LEN 1000
#define RSA_BLOCK_SIZE 256 - 12
#define KBITS 1024
#define KEXP 3

// #define PUB_KEY_FILE "public.pem"
// #define PRI_KEY_FILE "private.pem"

#define KEY_FILE (char*)"keys/client.key"
#define CERT_FILE (char*)"keys/client.crt"
#define CA_FILE (char*)"keys/CA.pem"

struct SocketParam{
	int sockfd;
    int socket_desc;
    SSL* ssl;
	SocketParam(int sockfd, int socket_desc, SSL* ssl): sockfd(sockfd), socket_desc(socket_desc), ssl(ssl){};
};
void printInstructionBefore();
void printInstructionAfter();
void afterLogin(int socket_desc, char *portnum, SSL *ssl, SSL_CTX* ctx);
void *transaction(void *param);
char *ip;
int port;

void GenerateRSAKey(string & out_pub_key, string & out_pri_key){
    size_t pri_len = 0;
    size_t pub_len = 0;
    char *pri_key = nullptr;
    char *pub_key = nullptr;

    RSA *keypair = RSA_generate_key(KBITS, (unsigned long)KEXP, NULL, NULL);

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSA_PUBKEY(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = (char *)malloc(pri_len +1);
    pub_key = (char *)malloc(pub_len +1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    out_pub_key = pub_key;
    out_pri_key = pri_key;

    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);
    free(pri_key);
    free(pub_key);
}

SSL_CTX* InitClientCTX()
{
    SSL_CTX *ctx;
    /* SSL 庫初始化 */
    SSL_library_init();
    /* 載入所有 SSL 演算法 */
    OpenSSL_add_all_algorithms();
    /* 載入所有 SSL 錯誤訊息 */
    SSL_load_error_strings();
    /* 以 SSL V2 和 V3 標準相容方式產生一個 SSL_CTX ，即 SSL Content Text */
    ctx = SSL_CTX_new(SSLv23_client_method());
    /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 單獨表示 V2 或 V3標準 */
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        abort();
    }
    return ctx;
}

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

bool generate_key()
{
	int				ret = 0;
	RSA				*r = NULL;
	BIGNUM			*bne = NULL;
	BIO				*bp_public = NULL, *bp_private = NULL;

	int				bits = 2048;
	unsigned long	e = RSA_F4;

	// 1. generate rsa key
	bne = BN_new();
	ret = BN_set_word(bne,e);
	// if(ret != 1){
	// 	goto free_all;
	// }

	r = RSA_new();
    X509 *x = NULL;
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	// if(ret != 1){
	// 	goto free_all;
	// }

	// 2. save public key
	bp_public = BIO_new_file("public.pem", "w+"); //PEM_write_bio_X509
	ret = PEM_write_bio_X509(bp_public, x); //PEM_write_bio_RSAPublicKey //PEM_write_bio_RSA_PUBKEY
	// if(ret != 1){
	// 	goto free_all;
	// }

	// 3. save private key
	bp_private = BIO_new_file("private.pem", "w+");
	ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

	// 4. free
    // free_all:
	// BIO_free_all(bp_public);
	// BIO_free_all(bp_private);
	// RSA_free(r);
	// BN_free(bne);

	return (ret == 1);
}

int main(int argc, char *argv[])
{
    /*----------create a socket-------------*/
    SSL_CTX* ctx = InitClientCTX();
    char cmd[2000] =  "openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout client.key -out client.crt";
    system(cmd);
    // generate_key();
    LoadCertificates(ctx, CERT_FILE, KEY_FILE);
    //a descriptor
    int socket_desc = 0;
    //Address Family - AF_INET (this is IP version 4) ,Type - SOCK_STREAM (this means connection oriented TCP protocol) ,Protocol - 0 [ or IPPROTO_IP This is IP protocol]
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    //socket創建失敗
    if (socket_desc == -1)
    {
        printf("Could not create socket\n");
    }

    /*----------connect socket to a server-------------*/
    //create a sockaddr_in structure with proper values
    struct sockaddr_in server;
    bzero(&server, sizeof(server)); //初始化，將struct涵蓋的bits設為0

    //Connect to remote server
    if (argc != 3)
    {
        printf("Input error, please input IP and portNum.\n");
        return 1;
    }
    else
    {
        ip = argv[1];
        port = atoi(argv[2]);
    }
    //function inet_addr is a very handy function to convert an IP address to a long format
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    /*----------send data over socket-------------*/
    int client_serviceNum;
    char client_request[MAX_BUFFER_LEN] = {0};
    char server_reply[MAX_RECV_LEN] = {0};
    char username[100] = {0};
    char portnum[100] = {0};
    SSL *ssl;

    if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) == -1)
    {
        printf("Connect error\n");
        return 1;
    }
    else{
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, socket_desc);
        /* 建立 SSL 連線 */
        if (SSL_connect(ssl) == -1)
        {
            ERR_print_errors_fp(stderr);
            return 1;
        }
        else
        {
            printf("\n");
            printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
            ShowCerts(ssl);
        }

        SSL_read(ssl, server_reply, MAX_RECV_LEN);
        puts(server_reply);
        if (strcmp(server_reply, "Exceed the connection limit of 3 clients!\n") == 0)
        {
            bzero(server_reply, sizeof(server_reply));
            close(socket_desc);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            return 0;
        }
        else
        {
            bzero(server_reply, sizeof(server_reply));
        }
    }

    while (1)
    {
        printInstructionBefore();
        printf("> service number:");
        scanf("%d", &client_serviceNum);

        //Register
        if (client_serviceNum == 0)
        {
            printf("Please enter your username for registration: ");
            scanf("%s", username);
            strcat(client_request, "REGISTER#");
            strcat(client_request, username);
            SSL_write(ssl, client_request, strlen(client_request));
            SSL_read(ssl, server_reply, MAX_RECV_LEN);
            puts(server_reply);
            if (strcmp(server_reply, "210 FAIL\n") == 0)
            {
                printf("The username has been used.\n");
            }
            if (strcmp(server_reply, "100 OK\n") == 0)
            {
                printf("Registration completed!\n");
            }
            bzero(server_reply, sizeof(server_reply));
            bzero(client_request, sizeof(client_request));
            continue;
        }
        //Login
        else if (client_serviceNum == 1)
        {
            printf("Please enter your username: ");
            scanf("%s", username);
            printf("Please enter a port number(between 1024 to 65535): ");
            scanf("%s", portnum);

            while (1)
            {
                if (atoi(portnum) < 1024 || atoi(portnum) > 65535)
                {
                    printf("Please enter a valid port number(between 1024 to 65535): ");
                    scanf("%s", portnum);
                }
                else
                {
                    strcat(client_request, username);
                    strcat(client_request, "#");
                    strcat(client_request, portnum);
                    break;
                }
            }

            SSL_write(ssl, client_request, strlen(client_request));
            SSL_read(ssl, server_reply, MAX_RECV_LEN);
            puts(server_reply);
            if (strcmp(server_reply, "220 AUTH_FAIL\n") == 0)
            {
                printf("It is a wrong username.\n");
                bzero(server_reply, sizeof(server_reply));
                bzero(client_request, sizeof(client_request));
            }
            else
            {
                afterLogin(socket_desc, portnum, ssl, ctx);
                bzero(server_reply, sizeof(server_reply));
                bzero(client_request, sizeof(client_request));
                return 0;
            }
        }
        //Exit
        else if (client_serviceNum == 2)
        {
            strcat(client_request, "exit");
            SSL_write(ssl, client_request, strlen(client_request));
            SSL_read(ssl, server_reply, MAX_RECV_LEN);
            puts(server_reply);
            bzero(server_reply, sizeof(server_reply));
            bzero(client_request, sizeof(client_request));
            close(socket_desc);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            break;
        }
        //Wrong service number
        else
        {
            printf("It is not a valid service number.\n");
            continue;
        }
    }
    return 0;
}

void printInstructionBefore()
{
    printf("Please enter the number of service(you haven't logged in yet): \n");
    printf("0: Register a new account\n");
    printf("1: Login\n");
    printf("2: Exit\n");
    printf("======================================\n");
}

void printInstructionAfter()
{
    printf("Please enter the number of service(you have logged in!): \n");
    printf("0: List account balance and accounts online\n");
    printf("1: Transaction\n");
    printf("2: Exit\n");
    printf("======================================\n");
}

void afterLogin(int socket_desc, char *portnum, SSL *ssl, SSL_CTX* ctx)
{

    // create thread for peer to peer communication
    int sockfd = 0;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf("Could not create socket.\n");
    }

    struct sockaddr_in server;
    bzero(&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(atoi(portnum));
    bind(sockfd, (struct sockaddr *)&server, sizeof(server)); //把自己家地址綁在Socket身上
    listen(sockfd, 10);                                       //設置Server(client listen to client)的監聽隊列

    // int input[3] = {sockfd, socket_desc, ssl}; //listen's socket, remote server's socket
    pthread_t tid;
    SocketParam param(sockfd, socket_desc, ssl);
    if (pthread_create(&tid, NULL, transaction, &param) != 0)
    {
        printf("Failed to create thread\n");
    }

    int client_serviceNum;
    char client_request[MAX_BUFFER_LEN] = {0};
    char server_reply[MAX_RECV_LEN] = {0};
    while (1)
    {
        printInstructionAfter();
        printf("> service number:");
        scanf("%d", &client_serviceNum);
        //List
        if (client_serviceNum == 0)
        {
            strcat(client_request, "List");
            SSL_write(ssl, client_request, strlen(client_request));
            SSL_read(ssl, server_reply, MAX_RECV_LEN);
            puts(server_reply);
            bzero(server_reply, sizeof(server_reply));
            bzero(client_request, sizeof(client_request));
            continue;
        }
        //transaction
        else if (client_serviceNum == 1)
        {
            printf("This is a list of your account balance and users online: \n");
            strcat(client_request, "List");
            SSL_write(ssl, client_request, strlen(client_request));
            SSL_read(ssl, server_reply, MAX_RECV_LEN);
            puts(server_reply);

            //get payee's ip and port num
            char payee_name[100];
            int payee_port = 0;
            char payee_IP[MAX_RECV_LEN];
            printf("Please enter the payee's username: ");
            scanf("%s", payee_name);
            char *token = strstr(server_reply, payee_name);
            while (1)
            {
                if (token == NULL)
                {
                    printf("Please enter an online payee's username: ");
                    scanf("%s", payee_name);
                }
                else
                {
                    break;
                }
            }
            token = strtok(token, "#");
            token = strtok(NULL, "#");
            strcat(payee_IP, token);
            token = strtok(NULL, "#");
            payee_port = atoi(token);

            bzero(server_reply, sizeof(server_reply));
            bzero(client_request, sizeof(client_request));

            char username[100] = {0};
            char payAmount[100] = {0};
            printf("Please enter your username: ");
            scanf("%s", username);
            printf("Please enter the amount: ");
            scanf("%s", payAmount);

            strcat(client_request, username);
            strcat(client_request, "#");
            strcat(client_request, payAmount);
            strcat(client_request, "#");
            strcat(client_request, payee_name);

            /** Encrypt **/
            FILE *key_file = fopen(KEY_FILE, "r");

            RSA *privateKey = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
            RSA *publicKey = PEM_read_RSAPublicKey(key_file, NULL, NULL, NULL);
            char *buf = (char *)malloc(RSA_size(privateKey));
            int err = RSA_private_encrypt((strlen(client_request) + 1) * sizeof(char), (unsigned char *)client_request, (unsigned char *)buf, privateKey, RSA_PKCS1_PADDING);
            if (err == -1)
            {
                ERR_print_errors_fp(stderr);
            }

            //connect to another payee
            int transfd = 0;
            transfd = socket(AF_INET, SOCK_STREAM, 0);
            if (transfd == -1)
            {
                printf("Could not create socket.");
            }

            struct sockaddr_in trans;
            bzero(&trans, sizeof(trans));

            SSL* ssl_2;
            /* Create an SSL_METHOD structure (choose an SSL/TLS protocol version) */
            SSL_METHOD *meth = (SSL_METHOD *)TLS_method();
            /* Create an SSL_CTX structure */
            SSL_CTX *ctx = SSL_CTX_new(meth);

            trans.sin_family = AF_INET;
            trans.sin_addr.s_addr = INADDR_ANY; // inet_addr(payee_IP)
            trans.sin_port = htons(payee_port);
            
            if (connect(transfd, (struct sockaddr *)&trans, sizeof(trans)) == -1)
            {
                printf("Connect error");
                break;
            } else {
                /* 基於 ctx 產生一個新的 SSL */
                ssl_2 = SSL_new(ctx);
                /* Assign the socket into the SSL structure (SSL and socket without BIO) */
                if (SSL_use_certificate_file(ssl_2, CERT_FILE, SSL_FILETYPE_PEM) <= 0)
                {
                    ERR_print_errors_fp(stderr);
                    exit(1);
                }

                /* Load the private-key corresponding to the client certificate */
                if (SSL_use_PrivateKey_file(ssl_2, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
                {
                    ERR_print_errors_fp(stderr);
                    exit(1);
                }

                /* Check if the client certificate and private-key matches */
                if (!SSL_check_private_key(ssl_2))
                {
                    fprintf(stderr, "Private key does not match the certificate public key\n ");
                    exit(1);
                }
                SSL_set_fd(ssl_2, transfd);
                /* 建立 SSL 連線 */
                if (SSL_connect(ssl_2) == -1)
                {
                    ERR_print_errors_fp(stderr);
                    continue;
                }
                else
                {
                    printf("Connected with %s encryption\n", SSL_get_cipher(ssl_2));
                    // ShowCerts(ssl_2);
                }
                printf("Connection to other client success.\n");
            }


            SSL_write(ssl_2, buf, RSA_size(privateKey));
            printf("\nmessage sent to clients receiver:\n");
            puts(buf);
            printf("\n");

            // X509 *cert_2 = SSL_get_peer_certificate(ssl_2);
            // EVP_PKEY *public_key_2 = X509_get_pubkey(cert_2);
            // RSA *rsa_publicKey = EVP_PKEY_get1_RSA(public_key_2);

            // SSL_write(ssl_2, rsa_publicKey, RSA_size(rsa_publicKey));

            SSL_read(ssl, server_reply, MAX_RECV_LEN);
            printf("====================================\n");
            puts(server_reply);

            bzero(server_reply, sizeof(server_reply));
            bzero(client_request, sizeof(client_request));
            continue;
        }
        //Exit
        else if (client_serviceNum == 2)
        {
            strcat(client_request, "Exit");
            SSL_write(ssl, client_request, strlen(client_request));
            SSL_read(ssl, server_reply, MAX_RECV_LEN);
            puts(server_reply);
            bzero(server_reply, sizeof(server_reply));
            bzero(client_request, sizeof(client_request));
            close(socket_desc);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            break;
        }
        //Wrong service number
        else
        {
            printf("It is not a valid service number.\n");
            continue;
        }
    }
}

void *transaction(void *param) //Another thread. As a server(payee), connect to payer
{

    SocketParam msg = *(SocketParam*) param;
	int sockfd = msg.sockfd;
    int socket_desc = msg.socket_desc;
    SSL* ssl = msg.ssl;

    while (1)
    {
        SSL *ssl_cli;
        /* Create an SSL_METHOD structure (choose an SSL/TLS protocol version) */
        SSL_METHOD *meth = (SSL_METHOD *)TLS_method();

        /* Create an SSL_CTX structure */
        SSL_CTX *ctx_cli = SSL_CTX_new(meth);

        /* Load the client certificate into the SSL_CTX structure */
        if (SSL_CTX_use_certificate_file(ctx_cli, CERT_FILE, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            exit(1);
        }

        /* Load the private-key corresponding to the client certificate */
        if (SSL_CTX_use_PrivateKey_file(ctx_cli, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            exit(1);
        }

        /* Check if the client certificate and private-key matches */
        if (!SSL_CTX_check_private_key(ctx_cli))
        {
            fprintf(stderr, "Private key does not match the certificate public key\n ");
            exit(1);
        }
        struct sockaddr_in client;
        int clientfd = 0;
        socklen_t addrlen = sizeof(client);
        clientfd = accept(sockfd, (struct sockaddr *)&client, &addrlen); //Server(client listen to client) 接收請求

        SSL_CTX_set_verify(ctx_cli, SSL_VERIFY_PEER, NULL);
        SSL_CTX_load_verify_locations(ctx_cli, CA_FILE, NULL);
        ssl_cli = SSL_new(ctx_cli);
        SSL_set_fd(ssl_cli, clientfd);
        /* 建立 SSL 連線 */
        if (SSL_accept(ssl_cli) == -1)
        {
            ERR_print_errors_fp(stderr);
            close(clientfd);
            continue;
        }
        // ShowCerts(ssl_cli);

        char receiveMessage[MAX_RECV_LEN] = {0};

        SSL_read(ssl_cli, receiveMessage, sizeof(receiveMessage));
        printf("\nmessage received from clients sender:\n");
        puts(receiveMessage);
        printf("\n");
        /*** Certificate ***/
        X509 *peer_cert = SSL_get_peer_certificate(ssl_cli);
        if (peer_cert == NULL)
        {
            printf("No Certificate Received\n");
        }
        EVP_PKEY *peer_pubkey = X509_get_pubkey(peer_cert);
        /*** Decrypt ***/
        unsigned char *peer_msg_plain = (unsigned char *)malloc(MAX_RECV_LEN);
        RSA *peer_rsa_pubkey = EVP_PKEY_get1_RSA(peer_pubkey);

        cout << peer_rsa_pubkey << "\n";
        BIO * print_out=BIO_new(BIO_s_file());
        BIO_set_fp(print_out,stdout,BIO_NOCLOSE);
        RSA_print(print_out, peer_rsa_pubkey, 0);

        int err = RSA_public_decrypt(RSA_size(peer_rsa_pubkey), (unsigned char *)receiveMessage, peer_msg_plain, peer_rsa_pubkey, RSA_PKCS1_PADDING);
        if (err == -1)
        {
            ERR_print_errors_fp(stderr);
        }
        printf("\ndecrypt plain peer message: ");
        cout << peer_msg_plain;
        printf("\n");

        /**** Encrypt ****/
        FILE *fp = fopen(KEY_FILE, "r");
        RSA *privateKey = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
        unsigned char *to_server = (unsigned char *)malloc(MAX_BUFFER_LEN * sizeof(char) + 2 * RSA_size(privateKey));
        unsigned char *cipher_text1 = (unsigned char *)malloc(RSA_size(privateKey));
        unsigned char *cipher_text2 = (unsigned char *)malloc(RSA_size(privateKey));
        unsigned char *peer_msg1 = (unsigned char *)malloc(RSA_size(privateKey));
        unsigned char *peer_msg2 = (unsigned char *)malloc(RSA_size(privateKey));
        copy(receiveMessage, receiveMessage + RSA_BLOCK_SIZE, peer_msg1);
        copy(receiveMessage + RSA_BLOCK_SIZE, receiveMessage + RSA_size(privateKey), peer_msg2);

        if(sizeof(peer_msg1) > RSA_BLOCK_SIZE){
            printf("the words to encrypt are too long\n");
            exit(1);
        }
        int res = RSA_private_encrypt((RSA_BLOCK_SIZE), (unsigned char *)peer_msg1, cipher_text1, privateKey, RSA_PKCS1_PADDING);
        if (res == -1)
        {
            ERR_print_errors_fp(stderr);
        }
        res = RSA_private_encrypt(RSA_size(privateKey) - (RSA_BLOCK_SIZE), (unsigned char *)peer_msg2, cipher_text2, privateKey, RSA_PKCS1_PADDING);
        if (res == -1)
        {
            ERR_print_errors_fp(stderr);
        }
        
        to_server[0] = 'T';
        copy(peer_msg_plain, peer_msg_plain + sizeof(peer_msg_plain), to_server + 1);
        to_server[sizeof(peer_msg_plain) + 1] = '&';
        copy(cipher_text1, cipher_text1 + RSA_size(privateKey), (to_server + 1) + sizeof(peer_msg_plain) + 1);
        copy(cipher_text2, cipher_text2 + RSA_size(privateKey), (to_server + 1) + sizeof(peer_msg_plain) + 1 + RSA_size(privateKey));
        SSL_write(ssl, to_server, MAX_BUFFER_LEN * sizeof(char) + 2 * RSA_size(privateKey));

        bzero(receiveMessage, sizeof(receiveMessage));
    }
}
