#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>



#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "ca_client" 


int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) 
    {
       printf("Verification passed.\n");
    } 
    else 
    {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n",
                    X509_verify_cert_error_string(err));
    }

    return preverify_ok;

}


int createTunDevice() 
{
    int tunfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

    tunfd = open("/dev/net/tun", O_RDWR);
    if (tunfd < 0) 
    {
        perror("Opening /dev/net/tun");
        return -1;
    }

    if (ioctl(tunfd, TUNSETIFF, &ifr) < 0) 
    {
        perror("ioctl(TUNSETIFF)");
        close(tunfd);
        return -1;
    }  

    return tunfd;
}

int connectToTCPServer(const char* hostname, int port) 
{
    int server_socket;
    struct sockaddr_in serverAddr;

    struct hostent* hp = gethostbyname(hostname);
    
    memset(&serverAddr, 0, sizeof(serverAddr));

    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket Creation Failed");
        return -1;
    }

    memset (&serverAddr, '\0', sizeof(serverAddr));
    memcpy(&(serverAddr.sin_addr.s_addr), hp->h_addr, hp->h_length);
    serverAddr.sin_port   = htons (port);
    serverAddr.sin_family = AF_INET;

    if (connect(server_socket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) 
    {
        perror("connect");
        close(server_socket);
        return -1;
    }

    printf("Connected to server!\n");

    return server_socket;

}

SSL* setupTLSClient(const char* hostname)
{

   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_ssl_algorithms();

   SSL_METHOD *meth;
   SSL *ssl;

   SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());


   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
   if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1)
   {
	printf("Error setting the verify locations. \n");
	exit(0);
   }

   ssl = SSL_new (ctx);

   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

   return ssl;
}

void getPrompt(SSL *ssl)
{
    char buff[256];
    int len;

    memset(buff, 0, sizeof(buff));

    len = SSL_read(ssl, buff, sizeof(buff) - 1);

    if (len <= 0) 
    {
        int err = SSL_get_error(ssl, len);
        printf("SSL_read error: %d\n", err);
        return;
    }

    buff[len] = '\0';
    printf("%s", buff);
}


void tunSelected(int tunfd, SSL *ssl)
{
    int  len;
    char buff[BUFF_SIZE];

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    if (len > 0)
    {
        SSL_write(ssl, buff, len);
    }
}

void socketSelected (int tunfd, SSL *ssl)
{
    int  len;
    char buff[BUFF_SIZE];

    bzero(buff, BUFF_SIZE);
    len = SSL_read(ssl, buff, BUFF_SIZE);
    if (len <= 0)
    {
        printf("TLS Connection Lost\n");
        return;
    }
   
    write(tunfd, buff, len);
    
}

int main (int argc, char * argv[]) 
{
   int tunfd, sockfd;

   int authenticated;

   char *hostname;
   int port;
   
   if (argc > 1) hostname = argv[1];
   if (argc > 2) port = atoi(argv[2]);
   
   
   while (1) {
       sockfd = connectToTCPServer(hostname, port);
       
       SSL *ssl = setupTLSClient(hostname);
       
       SSL_set_fd(ssl, sockfd);
       int err = SSL_connect(ssl); 
       CHK_SSL(err);
       printf("TLS handshake complete\n");
       
       // Get Username
       char username[256];
       getPrompt(ssl);
       fgets(username, sizeof(username), stdin);
       SSL_write(ssl, username, strlen(username));
        
       // Get Password
       char *password = getpass("Password: ");
       SSL_write(ssl, password, strlen(password));

       // Get Authentication Result
       getPrompt(ssl);
       SSL_read(ssl, &authenticated, sizeof(authenticated));
       authenticated = ntohl(authenticated);
    
        if (!authenticated) 
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sockfd);
            break;
        }
    
       tunfd  = createTunDevice();

       printf("Tun Device Created\n");


        while(1)
        {
            fd_set readFDSet;
            
            FD_ZERO(&readFDSet);
            FD_SET(sockfd, &readFDSet);
            FD_SET(tunfd, &readFDSet);
            select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
            
            if (FD_ISSET(tunfd,  &readFDSet))
            {
                tunSelected(tunfd, ssl);
            }
            if (FD_ISSET(sockfd, &readFDSet)) 
            {
                socketSelected(tunfd, ssl);
            }
            
        }
        
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
    }

    return 0;
}
