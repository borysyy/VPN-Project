#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <shadow.h>
#include <crypt.h>


#define PORT_NUMBER 4433
#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }


struct sockaddr_in clientAddr;

// Create TUN interface
int createTunDevice() {
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


int initTCPServer() {
    int server_socket;
    struct sockaddr_in server;

    memset(&server, 0, sizeof(server));

    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket Creation Failed");
        return -1;
    }

    int yes = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT_NUMBER);

    if (bind(server_socket, (struct sockaddr*) &server, sizeof(server)) == -1)
    {
        perror("Binding Failed");
        return -1;
    }

    if (listen(server_socket, 5) == -1)
    {
        perror("Listening Failed");
        return -1;
    }
  
    return server_socket;  
}

SSL* setupTLSServer()
{

   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_ssl_algorithms();

   SSL_METHOD *meth;
   SSL* ssl;

   SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

   SSL_CTX_use_certificate_file(ctx, "./cert_server/server-cert.pem", SSL_FILETYPE_PEM);
   SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/server-key.pem", SSL_FILETYPE_PEM);
   ssl = SSL_new (ctx);


   return ssl;
}



void tunSelected(int tunfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    if (len > 0)
    {
        SSL_write(ssl, buff, len);
    }
}

void socketSelected (int tunfd, SSL *ssl){
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


void sendUsernamePrompt(SSL *ssl)
{
    char *loginPrompt = "Username: ";
    SSL_write(ssl, loginPrompt, strlen(loginPrompt));
}

void sendAuthResult(SSL *ssl, int success)
{
    char *successMsg = "Authentication Successful\n";
    char *failureMsg = "Authentication Failed\n";

    success = htonl(success);
    
    if (success) 
    {
        SSL_write(ssl, successMsg, strlen(successMsg));
    } 
    else 
    {
        SSL_write(ssl, failureMsg, strlen(failureMsg));
    }

    SSL_write(ssl, &success, sizeof(success));

}

void getUserResponse(SSL *ssl, char *buffer, int size)
{
    int len = SSL_read(ssl, buffer, size - 1);
    if (len <= 0) 
    {
        int err = SSL_get_error(ssl, len);
        printf("SSL_read error: %d\n", err);
        buffer[0] = '\0';
        return;
    }
    buffer[len] = '\0'; 
}

int getSalt(SSL *ssl, char *user)
{
    struct spwd *shadowPasswordEntry;

    shadowPasswordEntry = getspnam(user);
    if (shadowPasswordEntry == NULL) 
    {
        printf("User not found: %s\n", user);
        return -1; // User not found
    }

    char *salt = shadowPasswordEntry->sp_pwdp;

    SSL_write(ssl, salt, strlen(salt));

    return 0;
}



int login(char *user, char *passwd)
{
    struct spwd *shadowPasswordEntry;

    printf("Authenticating user: %s\n", user);

    user[strcspn(user, "\n")] = 0; 

    shadowPasswordEntry = getspnam(user);

    if (strcmp(passwd, shadowPasswordEntry->sp_pwdp) == 0) 
    {
        return 1; // Authentication successful
    } 
    else
    {
        return 0; // Authentication failed
    }
}

int main (int argc, char * argv[]) 
{
    int tunfd, listenfd, clientfd;
    char username[256];
    char password[256];
    
    listenfd = initTCPServer();
    
    
    // Enter the main loop
    while (1) {

        printf("Waiting for a client...\n");
        
        socklen_t clientAddrLen = sizeof(clientAddr);
    
        if((clientfd = accept(listenfd, (struct sockaddr*)&clientAddr, &clientAddrLen)) == -1)
        {
            perror("Acceptance Failed");
            return -1;
        }

        printf("Client connected!\n");

        
        SSL *ssl = setupTLSServer();
        
        SSL_set_fd(ssl, clientfd);
        int err = SSL_accept(ssl);
        CHK_SSL(err);
        printf("TLS handshake complete\n");
        
        sendUsernamePrompt(ssl);
        
        printf("Waiting for client response...\n");
        getUserResponse(ssl, username, sizeof(username));

        printf("Waiting for client response...\n");
        getUserResponse(ssl, password, sizeof(password));

        if(login(username, password)) {
            printf("User %s authenticated successfully.\n", username);
            sendAuthResult(ssl, 1);
        } else {
            printf("Authentication failed for user %s.\n", username);
            sendAuthResult(ssl, 0);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(clientfd);
            continue; 
        }

        tunfd  = createTunDevice();

        printf("Tun Device Created\n");
 
            
        while(1)
        {
            fd_set readFDSet;
            FD_ZERO(&readFDSet);
            FD_SET(clientfd, &readFDSet);
            FD_SET(tunfd, &readFDSet);
            select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
            
            if (FD_ISSET(tunfd,  &readFDSet))
            {
                tunSelected(tunfd, ssl);
            }
            if (FD_ISSET(clientfd, &readFDSet)) 
            {
                socketSelected(tunfd, ssl);
            }
            
        }
    
            
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(clientfd);

    }

    return 0;
}
