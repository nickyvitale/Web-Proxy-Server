#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <poll.h>
#include <openssl/bio.h> 
#include <openssl/ssl.h> 
#include <openssl/err.h> 
#include <netdb.h>
#define BUFFSIZE 100
#define MAXLINE 5000
#define NUMSITES 10
char **forbSites;
int forbSitesLength;

struct threadArgs{
	char *accessLogPath;
	int fd;
};

int isNumeric(char* num){
	for (int i = 0; i < num[i] != '\0'; i++){
                if (!isdigit(num[i])){
                        return 0;
		}
	}
	return 1;
}

int isValidPort(char *port){
	if (isNumeric(port)){
        	if (atoi(port) >= 1024 && atoi(port) <= 65535){
        	        return 1;
        	}
	}
	return 0;
}

int isValidWebPort(char *port){
	if (isNumeric(port)){
                if (atoi(port) >= 0 && atoi(port) <= 65535){
                        return 1;
                }
        }
        return 0;	
}

void terminateThread(struct threadArgs *args){
	close(args->fd);
	free(args);
	pthread_exit(NULL);
}

// This function handles client requests, and is essentially the "main" function for threads
void *reqHandler(void *arg){
	// Setup (Claim args, detach, set up return val)
	struct threadArgs* args = arg;
	pthread_detach(pthread_self());

	// Perform server's main functionality

	// Timestamps
	time_t now;
	struct timeval timVal;
	time(&now);
	struct tm *timeStruct = gmtime(&now);
	char nowString[MAXLINE], nowStringMS[MAXLINE], dateHeader[MAXLINE];
	gettimeofday(&timVal, NULL);
	// For Access Log
	strftime(nowString, sizeof nowString - 1, "%FT%T", timeStruct);
	sprintf(nowStringMS,"%s.%dZ", nowString, timVal.tv_usec/1000);
	// For HTTP Response Headers
	strftime(dateHeader, sizeof dateHeader - 1, "%a, %d %b %Y %H:%M:%S %Z", timeStruct);

	// Setup for buffers to read from client
	int bufSize = BUFFSIZE;
 	char *buffer[BUFFSIZE];
	char *clientRequest = (char *)malloc(bufSize*sizeof(char));
	int r;
	int bytesRead = 0;

	// Setup the struct for using poll
	struct pollfd fds[1];
	fds[0].fd = args->fd;
	fds[0].events = 0;
	fds[0].events |= POLLIN;
	int timeout = 1000; // 1 second

	// Now use poll to read request from from client, store in clientRequest buffer
	while (poll(fds, 1, timeout) != 0){
		if ((r = read(args->fd, buffer, BUFFSIZE)) < 0){
			fprintf(stderr, "Error reading\n");
			terminateThread(args);
		}
		
		if (bytesRead + r > bufSize){ // Must reallocate buffer
			bufSize *= 2;
			char *newBuff = (char *)realloc(clientRequest, bufSize*sizeof(char));
			if (newBuff != NULL){
				clientRequest = newBuff;
			}
			else {
				fprintf(stderr, "Couldn't reallocate buffer\n");
				terminateThread(args);
			}
		}

		memcpy(&clientRequest[bytesRead], &buffer, r); // Append buf to msg
		bytesRead+=r;
	}
	clientRequest[bytesRead] = '\0';

	// Parse request in order to create new request to the web server
	strtok(clientRequest, "\n"); // Get first line of that field
	char *requestType = strtok(clientRequest, " "); // GET or HEAD, etc

	char *secondField = strtok(NULL, " "); 
	char secondRemoveFront[100];
	memcpy(&secondRemoveFront, &secondField[7], strlen(secondField) - 7);

	char *domainName = strtok(secondRemoveFront, "/");
	char *docPath = strtok(NULL, "\0");
	if (docPath == NULL){
		docPath = "";
	}
	strtok(domainName, ":");
	char *port = strtok(NULL, "\0");
	if (port == NULL){
		port = "443";
	}

	// Next, some validation
	if (!isValidWebPort(port)){ // send 400 Response and exit thread
		char reply[MAXLINE];
		sprintf(reply, "HTTP/1.1 400 Bad Request\r\n"
		"Content-Length: 47\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Date: %s\r\n"
		"\r\n"
		"<!DOCTYPE html>\n"
		"<html>\n"
		"400 Bad Request\n"
		"</html>\n", dateHeader);
		write(args->fd, reply, strlen(reply));
		terminateThread(args);
	}

	struct hostent *hostInfo;
	if ((hostInfo = gethostbyname(domainName)) == NULL){
		fprintf(stderr, "Couldn't resolve IP Address from given domain name\n");
		terminateThread(args);
	}
	char *ipDottedDecimal = inet_ntoa(*(struct in_addr *)hostInfo->h_addr);	
	for (int i = 0; i < forbSitesLength; i++){
		if (strcmp(forbSites[i], domainName) == 0 || strcmp(forbSites[i], ipDottedDecimal) == 0){
			char reply[MAXLINE];
			sprintf(reply, "HTTP/1.1 403 Forbidden\r\n"
	                "Content-Length: 45\r\n"
			"Content-Type: text/html; charset=UTF-8\r\n"
                	"Date: %s\r\n"
			"\r\n"
			"<!DOCTYPE html>\n"
                	"<html>\n"
                	"403 Forbidden\n"
               		"</html>\n", dateHeader);
        	        write(args->fd, reply, strlen(reply));
              		terminateThread(args);
		}
	}
		
	if (strcmp(requestType, "GET") != 0 && strcmp(requestType, "HEAD") !=0){
		char reply[MAXLINE];
		sprintf(reply, "HTTP/1.1 501 Not Implemented\r\n"
                "Content-Length: 51\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
                "Date: %s\r\n"
                "\r\n"
                "<!DOCTYPE html>\n"
                "<html>\n"
                "501 Not Implemented\n"
                "</html>\n", dateHeader);
                write(args->fd, reply, strlen(reply));
                terminateThread(args);
	}

	// Begin Process of Connecting to Web Server
	
	// Create socket for web server
	int webServerFd; // This will be the socket that will be used to connect to the web server
	if ((webServerFd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		fprintf(stderr, "Couldn't create web server's socket\n");
		terminateThread(args);
	}

	struct sockaddr_in webserver;
	webserver.sin_family = AF_INET;
	webserver.sin_port = htons(atoi(port));
	webserver.sin_addr.s_addr = *(in_addr_t *)hostInfo->h_addr;

	if((connect(webServerFd, (struct sockaddr *) &webserver, sizeof(webserver)) < -1)){
		fprintf(stderr, "Couldn't connect socket to web server\n");
		terminateThread(args);
	}

	struct timeval tv; // timeout stuff
	tv.tv_sec = 1; // 5 second timer
	tv.tv_usec = 0;
	setsockopt(webServerFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	// Initialize OpenSSL library
	SSL_load_error_strings();
	SSL_library_init();

	// Create new SSL client connection
	const SSL_METHOD *const req_method = SSLv23_client_method();
	SSL_CTX *const ctx = SSL_CTX_new(req_method);
	if (ctx == NULL) {
		fprintf(stderr, "Couldn't create SSL context\n");
		terminateThread(args);
	}

	SSL* ssl;
	if ((ssl = SSL_new(ctx)) == NULL){
		fprintf(stderr, "Couldn't create new ssl\n");
		terminateThread(args);
	}
	if((SSL_set_fd(ssl, webServerFd)) == 0){
		fprintf(stderr, "Couldn't set the fd for ssl\n");
		terminateThread(args);
	}
	if(SSL_connect(ssl) != 1){
		fprintf(stderr, "Couldn't perform handshake for SSL\n");
		terminateThread(args);
	}
	
	// Make request to web server

	char reqToWeb[MAXLINE];
	sprintf(reqToWeb, "%s /%s HTTP/1.1\r\nHost: %s\r\n\r\n", requestType, docPath, domainName);
	if ((SSL_write(ssl, reqToWeb, strlen(reqToWeb))) < 0){
		fprintf(stderr, "Couldn't write to SSL\n");
                terminateThread(args);
	}

	// Read response from web server
	bufSize = BUFFSIZE; // Size of the webResponse's buffer
	bytesRead = 0; // Counter tracking how many bytes read
	buffer[0] = '\0'; // Resets buffer used earlier to prevent buffer overflow
	
	char *webResponse = (char*)malloc(bufSize*sizeof(char));
	while ((r = SSL_read(ssl, buffer, BUFFSIZE)) > 0){		
		if (bytesRead + r >= bufSize){
			bufSize *= 2;
			char *reallocWebResponse = (char*)realloc(webResponse, bufSize*sizeof(char));
			if (reallocWebResponse != NULL){
				webResponse = reallocWebResponse;
			}
			else{
				fprintf(stderr, "Couldn't reallocate buffer for Web Server's response\n");
				terminateThread(args);
			}
		}
		memcpy(&webResponse[bytesRead], &buffer, r);
		bytesRead += r;
	}
	webResponse[bytesRead] = '\0';
	
	// Write response back to client
	if ((write(args->fd, webResponse, bytesRead)) < 0){
		fprintf(stderr, "Couldn't write response to client\n");
		terminateThread(args);
	}
	
	// End program
	free(webResponse);
	free(clientRequest);
	close(webServerFd);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	terminateThread(args);
}

int main(int argc, char *argv[]){
	// Check input args
	if (argc != 4){
		fprintf(stderr, "EXPECTED: ./myproxy listenPort forbiddenSitesFilePath accessLogFilePath\n");
		exit(1);
	}
	if (!isValidPort(argv[1])){
		fprintf(stderr, "Invalid port\n");
		exit(1);
	}
	
	// Start main code
	// Populate the forbidden sites list
	int numSites = NUMSITES;
	int forbSitesIndex = 0;
	forbSites = (char**)malloc(numSites*sizeof(char*));
	FILE *forbSitesFile = fopen(argv[2], "r");
	if (forbSitesFile == NULL) {
      		fprintf(stderr, "Couldn't open forbidden sites file\n");
     		exit(1);
  	}
	
	char buffer[MAXLINE];
	while(fgets(buffer, MAXLINE, forbSitesFile) != NULL){
		if (forbSitesIndex == numSites){
			numSites *= 2;
			char **newSitesBuff = (char**)realloc(forbSites, numSites*sizeof(char*));
			if(newSitesBuff != NULL){
				forbSites = newSitesBuff;
			}
			else{
				fprintf(stderr, "Couldn't reallocate to shrink forbidden sites list\n");
				exit(1);
			}
		}
		forbSites[forbSitesIndex] = strdup(buffer);
		forbSites[forbSitesIndex][strlen(buffer)-1] = '\0'; // Remove the \n
		forbSitesIndex++;
	}
	fclose(forbSitesFile);
	// Resize list once more (shrink to size of elements read in)
	forbSitesLength = forbSitesIndex;
	char **newSitesBuff = (char**)realloc(forbSites, forbSitesLength*sizeof(char*));
	if(newSitesBuff != NULL){
		forbSites = newSitesBuff;
	}
	else{
		fprintf(stderr, "Couldn't reallocate to shrink forbidden sites list\n");
		exit(1);
	}

	// Create socket file descriptor
	int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		fprintf(stderr, "Failed to create socket\n");
		exit(1);
	}

	// Assign IP/Port
	struct sockaddr_in servaddr;
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(atoi(argv[1]));
	
	// Bind socket to the address assigned above
	if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
		fprintf(stderr, "Couldn't bind\n");
		exit(1);
	}

	// Change the socket's state from active (default) to listening
	if (listen(sockfd, 50) < 0){
		fprintf(stderr, "Couldn't listen\n");
		exit(1);
	}

	// Going to loop infinitely in order to accept connections from clients
	struct sockaddr_in cliaddr;
	socklen_t len;
	int connectfd;
	while (1){
		len = sizeof(cliaddr);
		connectfd = accept(sockfd, (struct sockaddr *)&cliaddr, &len);

		if (connectfd < 0){
			fprintf(stderr, "Couldn't accept\n");
			exit(1);
		}
		// Make thread to handle this connection	
		struct threadArgs *args = (struct threadArgs*)malloc(sizeof(struct threadArgs));
		args->accessLogPath = argv[3];
		args->fd = connectfd;

		pthread_t thread;
		if (pthread_create(&thread, NULL, reqHandler, args) < 0){
			fprintf(stderr, "Couldn't create thread\n");
			exit(1);
		}
	}

	// End main (but will never reach here since server is infinite loop)
	close(sockfd);
	for(int i = 0; i < forbSitesLength; i++){
		free(forbSites[i]);
	}
	free(forbSites);
	return 0;	
}
