#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <signal.h>
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

// Global Variables
char *forbSitesFileName;
char **forbSites;
int forbSitesLength;

pthread_mutex_t logMutex;
pthread_mutex_t updateSites;

// Structure used to pass args to threads
struct threadArgs{
	int accessLog; // descriptor access log (output file)
	int fd; // descriptor for the connection received from accept
};

// Returns 1 if string composed of only digits, 0 else
int isNumeric(char* num){
	for (int i = 0; i < num[i] != '\0'; i++){
                if (!isdigit(num[i])){
                        return 0;
		}
	}
	return 1;
}

// Valid ports must be numeric and within the range [1024, 65535]
int isValidPort(char *port){
	if (isNumeric(port)){
        	if (atoi(port) >= 1024 && atoi(port) <= 65535){
        	        return 1;
        	}
	}
	return 0;
}

// Same as isValidPort, except used to verify the web port (so can access reserved ports)
int isValidWebPort(char *port){
	if (isNumeric(port)){
                if (atoi(port) >= 0 && atoi(port) <= 65535){
                        return 1;
                }
        }
        return 0;	
}

void constructForbSites(){
	pthread_mutex_lock(&updateSites);
	int numSites = NUMSITES;
	int forbSitesIndex = 0;
	forbSites = malloc(numSites*sizeof(char*));
	FILE *forbSitesFile = fopen(forbSitesFileName, "r");
	if (forbSitesFile == NULL) {
      		fprintf(stderr, "Couldn't open forbidden sites file\n");
     		exit(1);
  	}
	
	char buffer[MAXLINE];
	while(fgets(buffer, MAXLINE, forbSitesFile) != NULL){
		if (forbSitesIndex == numSites){
			numSites *= 2;
			char **newSitesBuff = realloc(forbSites, numSites*sizeof(char*));
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
	char **newSitesBuff = realloc(forbSites, forbSitesLength*sizeof(char*));
	if(newSitesBuff != NULL){
		forbSites = newSitesBuff;
	}
	else{
		fprintf(stderr, "Couldn't reallocate to shrink forbidden sites list\n");
		exit(1);
	}
	pthread_mutex_unlock(&updateSites);
}

// Checks if a domain name starts with "www." 
// Returns 1 if so, returns 0 otherwise
int hasWWW(char *domainName){
	if (strlen(domainName) <= 4) return 0;
	if(domainName[0] != 'w' && domainName[0] != 'W') return 0;
	if (domainName[1] != 'w' && domainName[1] != 'W') return 0;
	if (domainName[2] != 'w' && domainName[2] != 'W') return 0;	
	if (domainName[3] != '.') return 0;	
	
	return 1;
}

// This function is used to terminate a thread
void terminateThread(struct threadArgs *args){
	close(args->fd); // Close fd that was created for this thread by accept() in main
	free(args); // Free arguments struct allocated for this thread by main
	pthread_exit(NULL);
}

// This function sends HTTP responses to the client
// This is only used when some sort of "error" type response gets sent, like 400, etc.
// Thus the content will always be an http page that just displays the error
// Return value: Length of Content
int sendHttpResponse(int responseCode, char *responseStatus, char *dateHeader, struct threadArgs *args){
	char content[MAXLINE]; 
	sprintf(content, "<!DOCTYPE html>\n"
        "<html>\n"
        "%d %s\n"
        "</html>\n", responseCode, responseStatus);

	char reply[MAXLINE];
	sprintf(reply, "HTTP/1.1 %d %s\r\n"
	"Content-Length: %d\r\n"
	"Content-Type: text/html; charset=UTF-8\r\n"
	"Date: %s\r\n"
	"\r\n"
	"%s", responseCode, responseStatus, strlen(content), dateHeader, content);

	write(args->fd, reply, strlen(reply));

	return strlen(content);
}

// This function is used to record to the access log file
// Called by threads, therefore (if error) should exit using terminateThread function
void logAccess(char *timeOfAccess, char *clientIP, char *requestLine, int responseCode, int contentSize, struct threadArgs *args){
	pthread_mutex_lock(&logMutex);
	char log[MAXLINE];
	sprintf(log, "%s %s %s %d %d\n", timeOfAccess, clientIP, requestLine, responseCode, contentSize);	
	if (write(args->accessLog, log, strlen(log)) < 0){
		fprintf(stderr, "Couldn't write to file for access log\n");
		terminateThread(args);
	}
	pthread_mutex_unlock(&logMutex);
}

void sighandler(int signum){
	for(int i = 0; i < forbSitesLength; i++){
                free(forbSites[i]);
        }
        free(forbSites);
	constructForbSites();
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

	// Get client IP (used later in multiple places)
	struct sockaddr_in cliaddr;
	socklen_t lenCliaddr;
	getsockname(args->fd, (struct sockaddr *)&cliaddr, &lenCliaddr);
	char *clientIp = strdup(inet_ntoa(cliaddr.sin_addr));

	// Setup buffers to read from client
	int bufSize = BUFFSIZE;
 	char buffer[BUFFSIZE];
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
			exit(1);
		}
		
		if (bytesRead + r > bufSize){ // Must reallocate buffer
			bufSize *= 2;
			char *newBuff = (char *)realloc(clientRequest, bufSize*sizeof(char));
			if (newBuff != NULL){
				clientRequest = newBuff;
			}
			else {
				fprintf(stderr, "Couldn't reallocate buffer\n");
				exit(1);
			}
		}

		memcpy(&clientRequest[bytesRead], &buffer, r); // Append buf to msg
		bytesRead+=r;
	}
	clientRequest[bytesRead] = '\0';

	// Parse request in order to create new request to the web server
	char *reserve;
	strtok_r(clientRequest, "\n", &reserve); // Get first line of that field
	char *requestType = strtok_r(clientRequest, " ", &reserve); // GET or HEAD, etc

	char *secondField = strtok_r(NULL, " ", &reserve); 
	char secondRemoveFront[MAXLINE];
	if (strlen(secondField) >= 7){
		memcpy(&secondRemoveFront, &secondField[7], strlen(secondField) - 7); // Shaves off "http://"
		secondRemoveFront[strlen(secondField) - 7] = '\0';
	}
	else{
		secondRemoveFront = "";	
	}
	
	char *domainName = strtok_r(secondRemoveFront, "/", &reserve); // Separates the hostname and port from the path (gets host:port)
	char *docPath = strtok_r(NULL, "/", &reserve); // Gets the path
	if (docPath == NULL){
		docPath = "";
	}
	strtok_r(domainName, ":", &reserve); // Separates the hostname and port
	char *port = strtok_r(NULL, ":", &reserve); // Gets port
	if (port == NULL){ // If no ":" was there to specify a port, assign default port
		port = "443";
	}

	// Next, some validation, with error responses as necessary

	char requestLine[MAXLINE]; // For writing to access log
	sprintf(requestLine, "\"%s /%s HTTP/1.1\"", requestType, docPath);
	
	// If not a GET or HEAD request	
	if (strcmp(requestType, "GET") != 0 && strcmp(requestType, "HEAD") !=0){
		int contentLen = sendHttpResponse(501, "Not Implemented", dateHeader, args);
		logAccess(nowStringMS, clientIp, requestLine, 501, contentLen, args);
		terminateThread(args);
	}
	
	// If one of the parsed fields is NULL, or invalid
	if (domainName == NULL || requestType == NULL || !isValidWebPort(port)){
		int contentLen = sendHttpResponse(400, "Bad Request", dateHeader, args);
		logAccess(nowStringMS, clientIp, requestLine, 400, contentLen, args);
		terminateThread(args);
	}

	// If domain name cannot be resolved
	struct hostent *hostInfo; // First have to get the IP Address from the host name
	if ((hostInfo = gethostbyname(domainName)) == NULL){ 
		fprintf(stderr, "Couldn't resolve IP Address from given domain name\n");
		int contentLen = sendHttpResponse(404, "Not Found", dateHeader, args);
		logAccess(nowStringMS, clientIp, requestLine, 404, contentLen, args);
		terminateThread(args);
	}
	
	// If on forbidden list
	char *ipDottedDecimal = strdup(inet_ntoa(*(struct in_addr *)hostInfo->h_addr)); // Get IP of host name
	char altDomainName[strlen(domainName) + 4]; // Next, check if domainName has "www." in it or not
	if (hasWWW(domainName)){ // If www is there, make alternate domainName without it
		memcpy(&altDomainName, &domainName[4], strlen(domainName) - 4);
		altDomainName[strlen(domainName) - 4] = '\0'; 
	}
	else{ // If www is not there, make alternate domainName with it
		sprintf(altDomainName, "www.%s", domainName);
	}
	pthread_mutex_lock(&updateSites);
	for (int i = 0; i < forbSitesLength; i++){
		if (strcasecmp(forbSites[i], domainName) == 0 || strcasecmp(forbSites[i], ipDottedDecimal) == 0
		    || strcasecmp(forbSites[i], altDomainName) == 0 ){
			int contentLen = sendHttpResponse(403, "Forbidden", dateHeader, args);
			logAccess(nowStringMS, clientIp, requestLine, 403, contentLen, args);
			pthread_mutex_unlock(&updateSites);
           		terminateThread(args);
		}
	}
	pthread_mutex_unlock(&updateSites);	

	// Begin Process of Connecting to Web Server
	
	// Create socket for web server
	int webServerFd; // This will be the socket that will be used to connect to the web server
	if ((webServerFd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		fprintf(stderr, "Couldn't create web server's socket\n");
		exit(1);
	}

	struct sockaddr_in webserver;
	webserver.sin_family = AF_INET;
	webserver.sin_port = htons(atoi(port));
	webserver.sin_addr.s_addr = *(in_addr_t *)hostInfo->h_addr;
	
	if((connect(webServerFd, (struct sockaddr *) &webserver, sizeof(webserver)) < -1)){
		fprintf(stderr, "Couldn't connect socket to web server\n");
		exit(1);
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
		int contentLen = sendHttpResponse(503, "Service Temporarily Unavailable", dateHeader, args);
		logAccess(nowStringMS, clientIp, requestLine, 503, contentLen, args);
		terminateThread(args);
	}

	SSL* ssl;
	if ((ssl = SSL_new(ctx)) == NULL){
		fprintf(stderr, "Couldn't create new ssl\n");
		int contentLen = sendHttpResponse(503, "Service Temporarily Unavailable", dateHeader, args);
		logAccess(nowStringMS, clientIp, requestLine, 503, contentLen, args);
		terminateThread(args);
	}
	if((SSL_set_fd(ssl, webServerFd)) == 0){
		fprintf(stderr, "Couldn't set the fd for ssl\n");
		int contentLen = sendHttpResponse(503, "Service Temporarily Unavailable", dateHeader, args);
		logAccess(nowStringMS, clientIp, requestLine, 503, contentLen, args);
		terminateThread(args);
	}
	if(SSL_connect(ssl) != 1){
		fprintf(stderr, "Couldn't perform handshake for SSL\n");
		int contentLen = sendHttpResponse(503, "Service Temporarily Unavailable", dateHeader, args);
		logAccess(nowStringMS, clientIp, requestLine, 503, contentLen, args);
		terminateThread(args);
	}
	
	// Make request to web server
	char reqToWeb[MAXLINE];
	sprintf(reqToWeb, "%s /%s HTTP/1.1\r\nHost: %s\r\n\r\n", requestType, docPath, domainName);
	if ((SSL_write(ssl, reqToWeb, strlen(reqToWeb))) < 0){
		fprintf(stderr, "Couldn't write to SSL\n");
		int contentLen = sendHttpResponse(503, "Service Temporarily Unavailable", dateHeader, args);
		logAccess(nowStringMS, clientIp, requestLine, 503, contentLen, args);
                terminateThread(args);
	}

	// Read response from web server (reusing some variables used to buffer original request read from client)
	bufSize = BUFFSIZE; // Size of the webResponse's buffer
	bytesRead = 0; // Counter that tracks how many bytes read
	memset(&buffer, 0, sizeof(buffer)); // Resets buffer used earlier to prevent buffer overflow
	
	char *webResponse = (char*)malloc(bufSize*sizeof(char));
	while ((r = SSL_read(ssl, buffer, BUFFSIZE)) > 0){		
		if (bytesRead + r > bufSize){
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
		exit(1);
	}
	
	// Parse response for response code and content length, then log it
	char *responseContent = strstr(webResponse, "\r\n\r\n");
	int contentLength = strlen(responseContent) - 4; // Size of (content + "\r\n\r\n") - "\r\n\r\n"
	if (responseContent == NULL){
		int contentLen = sendHttpResponse(503, "Service Temporarily Unavailable", dateHeader, args);
		logAccess(nowStringMS, clientIp, requestLine, 503, contentLen, args);
		terminateThread(args);
	}
	
	strtok_r(webResponse, " ", &reserve); // get rid of the HTTP\1.1
	char *responseCode = strtok_r(NULL, " ", &reserve); // get the status code
	if (responseCode == NULL){
		int contentLen = sendHttpResponse(503, "Service Temporarily Unavailable", dateHeader, args);
		logAccess(nowStringMS, clientIp, requestLine, 503, contentLen, args);
		terminateThread(args);
	}

	logAccess(nowStringMS, clientIp, requestLine, atoi(responseCode), contentLength, args);

	// End program
	free(webResponse);
	free(clientRequest);
	free(ipDottedDecimal);
	free(clientIp);
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
	forbSitesFileName = argv[2];
	if(pthread_mutex_init(&updateSites, NULL)){
		fprintf(stderr, "Couldn't initialize mutex for forbidden-site updates\n");
		exit(1);
	}
	constructForbSites();	

	// Redirect termination signal to sighandler function
	signal(SIGINT, sighandler);

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
	int connectfd;
	if(pthread_mutex_init(&logMutex, NULL) != 0){
		fprintf(stderr, "Couldn't initialize log mutex\n");
		exit(1);
	}
	
	struct sockaddr_in cliaddr;
	socklen_t len;
	int accessLog;
	if ((accessLog = open(argv[3],  O_WRONLY | O_APPEND | O_CREAT, 0666)) < 0){
		fprintf(stderr , "Failed to open access log\n");
		exit(1);
	}
	while (1){
		len = sizeof(cliaddr);
		connectfd = accept(sockfd, (struct sockaddr *)&cliaddr, &len);

		if (connectfd < 0){
			fprintf(stderr, "Couldn't accept\n");
			exit(1);
		}
		// Make thread to handle this connection	
		struct threadArgs *args = (struct threadArgs*)malloc(sizeof(struct threadArgs));
		args->accessLog = accessLog;
		args->fd = connectfd;
		pthread_t thread;
		if (pthread_create(&thread, NULL, reqHandler, args) < 0){
			fprintf(stderr, "Couldn't create thread\n");
			exit(1);
		}
	}

	// End main (but will never reach here since server is infinite loop)
	close(sockfd);
	close(accessLog);
	pthread_mutex_destroy(&logMutex);
	pthread_mutex_destroy(&updateSites);
	for(int i = 0; i < forbSitesLength; i++){
		free(forbSites[i]);
	}
	free(forbSites);
	return 0;	
}
