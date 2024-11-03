// cpp_proxy_server_console.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
// http://localhost:8080/https://www.example.com/

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "proxy_parse.h"
#include <iostream>

#include <time.h>

#include <sys/types.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <io.h>
#include <direct.h>

#include <fcntl.h>

#include <errno.h>
#include <time.h>
#include <Windows.h>

//This line instructs the linker to link against Ws2_32.lib directly in your code, 
// which is useful if you're not adding it manually in the project properties.
#pragma comment(lib, "Ws2_32.lib")  // Link with Ws2_32.lib

#define MAX_CLIENTS			1
#define MAX_BYTES			4096
#define MAX_ELEMENT_SIZE	10*(1<<20)
#define MAX_SIZE			200*(1<<20)

struct  cache_element
{
	char*			data;
	int				len;
	char*			url;
	time_t			lru_time_track;
	cache_element*	next;
};

cache_element*  find					(char* url);
int				add_cache_element		(char* data, int size,const char* url);
void			remove_cache_element	();

int			PORT			= 8080;
SOCKET		proxy_socket_id;
HANDLE		tid[MAX_CLIENTS];	//stores thread id, this is nothing but array of threads
HANDLE		semaphore_lock;		//used to limit the thread creation (this will be a counting sem)
HANDLE		mutex_lock;			//used to maintain cuncarency in the LRU cache

cache_element*	head;
int				cache_size;

int checkHTTPversion(char* msg)
{
	int version = -1;

	if (strncmp(msg, "HTTP/1.1", 8) == 0)
	{
		version = 1;
	}
	else if (strncmp(msg, "HTTP/1.0", 8) == 0)
	{
		version = 1;										// Handling this similar to version 1.1
	}
	else
		version = -1;

	return version;
}

int sendErrorMessage(int socket, int status_code)
{
		char	str[1024];
		char	currentTime[50];
		time_t	now;

	time(&now);

		struct tm	data;
		errno_t		err = gmtime_s(&data, &now);

	strftime(currentTime, sizeof(currentTime), "%a, %d %b %Y %H:%M:%S %Z", &data);

	switch (status_code)
	{
	case 400: snprintf(str, sizeof(str), "HTTP/1.1 400 Bad Request\r\nContent-Length: 95\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>400 Bad Request</TITLE></HEAD>\n<BODY><H1>400 Bad Rqeuest</H1>\n</BODY></HTML>", currentTime);
		printf("400 Bad ~ Request\n");
		send(socket, str, strlen(str), 0);
		break;

	case 403: snprintf(str, sizeof(str), "HTTP/1.1 403 Forbidden\r\nContent-Length: 112\r\nContent-Type: text/html\r\nConnection: keep-alive\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>403 Forbidden</TITLE></HEAD>\n<BODY><H1>403 Forbidden</H1><br>Permission Denied\n</BODY></HTML>", currentTime);
		printf("403 Forbidden\n");
		send(socket, str, strlen(str), 0);
		break;

	case 404: snprintf(str, sizeof(str), "HTTP/1.1 404 Not Found\r\nContent-Length: 91\r\nContent-Type: text/html\r\nConnection: keep-alive\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD>\n<BODY><H1>404 Not Found</H1>\n</BODY></HTML>", currentTime);
		printf("404 Not Found\n");
		send(socket, str, strlen(str), 0);
		break;

	case 500: snprintf(str, sizeof(str), "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 115\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>500 Internal Server Error</TITLE></HEAD>\n<BODY><H1>500 Internal Server Error</H1>\n</BODY></HTML>", currentTime);
		//printf("500 Internal Server Error\n");
		send(socket, str, strlen(str), 0);
		break;

	case 501: snprintf(str, sizeof(str), "HTTP/1.1 501 Not Implemented\r\nContent-Length: 103\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>404 Not Implemented</TITLE></HEAD>\n<BODY><H1>501 Not Implemented</H1>\n</BODY></HTML>", currentTime);
		printf("501 Not Implemented\n");
		send(socket, str, strlen(str), 0);
		break;

	case 505: snprintf(str, sizeof(str), "HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: 125\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>505 HTTP Version Not Supported</TITLE></HEAD>\n<BODY><H1>505 HTTP Version Not Supported</H1>\n</BODY></HTML>", currentTime);
		printf("505 HTTP Version Not Supported\n");
		send(socket, str, strlen(str), 0);
		break;

	default:  return -1;

	}
	return 1;
}

/*
	Socket communication with remote port happens here.
*/
int connectRemoteServer(char * host_addr,int server_port) {

	// Now need to open socket to communicate with remote port
	
		const char*		service		= "80";
		struct addrinfo hints, * host;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family		= AF_INET; // AF_INET or AF_INET6 to specify address family
	hints.ai_socktype	= SOCK_STREAM; // TCP stream sockets

	getaddrinfo(host_addr, service, &hints, &host);

	if (!host) {

		perror("No such Host exist\n");
		return -1;
	}

		int remoteSocket = socket(host->ai_family, host->ai_socktype, host->ai_protocol);

	if (remoteSocket < 0) {

		printf("Remote soket creation failed\n");
		return -1;
	}

	if (connect(remoteSocket, host->ai_addr, (int) host->ai_addrlen) == SOCKET_ERROR) {

		perror("Error in connecting\n");
		return -1;
	}

	return remoteSocket;
}

/*
	tempReq : is the data received from client from "recv" function (url)
	this function fetches the data from the remote by establishing connection to the HTTP
*/
int handle_request(int clientSocketId, ParsedRequest * request, char * temReq) {
	
		char* buf				= (char*)calloc(MAX_BYTES, sizeof(char));
		std::string httpRequest = "";

	httpRequest = "GET " + std::string(request->path) + " " + std::string(request->version)+ "\r\n";
	httpRequest += "Host: " + std::string(request->host) + "\r\n";
	httpRequest += "Connection: close\r\n";
	httpRequest += "\r\n";

		int server_port = 80; //http reuest usually is done at port '80'

	if (request->port != NULL) {

		server_port = atoi(request->port);
	}
		
	printf("%s\n", httpRequest.c_str());

		int remoteSocketId = connectRemoteServer(request->host, server_port);

	if (remoteSocketId < 0)
		return -1;

		int bytes_send = send(remoteSocketId, httpRequest.c_str(), (int)httpRequest.length(), 0);

	ZeroMemory(buf, MAX_BYTES);

		int bytes_recv = recv(remoteSocketId, buf, MAX_BYTES - 1, 0);

		char*	temp_buffer			= (char*)malloc(sizeof(char) * MAX_BYTES);
		int		temp_buffer_size	= MAX_BYTES;
		int		temp_buffer_index	= 0;

	while (bytes_recv > 0) {

		bytes_recv = send(clientSocketId, buf, bytes_recv, 0);

		for (int i = 0; i < (bytes_recv / sizeof(char)); i++) {

			temp_buffer[temp_buffer_index] = buf[i];
			// printf("%c",buf[i]); // Response Printing
			temp_buffer_index++;

		}

		temp_buffer_size += MAX_BYTES;
		temp_buffer = (char*)realloc(temp_buffer, temp_buffer_size);

		if (bytes_recv < 0) {

			perror("Error in sending data to the client\n");
			break;
		}

		ZeroMemory(buf, MAX_BYTES);
		bytes_recv = recv(remoteSocketId, buf, MAX_BYTES, 0);
	}
	
	const char* cString = httpRequest.c_str();
	char* temp_link = (char *) calloc (strlen(cString), sizeof(char));

	memcpy(temp_link, cString, httpRequest.size());

	temp_buffer[temp_buffer_index] = '\0';
	free(buf);
	buf = NULL;
	add_cache_element(temp_buffer, strlen(temp_buffer), temp_link);
	free(temp_buffer);
	temp_buffer = NULL;
	closesocket(remoteSocketId);
	return 0;

}

DWORD WINAPI thread_fn (void * socketNew) {

	WaitForSingleObject(&semaphore_lock, INFINITE);
	printf("New thread is triggered\n");

	int* t = (int*)socketNew;
	int socket = *t;
	int bytes_send_client, len;

	char* buffer = (char*)calloc(MAX_BYTES, sizeof(char));

	if (!buffer) {

		perror("Memory aloc failed\n");
		exit(1);
	}
	
	ZeroMemory(buffer, MAX_BYTES);
	//memset(buffer, 0, MAX_BYTES);

	/*
		-	The recv() function is commonly used with sockets to receive data from a connected socket.
			recv() is a blocking call by default, which means it will wait until data is received.

		Parameter :

			@param param1 : The socket descriptor. This is an integer that uniquely identifies the socket.
			@param param2 : A pointer to the buffer where the received data should be stored.
			@param param3 : The length (in bytes) of the buffer, specifying the maximum amount of data to receive.
			@param param4 : Modifiers that control the behavior of the function. Common flags include:
					- 0:			No specific flag; basic receive operation.
					- MSG_DONTWAIT: Non-blocking receive.
					- MSG_PEEK:		Peek at the incoming message without removing it from the queue.
					- MSG_WAITALL:	Wait until the full request is received.

		Return value of recv() : 
		- On success, recv() returns the number of bytes received.
		- On error, it returns -1, and errno is set to indicate the error.
		- If the connection is closed, it returns 0.
	*/

	bytes_send_client = recv(socket, buffer, MAX_BYTES, 0);

	while (bytes_send_client > 0) {

		len = strlen(buffer);

		if (strstr(buffer, "\r\n\r\n") == NULL) {

			bytes_send_client = recv(socket, buffer + len, MAX_BYTES-len, 0);

		} else {

			break;
		}
	}

	char* temp_Req = (char*)malloc(strlen(buffer) * sizeof(char));

	ZeroMemory(temp_Req, sizeof(temp_Req));

	if (!temp_Req) {

		perror("Memory aloc failed\n");
		exit(1);
	}

	for (int i = 0; i < strlen(buffer); i++) {

		temp_Req[i] = buffer[i];
	}

	struct cache_element* temp = NULL;
	temp = find(temp_Req);

	if (temp) {

		int sz = temp->len / sizeof(char);
		int pos = 0;
		char response[MAX_BYTES];

		while (pos < sz) {

			ZeroMemory(response, MAX_BYTES);

			for (int i = 0; i < MAX_BYTES; i++) {

				response[i] = temp->data[i];
				pos++;
			}

			/*
				-	The send() function in C++ networking is used to transmit data over a connected socket
				-	If the message size exceeds the underlying buffer size, send() might not send the full 
					message in one call. In this case, you may need to implement a loop to send remaining data.
				-	This function is essential for sending data in TCP socket programming in C++.

				Parameter:

					@param param1: The socket descriptor representing the connection (created with socket() and connected with connect()).
					@param param2: Pointer to the data you want to send.
					@param param3: Size of the data in bytes.
					@param param4: Additional options (usually 0 for default behavior).

				RETURN VALUE :
				- On success, send() returns the number of bytes actually sent. On error, it returns -1, and errno 
					is set to indicate the error.
			*/
			send(socket, response, MAX_BYTES, 0);

			printf("Data retrieved from the cache\n");
			printf("response : %s\n\n", response);
		}

	} else if (bytes_send_client > 0) {
		
			ParsedRequest* request = ParsedRequest_create();
		
		len = (int)strlen(buffer);

		if (ParsedRequest_parse(request, buffer, len) < 0) {

			printf("parsing failed \n");
			shutdown(socket, SD_BOTH);
			closesocket(socket);
			free(buffer);
			buffer = NULL;
			ReleaseSemaphore(semaphore_lock, 1, NULL);

			printf("Threading ending, Semaphore close\n");
			return 0;

		} else {
			
			ZeroMemory(buffer, MAX_BYTES);
			if (!strcmp(request->method, "GET")) {
				
				if (request->host && request->path && checkHTTPversion(request->version) == 1) {

					//temp_req is the data received from client using "recv()" function
					bytes_send_client = handle_request (socket, request, temp_Req);

					if (bytes_send_client == -1) {

						sendErrorMessage(socket, 500);
					}

				} else {

					sendErrorMessage(socket, 500);
				}
			}
			else {

				printf("This system doesn't support any other request part from 'GET' \n");
			}
		}

		//ParsedRequest_destroy(request);

	} else if (bytes_send_client == 0) {
		
		printf("client is disconnected\n");
	}

	shutdown(socket, SD_BOTH);
	closesocket(socket);
	free(buffer);
	buffer = NULL;
	
	ReleaseSemaphore(semaphore_lock, 1, NULL);

	printf("Threading ending, Semaphore close\n");

	return 0;
}

int main(int argv, char* argc[])
{
		int			client_socketId; 
		int			client_len; //client_id : opens up port for the client, who wants to establish connection with the proxy
		sockaddr_in server_addr, client_addr; // Address of client and server to be assigned
		WSADATA		wsaData;
		int			result;

	// Initialize Winsock
	result = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (result != 0) {

		printf("WSAStartup failed: %d\n", result);
		exit(1);
	}


	semaphore_lock	= CreateSemaphore	(NULL, 1, MAX_CLIENTS, NULL);
	mutex_lock		= CreateMutex		(NULL, FALSE, NULL);

	if (argv == 2) {

		PORT = atoi(argc[1]);
	}

	printf("Starting proxy server at PORT : %d\n", PORT);


	/*
		AF_INET : indicated IPV4 addressing
		SOCK_STREAM : indicates TCP connection (SOCK_DGRAM for UDP)
	*/
	proxy_socket_id = socket(AF_INET, SOCK_STREAM, 0);

	if (proxy_socket_id < 0) {

		perror("Failed to create socket\n");
		exit(1);
	}

	int reuse = 1;

	//configuring socket
	if (setsockopt(
		proxy_socket_id,
		SOL_SOCKET,
		SO_REUSEADDR,	//Allows the socket to bind to an address that is already in use.
		(const char*)&reuse,
		sizeof(reuse)) < 0) {

		perror("setSockOpt failed\n");

	}

	memset(&server_addr, 0, sizeof(server_addr)); ////ZeroMemory()

	server_addr.sin_family		= AF_INET; //ipv4
	server_addr.sin_port		= htons(PORT); //converts from host byte order to network byte order
	server_addr.sin_addr.s_addr = INADDR_ANY; //TODO : tobe fixed 

	// Binds the socket to a specific IP address and port number.
	// This way, the system knows that any traffic destined for that IP/port should be handled by this socket.
	if (bind(proxy_socket_id, (sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
		
		perror("port not available");
		exit(1);
	}

	printf("Binding on port %d\n", PORT);

		// puts the server in a mode where it waits for incoming client connections.
		int listenstatus = listen(proxy_socket_id, MAX_CLIENTS);

	if (listenstatus < 0) {

		perror("Error in listening\n");
		exit(1);
	}

		int i = 0;
		int connected_socket_id[MAX_CLIENTS];

	while (1) {

		ZeroMemory((void *)& client_addr, sizeof(client_addr));
		client_len = sizeof(client_addr);
		//	- Accepts a connection request from a client.
		//	- Each time accept() is called, it removes the first pending connection request from the queue, 
		//	  creates a new socket for that connection, and returns it to the server to use for communication with that specific client.
		//	- Creates a new socket for each client, allowing the server to interact with multiple clients while keeping 
		//	  the main listening socket open for further connections.
		client_socketId = accept(proxy_socket_id,(struct sockaddr *) & client_addr, (socklen_t*)&client_len);

		if (client_socketId < 0) {

			perror("client connection failed\n");
			exit(1);

		} else {
			
			connected_socket_id[i] = client_socketId;
		}

			struct sockaddr_in* client_pt	= (struct sockaddr_in*)&client_addr;
			struct in_addr		ip_addr		= client_pt->sin_addr;
			char				str[INET_ADDRSTRLEN];

		//The inet_ntop() function is used in network programming to convert an IP address from its binary format (used internally in 
		// network functions) to a human-readable text format (like "192.168.1.1" for IPv4 or "2001:0db8::1" for IPv6).
		inet_ntop(AF_INET, &ip_addr, str, INET_ADDRSTRLEN);

		printf("Client is connected with port number %d and ip address is %s\n", ntohs(client_addr.sin_port), str);

		tid[i] = CreateThread(
			NULL,
			2 * 1024 * 1024,
			thread_fn,
			(void*)&connected_socket_id[i],
			0,
			NULL
		);

		i++;

		closesocket(client_socketId);

	}


	closesocket(proxy_socket_id);
	WSACleanup();
	return 0;
}

/*
	Checks for url in the cache if found returns pointer to the respective cache element or else returns NULL
*/

cache_element* find(char* url) {

		cache_element*	site = NULL;
		int				temp_lock_val = WaitForSingleObject(mutex_lock, INFINITE);

	printf("Cache lock status : %d\n", temp_lock_val);

	if (head != NULL) {

		site = head;

		while (site != NULL) {

			if (strcmp(site->url, url) == 0) {

				printf("LRU time track before : %ld\n", (long)site->lru_time_track);
				printf("\n URL found! :) \n");
				site->lru_time_track = time(NULL);
				printf("LRU time track after : %ld\n", (long)site->lru_time_track);
				break;
			}
			site = site->next;
		}
	} else {
		
		printf("URL NOt found :( \n");
	}

	temp_lock_val = ReleaseMutex(mutex_lock);
	printf("Lock is removed \n");
	return site;
}

void remove_cache_element() {

		cache_element* prev;
		cache_element* nxt;
		cache_element* cur;
		
		int	temp_lock_val = WaitForSingleObject(mutex_lock, INFINITE);

	printf("Cache lock status : %d\n", temp_lock_val);

	if (head != NULL) {

		cur = head;
		nxt = head;
		prev = NULL;

		while (cur->next) {

			nxt = cur->next;

			if (cur->lru_time_track > nxt->lru_time_track) {

				prev = cur->next;
				cur = nxt;

			} else {
				
				if (prev)
					prev->next = nxt;
				else
					head = nxt;

				cur->next = NULL;

				cache_size -= (cur->len + (int)sizeof(cache_element) + (int)strlen(cur->url) + 1);
				free(cur->data);
				cur->data = NULL;
				free(cur->url);
				cur->url = NULL;
				free(cur);
				cur = NULL;
				break;
			}

		}
	}

	temp_lock_val = ReleaseMutex(mutex_lock);
	printf("Lock is removed \n");
	return;
}

int add_cache_element(char * data, int size, const char * url) {

		int	temp_lock_val = WaitForSingleObject(mutex_lock, INFINITE);

	printf("Cache lock status : %d\n", temp_lock_val);

	int element_size = size + 1 + ((int)strlen(url)) + ((int)sizeof(cache_element));

	if (element_size > MAX_ELEMENT_SIZE) {

		temp_lock_val = ReleaseMutex(mutex_lock);
		printf("Add cache lock is unlocked\n");
		return 0;

	} else {
		
		while (cache_size + element_size > MAX_SIZE) {

			remove_cache_element();
		}

		cache_element* element = (cache_element*)malloc(sizeof(cache_element));
		element->data = (char*)malloc(sizeof(size + 1));
		strcpy(element->data, data);
		element->url = (char*)malloc(sizeof(1 + (strlen(url) * sizeof(char))));
		strcpy(element->url, url);
		element->lru_time_track = time(NULL);
		element->next = head;
		element->len = size;
		head = element;
		cache_size += element_size;
		temp_lock_val = ReleaseMutex(mutex_lock);
		printf("Lock is removed \n");
		return 1;
	}

	return 0;
}