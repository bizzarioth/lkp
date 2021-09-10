#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

#define PORT 5984
#define BUFF_SIZE 4096

int main(int argc, const char *argv[])
{
	int server_fd, new_socket;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);
	char buffer[BUFF_SIZE] = {0};
	char *hello = "Hello from server";

	/* [S1: point 1]
	 * Explain following in here.
	 Socket() function creates an unbound socket and returns the file handle to refer and operate on sockets using functions.
	 The snippet checks if the socket was created successfully and exits otherwise.
	 The socket details are:
	 -DOMAIN: Internet domain sockets for use with IPv4 addresses
	 -TYPE: sequenced, reliable, bidirectional, connection-mode byte streams
	 -PROTOCOL: default protocol for given socket type
	 socket() returns -1 code for failing to create the socket
	 The IF Condition checks for a file-handle value of 0, as 0 is open as the stdin of the shell
	 */
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	/* [S2: point 1]
	 * Explain following in here.
	 The function allows the program to control the socket behaviour at different protocol levels.
	 Here the snippet takes effect at the Socket level, as specified by SOL_SOCKET
	 The function here will set 1 (which is stored at location &opt), for Reuse address and ports
	 This allows to avoid address reuse errors
	 The functions returns 0 on failing
	 */
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
		       &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	/* [S3: point 1]
	 * Explain following in here.
	 address is a struct sockaddr_in, here the members are being set up
	 Specificalyy the address and port numbers are being defined
	 */
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons( PORT );

	/* [S4: point 1]
	 * Explain following in here.
	 The bind function attempts to bind the socket to the address and ports specified in the address struct
	 */
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	/* [S5: point 1]
	 * Explain following in here.
	 Puts the socket in a listener mode and waits for client to request a connection
	 The requests get queued in a queue of depth 3
	 */
	if (listen(server_fd, 3) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	/* [S6: point 1]
	 * Explain following in here.
	 This uses the first connection request for the listening socket. A new connection socket is created and the file-handler is returned for it
	 This completes the connection.
	 */
	if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
				 (socklen_t*)&addrlen)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	/* [S7: point 1]
	 * Explain following in here.
	 The program waits for user input
	 Ideally the client is supposed to ping the server or send a message to the server, before continuing
	 */
	printf("Press any key to continue...\n");
	getchar();

	/* [S8: point 1]
	 * Explain following in here.
	 The server reads from client's message from the buffer, at the connection created
	 */
	read( new_socket , buffer, 1024);
	printf("Message from a client: %s\n",buffer );

	/* [S9: point 1]
	 * Explain following in here.
	 The server sends a message to the client using send() command
	 */
	send(new_socket , hello , strlen(hello) , 0 );
	printf("Hello message sent\n");
	return 0;
}
