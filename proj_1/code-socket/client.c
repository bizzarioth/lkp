#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

#define PORT 5984
#define BUFF_SIZE 4096

int main(int argc, const char *argv[])
{
	int sock = 0;
	struct sockaddr_in serv_addr;
	char *hello = "Hello from client";
	char buffer[BUFF_SIZE] = {0};

	/* [C1: point 1]
	 * Explain following in here.
	 Socket() function creates an unbound socket and returns the file descriptor to refer and operate on sockets using functions.
	 The snippet checks if the socket was created successfully and exits otherwise.
	 The socket details are:
	 -DOMAIN: Internet domain sockets for use with IPv4 addresses
	 -TYPE: sequenced, reliable, bidirectional, connection-mode byte streams
	 -PROTOCOL: default protocol for given socket type
	 socket() returns -1 code for failing to create the socket, hence it is tested for negative value
	 */
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Socket creation error \n");
		return -1;
	}

	/* [C2: point 1]
	 * Explain following in here.
	 This avoids junk values at creation by allocating static storage. It initiates with 0 values
	 */
	memset(&serv_addr, '0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	/* [C3: point 1]
	 * Explain following in here.
	 The ip adress is being hardcoded and passed to AF_INET protocol and passed along the serv_addr struct.

	 */
	if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	/* [C4: point 1]
	 * Explain following in here.
	 Connect requests the connection to the server sockets.
	 0 is returned for a success
	 */
	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		printf("\nConnection Failed \n");
		return -1;
	}


	/* [C5: point 1]
	 * Explain following in here.
	 The program waits for user input
	 Ideally the client is supposed to ping the server or send a message to the server, before continuing
	 */
	printf("Press any key to continue...\n");
	getchar();

	/* [C6: point 1]
	 * Explain following in here.
	 send() transmits the mesage to socket
	 */
	send(sock , hello , strlen(hello) , 0 );
	printf("Hello message sent\n");

	/* [C7: point 1]
	 * Explain following in here.
	 read() dunction reads from the socket file descriptor into buffer
	 */
	read( sock , buffer, 1024);
	printf("Message from a server: %s\n",buffer );
	return 0;
}
