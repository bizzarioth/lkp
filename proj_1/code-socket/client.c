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
	 */
	memset(&serv_addr, '0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	/* [C3: point 1]
	 * Explain following in here.
	 */
	if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	/* [C4: point 1]
	 * Explain following in here.
	 */
	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		printf("\nConnection Failed \n");
		return -1;
	}


	/* [C5: point 1]
	 * Explain following in here.
	 */
	printf("Press any key to continue...\n");
	getchar();

	/* [C6: point 1]
	 * Explain following in here.
	 */
	send(sock , hello , strlen(hello) , 0 );
	printf("Hello message sent\n");

	/* [C7: point 1]
	 * Explain following in here.
	 */
	read( sock , buffer, 1024);
	printf("Message from a server: %s\n",buffer );
	return 0;
}
