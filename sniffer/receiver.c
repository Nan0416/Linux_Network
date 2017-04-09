#include <stdio.h>  
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#define PORT 9921
int main(){
	char * receiver_ip = "10.180.28.226";
	struct sockaddr_in receiver;
	receiver.sin_family = AF_INET;
	receiver.sin_addr.s_addr = inet_addr(receiver_ip);
	receiver.sin_port = htons((short)PORT);
	int sock = socket(AF_INET, SOCK_STREAM, 0); // tcp socket
	if(bind(sock, (struct sockaddr *)&receiver, sizeof(struct sockaddr_in)) == -1){
		perror("Error in binding");
		return 1;
	}
	
	listen(sock, 1);
	
	socklen_t len = sizeof(struct sockaddr_in);
	/** in future, implement with stack **/
	struct sockaddr_in addr;
	int client_fd = accept(sock, (struct sockaddr *)&addr, &len);
	printf("Get client\n");
	char x;
	read(client_fd, &x, 1);
	printf("%c\n", x);
	char y  = 'n';
	sleep(2);
	write(client_fd, &y, 1);
	while(1);
	close(client_fd);
	close(sock);
	return 0;
}
