#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/select.h>
#include <errno.h>
#define PORT 9921
#define MAX_SELECT 30
typedef struct sniff_ip{
	struct sockaddr_in receiver;
	int sock;
}sniff_ip; 
typedef struct ip_num{
	unsigned char x1;
	unsigned char x2;
	unsigned char x3;
	unsigned char x4;
	
}ip_num;
void generate_ip_chars(unsigned char x1,unsigned char x2, unsigned char x3, unsigned char x4, char * rs);
int sniff(const ip_num * start, const ip_num * end);


void address_num_increment(ip_num * addr);
int compare(const ip_num * small, const ip_num * big);
void print_ip(int ip);
void convert_ip_string_ip_num(char * ip, ip_num *n_ip);


//pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

int main(){
	char * start_c = "10.180.28.100";
	char * end_c = "10.180.28.250";
	
	
	ip_num start;
	ip_num end;
	convert_ip_string_ip_num(start_c, &start);
	convert_ip_string_ip_num(end_c, &end);
	//printf("%d", start.x2);
	int receiver_fd = sniff(&start, &end);
	if(receiver_fd != -1){
		char x = 'q';
		write(receiver_fd, &x, 1);
		read(receiver_fd, &x, 1);
		printf("%c\n", x);
	}
	return 0;
	
}
void generate_ip_chars(unsigned char x1,unsigned char x2, unsigned char x3, unsigned char x4, char * rs){
	char s[4];
	int i = 0;
	int j = 0;
	sprintf(s, "%d", x1);
	for(j = 0; j < strlen(s); j++){
		rs[i] = s[j];
		i++;
	}
	rs[i] = '.';
	i++;
	
	sprintf(s, "%d", x2);
	for(j = 0; j < strlen(s); j++){
		rs[i] = s[j];
		i++;
	}
	rs[i] = '.';
	i++;
	
	sprintf(s, "%d", x3);
	for(j = 0; j < strlen(s); j++){
		rs[i] = s[j];
		i++;
	}
	rs[i] = '.';
	i++;
	
	sprintf(s, "%d", x4);
	for(j = 0; j < strlen(s); j++){
		rs[i] = s[j];
		i++;
	}
	rs[i] = '\0';
	return;
	
}





void address_num_increment(ip_num * addr){
	addr->x4 += 1;
	if(addr->x4 == 0){
		//overflow
		addr->x3 += 1;
	}
	if(addr->x3 == 0){
		addr->x2 += 1;
	}
	if(addr->x2 == 0){
		addr->x1 += 1;
	}
	
}
int compare(const ip_num * small, const ip_num * big){
	if(small->x1 > big->x1){
		return -1;
	}
	if(small->x1 == big->x1 && small->x2 > big->x2){
		return -1;
	}
	if(small->x1 == big->x1 && small->x2 == big->x2 && small->x3 > big->x3){
		return -1;
	}
	if(small->x1 == big->x1 && small->x2 == big->x2 && small->x3 == big->x3 && small->x4 > big->x4){
		return -1;
	}
	if(small->x1 == big->x1 && small->x2 == big->x2 && small->x3 == big->x3 && small->x4 == big->x4){
		return 0;
	}
	return 1;
}
void print_ip(int ip){
	unsigned char * x = (unsigned char *)&ip;
	printf("%d.%d.%d.%d\n", x[0],x[1], x[2], x[3]);
}

void convert_ip_string_ip_num(char * ip, ip_num *n_ip){
	int addr = inet_addr(ip);
	unsigned char * x = (unsigned char *)&addr;
	n_ip->x1 = x[0];
	n_ip->x2 = x[1];
	n_ip->x3 = x[2];
	n_ip->x4 = x[3];
	
}
/*
static int testing(){
	int sock1 = socket(AF_INET, SOCK_STREAM, 0);
	int sock2 = socket(AF_INET, SOCK_STREAM, 0);
	
	fcntl(sock1, F_SETFL,  O_NONBLOCK);	
	fcntl(sock2, F_SETFL, O_NONBLOCK);	
	
	char * ip1 = "10.180.28.226";
	char * ip2 = "10.180.28.227";
	
	struct sockaddr_in addr1;
	struct sockaddr_in addr2;
	
	addr1.sin_addr.s_addr = inet_addr(ip1);
	addr1.sin_port = htons((short)PORT);
	addr1.sin_family = AF_INET;
	
	addr2.sin_addr.s_addr = inet_addr(ip2);
	addr2.sin_port = htons((short)PORT);
	addr2.sin_family = AF_INET;
	
	if(connect(sock1, (struct sockaddr *)&(addr1), sizeof(struct sockaddr_in)) == -1 ){
		if(errno != EINPROGRESS){
			perror("Error in connect");
		}
	}
	
	if(connect(sock2, (struct sockaddr *)&(addr2), sizeof(struct sockaddr_in)) == -1 ){
		if(errno != EINPROGRESS){
			perror("Error in connect");
		}
	}
	
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(sock1, &fds);
	FD_SET(sock2, &fds);
	
	int max = (sock1 > sock2) ?sock1: sock2;
	
	struct timeval tm;
	tm.tv_sec = 10;
	tm.tv_usec = 0;
	int num = select(max + 1, NULL, &fds, NULL, &tm);
	//** select will return if there is a socket has been determined 
	//** determined means if connection exist, no route to the server also lets select return 
	printf("num %d\n", num);
	int error;
	int len = sizeof(int);
	if(FD_ISSET(sock1, &fds)){
		printf("sock1 determined\n");
		getsockopt(sock1, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len);
		if(error != 0){
			printf(" sock1 failed\n");
		}
	}
	if(FD_ISSET(sock2, &fds)){
		printf("sock2 determined\n");
		getsockopt(sock2, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len);
		if(error != 0){
			printf(" sock2 failed\n");
		}
	}
	
	return 1;
	
}*/
	

int sniff(const ip_num * start, const ip_num * end){
	ip_num fun_local = *start;
	char receiver_ip[16];
	sniff_ip sip[MAX_SELECT];
	int flags[MAX_SELECT];
	fd_set writefds;
	
	while(compare(&fun_local, end) > 0){
		FD_ZERO(&writefds);
		int i = 0;
		
		int max_fd = -1;
		for(; i < MAX_SELECT; i++){
			if(compare(&fun_local, end) > 0){
				generate_ip_chars(fun_local.x1,fun_local.x2, fun_local.x3, fun_local.x4, receiver_ip);	
				sip[i].sock = socket(AF_INET, SOCK_STREAM, 0);
				flags[i] = fcntl(sip[i].sock, F_GETFL);
				fcntl(sip[i].sock, F_SETFL, O_NONBLOCK);	
				sip[i].receiver.sin_addr.s_addr = inet_addr(receiver_ip);
				sip[i].receiver.sin_port = htons((short)PORT);
				sip[i].receiver.sin_family = AF_INET;
				if(connect(sip[i].sock, (struct sockaddr *)&(sip[i].receiver), sizeof(struct sockaddr_in)) == -1 ){
					if(errno != EINPROGRESS){
						perror("Error in connect");
					}
				}
				FD_SET(sip[i].sock, &writefds);
				if(max_fd < sip[i].sock){
					max_fd = sip[i].sock;
				}
				address_num_increment(&fun_local);
			}
		}

		struct timeval tm;
		tm.tv_sec = 1;
	/****/
		tm.tv_usec = 0;
	
		int num;
	
		if((num = select(max_fd + 1, NULL, &writefds, NULL, &tm)) > 0){
			i = 0;
			for(; i < MAX_SELECT; i++){
				
				if(FD_ISSET(sip[i].sock, &writefds)){
					
					int error;
					int len = sizeof(int);
					getsockopt(sip[i].sock, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len);
					if(error != 0){
						printf("Group member found error.\n");
						int fd_index = 0;
						for(; fd_index < MAX_SELECT; fd_index++){
							
							if(close(sip[fd_index].sock) == -1){
								perror("Error in close");
							}
						}
						break;
						
					}else{
						int fd_index = 0;
						for(; fd_index < MAX_SELECT; fd_index++){
							if(i != fd_index){
								if(close(sip[fd_index].sock) == -1){
									perror("Error in close");
								}
							}
						}
						fcntl(sip[i].sock, F_SETFL, flags[i]);
						printf("Target found:\n");
						print_ip(sip[i].receiver.sin_addr.s_addr);
						return sip[i].sock;
					}
				}
			}
		}else{
			printf("Group time out.\n");
		}
		
	}
	printf("no connection available.\n");
	return -1;
	
}
	

