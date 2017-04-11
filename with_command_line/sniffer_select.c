#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/select.h>
#include <errno.h>
#include "sniffer_select.h"
#include "cpair_port.h"
#include "transceiver.h"

//temp
#define MAX_SELECT 100
#define PORT 9416
#define SNIFF_TIMEOUT 2
static char * config_file = "./config_cpair";
static response request(int server_fd, request_type rt){
	
	write(server_fd, &rt, sizeof(request_type));
	response rs;
	read(server_fd, &rs, sizeof(response));
	return rs;
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
void reverse_inet_addr(int addr, char * ip){
	unsigned char * x = (unsigned char *)&addr;
	sprintf(ip, "%u.", x[0]);
	int i = 0;
	for(; ip[i] != '\0'; i++){
		
	}
	sprintf(ip+i, "%u.", x[1]);
	for(; ip[i] != '\0'; i++){
		
	}
	sprintf(ip+i, "%u.", x[2]);
	for(; ip[i] != '\0'; i++){
		
	}
	sprintf(ip+i, "%u", x[3]);
	
}
void convert_ip_string_ip_num(char * ip, ip_num *n_ip){
	int addr = inet_addr(ip);
	unsigned char * x = (unsigned char *)&addr;
	n_ip->x1 = x[0];
	n_ip->x2 = x[1];
	n_ip->x3 = x[2];
	n_ip->x4 = x[3];
	
}

_config return_port(void){
	FILE * fp =  fopen(config_file, "r");
	_config fig;
	if(fp != NULL){
		char buffer[32];
		char * port_ = "PORT";
		char * max_ = "MAX";
		size_t len = 32;
		ssize_t nread;
		int port = 0;
		int max = 0;
		char num[6];
		int i = 0;
		while ((nread = getline((char **)&buffer, &len, fp)) != -1) {
			if( strncmp(buffer, port_, 4) == 0){
				for(i  = 5; i < 11; i++){
					if(buffer[i] <= '9' && buffer[i] >= '0'){
						num[i-5] = buffer[i];
					}else{
						num[i-5] = '\0';
						break;
					}
				}
				port = atoi(num);
			}else if(strncmp(buffer, max_, 3) == 0){
			
				for(i  = 4; i < 10; i++){
					if(buffer[i] <= '9' && buffer[i] >= '0'){
						num[i-4] = buffer[i];
					}else{
						num[i-4] = '\0';
						break;
					}
				}
				max = atoi(num);
			}
        }
		if(max == 0 && port == 0){
			fig.max_select = _MAX_SELECT__;
			fig.port = _CPAIR_PORT__;
			return fig;
		}else if(max != 0 && port == 0){
			fig.max_select = max;
			fig.port = _CPAIR_PORT__;
			return fig;
		}
		else if(max == 0 && port != 0){
			fig.max_select = _MAX_SELECT__;
			fig.port = port;
			return fig;
		}else{
			fig.max_select =max;
			fig.port = port;
			return fig;
		}
		
	}
	fig.max_select = _MAX_SELECT__;
	fig.port = _CPAIR_PORT__;
	return fig;
	
	
}

int sniff(const ip_num * start, const ip_num * end, char * receiver_ip){
	ip_num fun_local = *start;
	//char receiver_ip[16];
	sniff_ip sip[MAX_SELECT];
	int flags[MAX_SELECT];
	int usedfd[MAX_SELECT];
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
				usedfd[i] = 1;
				address_num_increment(&fun_local);
				
			}
		}

		struct timeval tm;
		tm.tv_sec = SNIFF_TIMEOUT;
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
							
							if(usedfd[fd_index] == 1 && close(sip[fd_index].sock) == -1){
								perror("Error in close");
							}
							usedfd[fd_index] = 0;
						}
						break;
						
					}else{
						int fd_index = 0;
						for(; fd_index < MAX_SELECT; fd_index++){
							if(i != fd_index && usedfd[fd_index] == 1 && close(sip[fd_index].sock) == -1){

								perror("Error in close");
								
							}
						}
						fcntl(sip[i].sock, F_SETFL, flags[i]);
						printf("Target found:\n");
						print_ip(sip[i].receiver.sin_addr.s_addr);
						reverse_inet_addr(sip[i].receiver.sin_addr.s_addr, receiver_ip);
						request_type rt = SNIFF_TRY_CLOSE;
						response rp  = request(sip[i].sock, rt);
						if(rp.code != PERMIT){
							fprintf(stderr, "Sniff request failed.\n");
							close(sip[i].sock);
						}else{
							close(sip[i].sock);
						}
						return 0;
					}
				}
			}
		}else{
			//printf("Group time out.\n");
		}
		
	}
	printf("no connection available.\n");
	return -1;
	
}



