#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <pthread.h>
#define PORT 81
#define THREAD_POOL 100
typedef struct sniff_ip{
	struct sockaddr_in receiver;
	pthread_t tid;
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
void* sniff_worker(void * arg);

void address_num_increment(ip_num * addr);
int compare(const ip_num * small, const ip_num * big);
void print_ip(int ip);
void convert_ip_string_ip_num(char * ip, ip_num *n_ip);


//pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

int main(){
	char * start_c = "10.180.28.50";
	char * end_c = "10.180.28.250";
	start_c = "103.235.46.39";
	end_c = "103.235.46.40";
	ip_num start;
	ip_num end;
	convert_ip_string_ip_num(start_c, &start);
	convert_ip_string_ip_num(end_c, &end);
	//printf("%d", start.x2);
	int receiver_fd = sniff(&start, &end);
	//printf("sock %d\n", receiver_fd);
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



void* sniff_worker(void * arg){
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	sniff_ip * sn = (sniff_ip *)arg;
	//printf("%d\n", sn->sock);
	if(connect(sn->sock, (struct sockaddr *)&(sn->receiver), sizeof(struct sockaddr_in)) == -1){
		//pthread_mutex_lock(&lock);
		//perror("Error in binding");
		//printf(" %d\n", sn->receiver.sin_addr.s_addr);
		//pthread_mutex_unlock(&lock);
		
		
		return NULL;
	}
	
	return arg;
	
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
int sniff(const ip_num * start, const ip_num * end){
	ip_num fun_local = *start;
	
	char receiver_ip[16];
	sniff_ip sip[THREAD_POOL];
	
	int i = 0;
	void * rs;
	int flag = 0;
	sniff_ip * sn_rs;
	while(1){
		i = 0;
		for(; i < THREAD_POOL; i++){
			sip[i].tid = -1;
			if(compare(&fun_local, end) > 0){
				generate_ip_chars(fun_local.x1,fun_local.x2, fun_local.x3, fun_local.x4, receiver_ip);
		
				sip[i].sock = socket(AF_INET, SOCK_STREAM, 0);
			
				sip[i].receiver.sin_addr.s_addr = inet_addr(receiver_ip);
				//printf("%s\n", receiver_ip);// , sip[i].receiver.sin_addr.s_addr);
				sip[i].receiver.sin_port = htons((short)PORT);
				sip[i].receiver.sin_family = AF_INET;
				pthread_create(&(sip[i].tid), NULL, sniff_worker, (void *)&sip[i]);
				address_num_increment(&fun_local);
			}
		}
		i = 0;
		for(; i < THREAD_POOL; i++){
			flag = 0;
			if(sip[i].tid != -1){
				flag = 1;
				pthread_join(sip[i].tid, &rs);
				sn_rs = (sniff_ip*)rs;
				if(sn_rs == NULL){
					// close fd
					close(sip[i].sock);
					sip[i].tid = -1;
				}else{
					//
					int j = 0;
					for(; j < THREAD_POOL; j++){
						if(sip[j].tid != -1 && j != i){
							pthread_cancel(sip[j].tid);
							if(close(sip[j].sock) == -1){
								perror("Error in close");
							}
							sip[j].tid = -1;
						}
					}
					print_ip(sip[i].receiver.sin_addr.s_addr);
					return sip[i].sock;
				}
			}
			if(flag == 0){
				return -1;
			}
		}
	}
	
}
	

