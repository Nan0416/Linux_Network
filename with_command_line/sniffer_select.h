#ifndef _SNIFFER_SELECT__
#define _SNOFFER_SELECT__
#include <arpa/inet.h>
#include <sys/socket.h>

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
typedef struct _config{
	int port;
	int max_select;
}_config;
void generate_ip_chars(unsigned char x1,unsigned char x2, unsigned char x3, unsigned char x4, char * rs);
void address_num_increment(ip_num * addr);
int compare(const ip_num * small, const ip_num * big);
void print_ip(int ip);
void convert_ip_string_ip_num(char * ip, ip_num *n_ip);
int sniff(const ip_num * start, const ip_num * end, char * receiver_ip);

#endif // _SNOFFER_SELECT__
