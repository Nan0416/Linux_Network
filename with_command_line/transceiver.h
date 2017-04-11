#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#ifndef __COPY_ACROSS_AIR_
#define __COPY_ACROSS_AIR_
#define OUTPUT stdout
#define PORT 9416
#define MAX_SERVICE 30

#define OUTPUT stdout

#define CHANNEL_AVAILABLE 0x01
typedef unsigned char byte;
#ifdef _FILE_NAME_SIZE
#warning _FILE_NAME_SIZE was defined in other places
#endif
#ifndef _FILE_NAME_SIZE
#define _FILE_NAME_SIZE 64
#endif

#ifdef _BUFFER_SIZE
#warning _BUFFER_SIZE was defined in other places
#endif
#ifndef _BUFFER_SIZE
#define _BUFFER_SIZE 128
#endif


typedef unsigned int seq_no;
typedef enum request_type{
	FILE_TRANSFER,
	SNIFF_TRY_CLOSE
}request_type;
typedef enum response_code{
	FAIL_CREAT_FILE,
	DENIED_NO_REASON,
	DENIED_BUSY,
	PERMIT
}response_code;
typedef struct response{
	int session_id;
	response_code code;
}response;


typedef enum header_code{
	FILE_TITLE
	
}header_code;
typedef struct file_title{
	char filename[_FILE_NAME_SIZE];
	long filesize; // bytes
	int session_id;
	
}file_title;

typedef union header_content{
	file_title fh;
}header_content;

typedef struct header{
	header_code code;
	header_content hc;
}header;

typedef struct packet{
	byte buf[_BUFFER_SIZE];
	int session_id;
	seq_no seq;
	size_t len;
}packet;


typedef struct channel{
	header hd;
	
	int client_fd;
	int file_fd;
	int session_id;
	pid_t worker_pid;
	int channel_no;
	unsigned int flags;
	struct sockaddr_in client;
}channel;



void _print_addr(struct sockaddr_in * addr);

int sender_wrapper(char * receiver_ip, char * filename);
int sender(int sock, char * filename);

void construct_header(char * filename, int session_id, header * hd);
int send_header(int server_fd, const header * file_title);
int send_packets(int session_id, int server_fd, char * filename);

int receiver(char * receiver_ip, int receiverID);
int worker(channel * ch_ptr);
void show_channel(channel * ch_ptr);
void handler_sa(int signo);
void handler(int signo, siginfo_t * info, void * p);
int controller_evaluate(channel * ch_ptr);
void __print_header(header * hd);



#endif // __COPY_ACROSS_AIR_
