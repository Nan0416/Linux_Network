#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/wait.h>
#include "transceiver.h"

channel ch[MAX_SERVICE];

static int request(int server_fd){
	request_type rt = FILE_TRANSFER;
	write(server_fd, &rt, sizeof(request_type));
	response rs;
	read(server_fd, &rs, sizeof(response));
	switch(rs.code){
		case PERMIT: return rs.session_id;
		// in future, set errno
		case DENIED_BUSY: fprintf(OUTPUT, "DENIED: Server busy!\n"); return -1;
		case DENIED_NO_REASON: fprintf(OUTPUT, "DENIED: Server angry!\n"); return -1;
		default : return -1;
	}
}

int receiver(char * receiver_ip, int receiverID){
	/** config signal handler **/
	struct sigaction act;
	act.sa_sigaction = handler;
	sigfillset(&act.sa_mask);
	act.sa_flags |= SA_SIGINFO;
	sigaction(SIGCHLD, &act, NULL);
	
	/** config network **/
	
	struct sockaddr_in receiver;
	receiver.sin_family = AF_INET;
	if(receiver_ip != NULL){
		receiver.sin_addr.s_addr = inet_addr(receiver_ip);
	}else{
		receiver.sin_addr.s_addr = htonl(INADDR_ANY);
	}
	receiver.sin_port = htons((short)PORT);
	int sock = socket(AF_INET, SOCK_STREAM, 0); // tcp socket
	if(bind(sock, (struct sockaddr *)&receiver, sizeof(struct sockaddr_in)) == -1){
		perror("Error in binding");
		return 1;
	}
	
	listen(sock, MAX_SERVICE);
	
	socklen_t len = sizeof(struct sockaddr_in);
	/** in future, implement with stack **/
	
	int i = 0;
	for(; i < MAX_SERVICE; i++){
		
			ch[i].flags = CHANNEL_AVAILABLE;
			ch[i].channel_no = i;
			ch[i].client_fd = 0;
	}
	
	while(1){
		channel * ch_ptr = NULL;
		for(int i = 0; i< MAX_SERVICE; i++){
			
			if(ch[i].flags & CHANNEL_AVAILABLE){
				ch_ptr = ch + i;
			
				ch_ptr->flags &= ~((unsigned int)CHANNEL_AVAILABLE);
				ch_ptr->file_fd = 0;
		
				break;
			}
		}
		if(ch_ptr == NULL){
			printf("No availabe channle");
			pause(); // waiting child finish

			continue;
			/* undefined */
		}
		printf("Waiting sender...\n");
		/** during the block of accept, it maybe interrupt by the sigchld signal **/
		ch_ptr->client_fd = accept(sock, (struct sockaddr *)&(ch_ptr->client), &len);
		
		if(ch_ptr->client_fd == -1){
			//perror("Error in accept");
			ch_ptr->flags |= CHANNEL_AVAILABLE;
			continue;
		}
		
		
		if(controller_evaluate(ch_ptr) != 0){
			
			close(ch_ptr->client_fd);
			if(ch_ptr->file_fd != 0){
				close(ch_ptr->file_fd);
			}
			ch_ptr->flags |= CHANNEL_AVAILABLE;
			continue;
		}
		//show_channel(ch_ptr);
		ch_ptr->worker_pid = fork();
		if(ch_ptr->worker_pid > 0){
			
			close(ch_ptr->client_fd);
			close(ch_ptr->file_fd);
		}else if(ch_ptr->worker_pid == 0){
			close(sock);
			worker(ch_ptr);
			//printf("Child [%d] finished\n", getpid());
			break;
		}else{
			perror("Error in create worker process");
			/* close fds */
			close(ch_ptr->client_fd);
			close(ch_ptr->file_fd);
			return 1;
		}
	}
	return 0;
}
int controller_evaluate(channel * ch_ptr){
	/** receive request **/
	request_type rt;
	response rs;
	int session_id = 10;
	read(ch_ptr->client_fd, &rt, sizeof(request_type));
	/** construct reponse and assign session_id accroding flag **/
	if(rt == FILE_TRANSFER){
		ch_ptr->session_id = session_id;
		rs.session_id = session_id;
		rs.code = PERMIT;
		/** send response **/
		write(ch_ptr->client_fd, &rs, sizeof(response));
	}else if(rt == SNIFF_TRY_CLOSE){
		ch_ptr->session_id = session_id;
		rs.session_id = session_id;
		rs.code = PERMIT;
		/** send response **/
		write(ch_ptr->client_fd, &rs, sizeof(response));
		
		return 1;
	}else{
		ch_ptr->session_id = session_id;
		rs.session_id = session_id;
		rs.code = DENIED_NO_REASON;
		/** send response **/
		write(ch_ptr->client_fd, &rs, sizeof(response));
		return -1;
	}

	/** read header **/
	
	response_code rs_c;
	read(ch_ptr->client_fd, &(ch_ptr->hd), sizeof(header));
	__print_header( &(ch_ptr->hd));
	
	/** create file **/
	/** open consider hd.code == FILE_TITLE **/
	ch_ptr->file_fd = open(ch_ptr->hd.hc.fh.filename, O_WRONLY | O_CREAT, 0666);
	if(ch_ptr->file_fd == -1){
		rs_c = FAIL_CREAT_FILE;
		return ch_ptr->channel_no;
	}else{
		rs_c = PERMIT;
	}
	/** response **/
	write(ch_ptr->client_fd, &rs_c, sizeof(response_code));
	
	return 0;
}

int worker(channel * ch_ptr){

	/** receive data **/
	packet pk;
	seq_no count = 0;
	
	do{

		memset(&pk, 0, sizeof(packet));
		read(ch_ptr->client_fd, &pk, sizeof(packet));
		if( pk.session_id == ch_ptr->session_id){
			/* for security */
			if(pk.seq == count){
				write(ch_ptr->file_fd, pk.buf, pk.len);
				write(ch_ptr->client_fd, &count, sizeof(seq_no));
				//printf("receive [%d]\n", count);
				count++;
			}
		}else{
			// session id
			/* close */
		}
	}while(pk.len >= _BUFFER_SIZE);
	close(ch_ptr->file_fd);
	close(ch_ptr->client_fd);
	return 0;
	
	
}

void handler_sa(int signo){
	printf("=== child finished ===\n");
	
}

void handler(int signo, siginfo_t * info, void * p){
	
	int i = 0;
	for(; i < MAX_SERVICE; i++){
		if(ch[i].worker_pid == info->si_pid){
			ch[i].flags |= ((unsigned int)CHANNEL_AVAILABLE);
			//printf("==========file [%s] finished =====\n", ch[i].hd.hc.fh.filename);
			printf("=======F===filesize [%lu]=====\n", ch[i].hd.hc.fh.filesize);
			
			return;
		}
	}
	printf("Fatal error\n");
}

void __print_header(header * hd){
	printf("==========filename [%s]=====\n", hd->hc.fh.filename);
	printf("==========filesize [%lu]=====\n", hd->hc.fh.filesize);
	
}


/** sender **/

int sender_wrapper(char * receiver_ip, char * filename){
	
	struct sockaddr_in receiver;
	receiver.sin_family = AF_INET;
	receiver.sin_addr.s_addr = inet_addr(receiver_ip);
	receiver.sin_port = htons((short)PORT);
	int sock = socket(AF_INET, SOCK_STREAM, 0); // tcp socket
	if(connect(sock, (struct sockaddr *)&receiver, sizeof(struct sockaddr_in)) == -1){
		perror("Error in binding");
		return 1;
	}
	
	return sender(sock, filename);
	
}
int sender(int sock, char * filename){
	
	/** send request, wait session_id **/
	int session_id;
	if((session_id = request(sock)) == -1){
		close(sock);
		return 1;
	}
	/** prepare header **/
	header hd;
	construct_header(filename, session_id, &hd);
	/** send header **/
	if(send_header(sock, &hd) == -1){
		close(sock);
		return 1;
	}
	
	/** send packets **/
	send_packets(session_id, sock, filename);
	close(sock);
	
	return 0;
	
}


void construct_header(char * filename, int session_id, header * hd){
	hd->code = FILE_TITLE;
	strcpy(hd->hc.fh.filename, filename);
	struct stat buf;
	stat(filename, &buf);
	hd->hc.fh.filesize = buf.st_size; // fake
	hd->hc.fh.session_id = session_id;
	
}

int send_header(int server_fd, const header * hd){
	write(server_fd, hd, sizeof(header));
	response_code rs;
	read(server_fd, &rs, sizeof(response_code));
	switch(rs){
		case PERMIT: return 0;
		// in future, set errno
		case DENIED_BUSY: fprintf(OUTPUT, "DENIED: Server busy!\n"); return -1;
		case DENIED_NO_REASON: fprintf(OUTPUT, "DENIED: Server angry!\n"); return -1;
		default : return -1;
	}
}

int send_packets(int session_id, int server_fd, char * filename){
	packet pk;
	int local_fd = open(filename, O_RDONLY, 0666);
	ssize_t nread;
	pk.seq = 0;
	seq_no count;
	do{
		
		memset(pk.buf, 0, _BUFFER_SIZE);
		nread = read(local_fd, pk.buf, _BUFFER_SIZE);
		pk.len = (size_t)nread;
		pk.session_id = session_id;
		write(server_fd, &pk, sizeof(packet));
		read(server_fd, &count, sizeof(seq_no));
		if(count != pk.seq){
			printf("Out or order\n");
		}
		pk.seq++;
	}while(nread == _BUFFER_SIZE);
	return 0;
	
}

void show_channel(channel * ch_ptr){
	printf("======= # ==========\n");
	printf("  client fd [%d]\n", ch_ptr->client_fd);
	printf("  file fd [%d]\n", ch_ptr->file_fd);
	printf("  channel no [%d]\n", ch_ptr->channel_no);
	printf("======= $ ==========\n");
}
void _print_addr(struct sockaddr_in * addr){
	printf("%d\n", ntohs(addr->sin_port));
	printf("%d\n", ntohl(addr->sin_addr.s_addr));
}
