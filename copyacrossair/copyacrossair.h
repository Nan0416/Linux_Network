#ifndef __COPY_ACROSS_AIR_
#define __COPY_ACROSS_AIR_

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
	FILE_TRANSFER
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





#endif // __COPY_ACROSS_AIR_
