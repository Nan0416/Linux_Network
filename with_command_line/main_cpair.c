#include <string.h>
#include <stdlib.h>
#include <argp.h>
#include "transceiver.h"
#include "sniffer_select.h"

const char *argp_program_version = "CopyAcrossAir Version 0.0.1";
const char *argp_program_bug_address = "qinnan0416@gmail.com";

/* Program documentation. details after \v */
static char doc[] = "A program simplified the process of transferring file across LAN or Internet.\vDetails:";

/* A string describing what non-option arguments are called by this parser. */
static char args_doc[] = "-r\n-s [--sniff] -f test.txt";

/* The options we understand. */
static struct argp_option options[] = {
	{"receiver",  'r', 0,      0,  "receiver mode", 0 }, /** verbose name, short name (just a code), args, flag, group**/ 
	{"sender",    's', 0,      0,  "sender mode", 0 },
	{"addr",      'a', "IP",      0,  "receiver's ip address", 0 }, /** "IP" means must be followed by a value. **/
	{"sniff",      0 , 0,      0,  "auto sniff ip address used in sender mode", 0},
	{"file",      'f', "Filename",      0,  "the file to be sent", 0},
	{"startip",    1 , "START IP",      0, "sniffing ip range start, inclusive", 0},
	{"endip",      2 , "END IP",        0, "sniffing ip range end, exclusive", 0}};

/* Used by main to communicate with parse_opt. */
typedef struct arguments
{
	char mode; // 1 receiver mode, 2 sender mode
	char *ip;           
	char *file;
	char sniff_required;
	char * start_ip;
	char * end_ip;
}arguments;

/* Parse a single option. */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
	struct arguments *content = state->input;
	switch (key){
		case 'r': content->mode = 1;break;
    	case 's': content->mode = 2;break;
		case 'a': content->ip = arg;break;
		case 0: content->sniff_required = 1;
		case 'f': content->file = arg;break;
		case 1: content->start_ip = arg; break;
		case 2: content->end_ip = arg; break;
		default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
   

/* Our argp parser. */
static struct argp argp = { options, parse_opt, args_doc, doc ,NULL, NULL, NULL}; 

int main (int argc, char **argv)
{
	struct arguments content;
  /* Default values. */
	content.mode = 0;
	content.ip = NULL;
	content.file = NULL;
	content.sniff_required = 0;
	content.start_ip = "192.168.1.2";
	content.end_ip = "192.168.1.254";
	argp_parse (&argp, argc, argv, 0, 0, &content);
	
	//printf("sniff [%d]\n", content.sniff_required);
	
	
    if(content.mode == 2 && content.file != NULL){
		if(content.sniff_required == 1){
			char receiver_ip[16];
			ip_num start;
			ip_num end;
			convert_ip_string_ip_num(content.start_ip, &start);
			convert_ip_string_ip_num(content.end_ip, &end);
			int receiver_fd = sniff(&start, &end, receiver_ip);
			if(receiver_fd == -1){
				printf("Failed.\n");
				return 1;
			}
			content.ip = receiver_ip;
			//return sender(server_fd, content.file);
			return sender_wrapper(content.ip, content.file);
		}else{	
			
			return sender_wrapper(content.ip, content.file);
		}
	}else if(content.mode == 1){
		
		return receiver(content.ip, 0);	
	}
	return 0;
}
