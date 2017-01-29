#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "dns.h"

static int debug=0, nameserver_flag=0;
static int MAXBUF = 512;

typedef struct node_struct{
	char* name;
	char* ip;
	struct node_struct* next;
}NODE;

NODE* Used_HS = NULL;
char* globalHostName =NULL;

char* doDNS(char* nameserver, char* hostname, int sock);
char* readRootServers(char* hostname,int sock);
//------------------------------------------------------------------------------------------------------------------------------//
void push(NODE** head, char* str)
{
	char* temp = (char*)malloc(sizeof(MAXBUF));
	strcpy(temp,str);

	if((*head)==NULL)
	{
		NODE* newNode = (NODE*)malloc(sizeof(NODE));
		newNode->name = temp;
		newNode->ip = NULL;
		newNode->next = NULL;
		*head = newNode;
		return;
	}
	
	NODE* newNode = (NODE*)malloc(sizeof(NODE));
	newNode->name = temp;
	newNode->ip = NULL;
	newNode->next = *head;
	*head = newNode;
	return;
}

void freeTheList(NODE* list)
{
	if(list==NULL)
	{
		return;
	}
	if(list->next !=NULL)
	{
		freeTheList(list->next);
		free(list);
	}
	else
	{
		free(list);
	}
}

void printList(NODE* list)
{
	NODE* temp = list;
	while(temp!=NULL)
	{
		printf("%s     :     %s\n",temp->name,temp->ip);
		temp = temp->next;
	}
	return;
}

int checkUsed_HS(NODE* list,char* name)
{
	NODE* temp = list;
	if(temp==NULL)
	{
		return 0;
	}
	while(temp!=NULL)
	{
		if(!(strcmp(name,temp->name)))
		{
			return 1;
		}
		temp = temp->next;
	}
	return 0;
}

void insertIP(NODE** head, char* name, char* ip)
{
	if((*head)==NULL)
	{
		return;
	}
	if(!strcmp((*head)->name,name))
	{
		char* temp = (char*)malloc(sizeof(MAXBUF));
		strcpy(temp,ip);
		(*head)->ip = temp;
	}
	else
	{
		insertIP(&((*head)->next), name, ip);
	}

}

void checkListForIP(NODE** head,int sock,char *hostname)
{
	printf("DOES THIS SHIT GET HERE?-5\n");
	if(head==NULL || (*head)==NULL)
	{
		printf("DOES THIS SHIT GET HERE?-4\n");
		return;
	}
	printf("DOES THIS SHIT GET HERE?-6\n");
	if((*head)->ip == NULL)
	{
		printf("IP IS NULL\n");
		char* temp = (*head)->name;
		
		if(!(checkUsed_HS(Used_HS,temp)))
		{
			//printf("DOES THIS SHIT GET HERE?-6\n");
			push(&Used_HS,temp);
			(*head)->ip = readRootServers(temp,sock);
			return;
		}
		else
		{
			return;
		}
		
	}
	else
	{
		printf("PASSED!\n");
		checkListForIP(&((*head)->next),sock,hostname);
	}
	return;
}
//------------------------------------------------------------------------------------------------------------------------------//

/*
*	Reads from root-servers.txt and stores rootservers
*	into an array of strings. 
*	RETURN: number of Rootservers read in
*/
char* readRootServers(char* hostname,int sock)
{
	FILE* fp = fopen("root-servers.txt","r");
	if(fp==NULL)
	{
		printf("Error, could not find file\n");
		exit(1);
	}

	char* rootServer = (char*)malloc(sizeof(MAXBUF));
	char* pos;
	NODE* head = NULL;

	while( fgets(rootServer,MAXBUF,fp)!=NULL )
	{
		//replace newline char with sentinal
		if( (pos=strchr(rootServer,'\n'))!=NULL )
		{
			*pos='\0';
		}
		//push(&head,rootServer);
		char* ip;
		if( (ip=doDNS(rootServer, hostname, sock)) !=NULL)
		{
			return ip;
		}
	}
	return;
}
//------------------------------------------------------------------------------------------------------------------------------//

char* doDNS(char* nameserver, char* hostname, int sock)
{
	printf("USING THIS NAME-SERVER: %s\n",nameserver);
	printf("USING HOST NAME: %s\n",hostname);

	

	in_addr_t nameserver_addr=inet_addr(nameserver);
				
	// construct the query message
	uint8_t query[1500];
	int query_len=construct_query(query,1500,hostname);

	struct sockaddr_in addr; 	// internet socket address data structure
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53); // port 53 for DNS
	addr.sin_addr.s_addr = nameserver_addr; // destination address (any local for now)
		
	int send_count = sendto(sock, query, query_len, 0,
														(struct sockaddr*)&addr,sizeof(addr));
	if(send_count<0) { perror("Send failed");	exit(1); }	

	// await the response 
	uint8_t answerbuf[1500];
	int rec_count = recv(sock,answerbuf,1500,0);
	if(rec_count<0)
	{
		if(errno == EAGAIN)
		{
			printf("Error Host %s not found on nameserver %s\n",hostname,nameserver);
			if(nameserver_flag==0)
			{
				return NULL; //Go back and iterate into next rootServer in list
			}
			else
			{
				exit(1);
			}
		}
	}
		
	// parse the response to get our answer
	struct dns_hdr *ans_hdr=(struct dns_hdr*)answerbuf;
	uint8_t *answer_ptr = answerbuf + sizeof(struct dns_hdr);
		
	// now answer_ptr points at the first question. 
	int question_count = ntohs(ans_hdr->q_count);
	int answer_count = ntohs(ans_hdr->a_count);
	int auth_count = ntohs(ans_hdr->auth_count);
	int other_count = ntohs(ans_hdr->other_count);

	// skip past all questions
	int q;
	for(q=0;q<question_count;q++) {
		char string_name[255];
		memset(string_name,0,255);
		int size=from_dns_style(answerbuf,answer_ptr,string_name);
		answer_ptr+=size;
		answer_ptr+=4; //2 for type, 2 for class
	}

	int a;
	int got_answer=0;
	NODE* NS_List;
	

	// now answer_ptr points at the first answer. loop through
	// all answers in all sections
	for(a=0;a<answer_count+auth_count+other_count;a++) 
	{
		// first the name this answer is referring to 
		char string_name[255];
		int dnsnamelen=from_dns_style(answerbuf,answer_ptr,string_name);
		answer_ptr += dnsnamelen;

		// then fixed part of the RR record
		struct dns_rr* rr = (struct dns_rr*)answer_ptr;
		answer_ptr+=sizeof(struct dns_rr);

		const uint8_t RECTYPE_A=1;
		const uint8_t RECTYPE_NS=2;
		const uint8_t RECTYPE_CNAME=5;
		const uint8_t RECTYPE_SOA=6;
		const uint8_t RECTYPE_PTR=12;
		const uint8_t RECTYPE_AAAA=28;

		if(htons(rr->type)==RECTYPE_A) 
		{
			printf("The name %s resolves to IP addr: %s\n", string_name, inet_ntoa(*((struct in_addr *)answer_ptr)));
			
			char* ip =inet_ntoa(*((struct in_addr *)answer_ptr));
			if(!strcmp(string_name,hostname))
			{
				return ip;
			}
			insertIP(&NS_List,string_name,ip);
			got_answer=1;
		}
		else if(htons(rr->type)==RECTYPE_NS) 
		{
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
			
			push(&NS_List,ns_string); //Push the ns_string onto the list

			if(debug)
			{
				printf("The name %s can be resolved by NS: %s\n", string_name, ns_string);					
			}
			got_answer=1;
		}

		else if(htons(rr->type)==RECTYPE_CNAME) 
		{
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
			if(debug)
			{
				printf("The name %s is also known as %s.\n",string_name, ns_string);								
			}
		
			char* cName_ret;
			if( (cName_ret=readRootServers(ns_string,sock)) !=NULL)
			{
				return cName_ret;
			}
			got_answer=1;
		}

		else if(htons(rr->type)==RECTYPE_PTR) {
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
			//printf("The host at %s is also known as %s.\n", string_name, ns_string);
			printf("%s resolves to %s",globalHostName,ns_string);
			exit(1);
			got_answer=1;
		}

		else if(htons(rr->type)==RECTYPE_SOA) {
			if(debug)
				printf("Ignoring SOA record\n");
		}

		else if(htons(rr->type)==RECTYPE_AAAA)  {
			if(debug)
				printf("Ignoring IPv6 record\n");
		}
		else {
			if(debug)
				printf("got unknown record type %hu\n",htons(rr->type));
		} 

		answer_ptr+=htons(rr->datalen);
	}
	printf("DOES THIS SHIT GET HERE?-3\n");
	checkListForIP(&NS_List,sock,hostname);
	printf("DOES THIS SHIT GET HERE?-2\n");
	NODE* ptr = NS_List; 
	while(ptr!=NULL)
	{
		if(ptr->ip !=NULL)
		{
			char* ns = ptr->ip;
			ptr = ptr->next;
			char* ret;
			if((ret=doDNS(ns,hostname,sock))!=NULL);
			{
				return ret;
			}
		}
		else
		{
			ptr=ptr->next;
		}	
		
	}

	//if(!got_answer) printf("Host %s not found.\n",arg2);
	freeTheList(NS_List);

}







//------------------------------------------------------------------------------------------------------------------------------//
void usage() 
{
	printf("Usage: hw5 [-d] -n nameserver -i domain/ip_address\n\t-d: debug\n");
	exit(1);
}

/* constructs a DNS query message for the provided hostname */
int construct_query(uint8_t* query, int max_query, char* hostname) {
	memset(query,0,max_query);

	in_addr_t rev_addr=inet_addr(hostname);
	if(rev_addr!=INADDR_NONE) {
		static char reverse_name[255];		
		sprintf(reverse_name,"%d.%d.%d.%d.in-addr.arpa",
						(rev_addr&0xff000000)>>24,
						(rev_addr&0xff0000)>>16,
						(rev_addr&0xff00)>>8,
						(rev_addr&0xff));
		hostname=reverse_name;
	}

	// first part of the query is a fixed size header
	struct dns_hdr *hdr = (struct dns_hdr*)query;

	// generate a random 16-bit number for session
	uint16_t query_id = (uint16_t) (random() & 0xffff);
	hdr->id = htons(query_id);
	// set header flags to request recursive query
	hdr->flags = htons(0x0100);	
	// 1 question, no answers or other records
	hdr->q_count=htons(1);

	// add the name
	int query_len = sizeof(struct dns_hdr); 
	int name_len=to_dns_style(hostname,query+query_len);
	query_len += name_len; 
	
	// now the query type: A or PTR. 
	uint16_t *type = (uint16_t*)(query+query_len);
	if(rev_addr!=INADDR_NONE)
		*type = htons(12);
	else
		*type = htons(1);
	query_len+=2;

	// finally the class: INET
	uint16_t *class = (uint16_t*)(query+query_len);
	*class = htons(1);
	query_len += 2;
 
	return query_len;	
}

int main(int argc, char** argv)
{
	if(argc<2) usage();
	
	char *hostname;
	char *nameserver;
	
	char *optString = "-d-n:-i:";
 	int opt = getopt( argc, argv, optString );
    while( opt != -1 ) 
    {
        switch( opt ) {      
        	case 'd':
        		debug = 1; 
        		break;
        	case 'n':
        		nameserver_flag = 1; 
        		nameserver = optarg;
        		break;	 		
            case 'i':
                hostname = optarg;
                break;	
            case '?':
				usage();
        		exit(1);               
            default:
            	usage();
            	exit(1);
        }
        opt = getopt( argc, argv, optString );
    }
   
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) {
		perror("Creating socket failed: ");
		exit(1);
	}
	struct timeval tv;
	tv.tv_sec = 1;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval));

	char* finalIP;
	globalHostName = hostname;
    if(nameserver_flag==0)
    { 
    	finalIP = readRootServers(hostname,sock);
    	printf("%s resolves to %s",hostname,finalIP);
	}
	else
	{
		finalIP = doDNS(nameserver,hostname,sock);
		printf("%s resolves to %s",hostname,finalIP);

	}
	freeTheList(Used_HS);
	shutdown(sock,SHUT_RDWR);
	close(sock);
	
}