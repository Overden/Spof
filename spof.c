/*
 * Spof
 * ICMP-IP SPOOFING TOOL
 * by Overden <overden [at] autistici [dot] org > 
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <memory.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ip.h>


typedef u_int32_t u32;
typedef u_int16_t u16;
typedef u_int8_t  u8;
typedef struct iphdr iphdr;

#define ICMP_ECHO	8
#define IP_LEN		sizeof(iphdr)
#define ICMP_LEN	sizeof(icmphdr)

typedef struct {
	u8	type;
	u8	code;
	u16 checksum;
	u16 id;
	u16 sequence;
}icmphdr;

u16 csum(u16 *buf, ssize_t size);

int main(int argc, char **argv)
{
	int sock, one=1, i;
	char *source_ip;
	char *destination_ip;
	
	u8 buf[1024];
	char data[56];

	struct sockaddr_in sin;
	char *tmp = malloc(IP_LEN + ICMP_LEN + 1024);
	iphdr *ip = (iphdr *) tmp;
	icmphdr *icmp = (icmphdr *) ip + IP_LEN;
	
	/* PREPARING DATA */
	for(i=0; i<56; i++)
		data[i] = i;
	
	
	if(argc < 3){
		printf("Usange.\n");
		printf("%s SOURCE_IP DESTINATION_IP", argv[0]);
	}else{
		source_ip = argv[1];
		destination_ip = argv[2];
	}
	
	memset(buf, 0, sizeof(buf));
	
	/* IP HEADERS */
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = IP_LEN + ICMP_LEN + 1024;
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = 255;
	ip->protocol = 0x01;
	ip->saddr = inet_addr(source_ip);
	ip->daddr = inet_addr(destination_ip);
	ip->check = csum ((u16 *) buf, ip->tot_len >> 1);
	
	/* ICMP HEADERS */
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->id = 1;
	icmp->sequence = 1;
	
	/* INITIALIZING SOCKET */
	sin.sin_family = AF_INET;
	sin.sin_port = 0;
	sin.sin_addr.s_addr = ip->saddr;
	
	/* RAW SOCKET */
	if ((sock = socket(PF_INET, SOCK_RAW, 0x01)) < 0){
		fprintf(stderr, "socket() error: %s\n", strerror(errno));
	}
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){
		printf("Error: Cannot set HDRINCL!\n");
	}
	if (sendto(sock, ip, ip->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0){
		printf("Error: Send error.\n");
	}else{
		printf("Packet sent!\n");
	}
	return 0;
}

u16 csum(u16 *buf, ssize_t size){
	u16 sum = 0;
	sum >>= 1;
	for (sum = 0; size > 0; size--){
		sum += *buf++;
		sum = (sum >> 16) + (sum & 0xffff);
		sum += (sum >> 16);
	}
	return ~sum;
}	
