/*
	DiabloHorn
	sniffer using raw sockets
*/
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <time.h>

#include "pcap.h"

/*
typedef struct _iphdr
{
	unsigned char h_lenver;
	unsigned char tos;
	unsigned short total_len;
	unsigned short ident;
	unsigned short frag_and_flags;
	unsigned char ttl;
	unsigned char proto;
	unsigned short checksum;
	unsigned int sourceIP;
	unsigned int destIP;
}IP_HDR;

typedef struct tcphdr
{
     unsigned short int sport;
     unsigned short int dport;
     unsigned int th_seq;
     unsigned int th_ack;
     unsigned char th_x2:4;
     unsigned char th_off:4;
     unsigned char Flags;
     unsigned short int th_win;
     unsigned short int th_sum;
     unsigned short int th_urp;
//	 unsigned char *data;
}TCP_HDR;

typedef struct udphdr
{
	unsigned short	sport;
	unsigned short	dport;
	unsigned short	length;
	unsigned short	checksum;
}UDP_HDR;

typedef struct icmphdr
{
	unsigned char icmp_type;
	unsigned char icmp_code;
	unsigned short icmp_cksum;
	unsigned short icmp_id;
	unsigned short icmp_seq;
	//8bytes
}ICMP_HDR;


typedef struct _rawPacketTCP
{
	IP_HDR *ipHdr;
	TCP_HDR *tcpHdr;
	unsigned char *data;
	int dataLen;
} PACKET_TCP, *PPACKET_TCP;

typedef struct _rawPacketUDP
{
	IP_HDR *ipHdr;
	UDP_HDR *udpHdr;
	unsigned char *data;
	int dataLen;
} PACKET_UDP, *PPACKET_UDP;

typedef struct _rawPacketICMP
{
	IP_HDR *ipHdr;
	ICMP_HDR *icmpHdr;
	unsigned char *data;
	int dataLen;
} PACKET_ICMP,*PPACKET_ICMP;
*/