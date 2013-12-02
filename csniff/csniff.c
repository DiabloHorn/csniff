/*
	DiabloHorn http://diablohorn.wordpress.com
	sniffer using raw sockets, saves in pcap format
	admin privs needed :(
*/
#include "csniff.h"

#define MAX_HOSTNAME_LAN 255
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) //set the card into promiscious mode

#pragma comment(lib,"ws2_32")

int main(int argc,char *argv[]){
	SOCKET sock;
	WSADATA wsd;
	SOCKADDR_IN sa;
	DWORD dwBytesRet;
	struct hostent *pHostent;
	unsigned int optval = 1;
	char name[MAX_HOSTNAME_LAN];
	/*missing bytes will be filled with fake eth header*/
	char RecvBuf[65521] = {0};
	int retLen;
	HANDLE hPcap;

	WSAStartup(MAKEWORD(2,1),&wsd);
	//create raw socket
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	//check if it succeeded
	if(sock == INVALID_SOCKET){
		printf("socket() error: %d\n",WSAGetLastError());
		return -1;
	}

	memset(&sa,0,sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(0);
	sa.sin_addr.s_addr  =  htonl (INADDR_ANY); //wil change later
	
	gethostname(name, MAX_HOSTNAME_LAN);
	pHostent = (struct hostent * )malloc(sizeof(struct hostent));
	memset(pHostent,0,sizeof(struct hostent));
	pHostent = gethostbyname(name);
	if(pHostent == NULL){
		printf("gethostbyname() %d\n",WSAGetLastError());
		return 1;
	}
	//set correct sniffing ip
	memcpy(&sa.sin_addr.S_un.S_addr, pHostent->h_addr_list[0], pHostent->h_length);
	
	if((bind(sock, (SOCKADDR *)&sa, sizeof(sa)))==SOCKET_ERROR){
		printf("bind() error: %d\n",WSAGetLastError());
		return -1;
	}
	
	printf("Sniffing on: %s\n",inet_ntoa(sa.sin_addr));
	//make sure to set it in promiscious mode and receive all NIC traffic
	//admin privs needed :(
	if(WSAIoctl(sock, SIO_RCVALL, &optval, sizeof(optval), NULL, 0, &dwBytesRet, NULL, NULL) != 0){
		printf("WSAIoctl() Error: %d",WSAGetLastError());
		return -1;
	}
	//start sniffing
	hPcap = openpcap(TEXT("save.pcap"));
	if(hPcap == INVALID_HANDLE_VALUE){
		printf("Pcap saving error\n");
		return 1;
	}

	while(1){
		memset(RecvBuf, 0 , sizeof(RecvBuf));
		retLen = recv(sock, RecvBuf, sizeof(RecvBuf),0);
		if(retLen > 0){
			writepcaprec(hPcap,RecvBuf,retLen);
		}
		//just ignore and continue recv
	}
	closepcap(hPcap);
	return 0;
}