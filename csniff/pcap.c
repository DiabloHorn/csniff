#include "csniff.h"

/*
	Opens a pcap file for appending, file is set to +S +H.
	Writes the general header.
*/
HANDLE openpcap(LPCWSTR filename){
	HANDLE hFile = NULL;
	pcap_hdr *genHeader;
	DWORD numWritten;
	//create file with shared read access and set it's attrib to +S +H
	hFile = CreateFile(filename,FILE_APPEND_DATA,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,NULL);
	if(hFile == INVALID_HANDLE_VALUE){
		return hFile;
	}else if(GetLastError() == ERROR_ALREADY_EXISTS){
		printf("Appending to existing pcap file\n");
		return hFile;
	}
	printf("Created empty pcap file\n");
	genHeader = (pcap_hdr *)malloc(sizeof(pcap_hdr));
	memset(genHeader,0,sizeof(pcap_hdr));
	genHeader->magic_number = 0xa1b2c3d4;
	genHeader->network = 1;//ethernet
	genHeader->sigfigs = 0;
	genHeader->snaplen = 65535;
	genHeader->thiszone = 0;
	genHeader->version_major = 2;
	genHeader->version_minor = 4;
	printf("Writing general pcap header\n");
	
	if(WriteFile(hFile,genHeader,sizeof(pcap_hdr),&numWritten,NULL) == 0){
		//need something more sexy here
		return INVALID_HANDLE_VALUE;
	}
	free(genHeader);
	return hFile;
}

/*
	Write the record of the pcap file
	Write record header (does not take into account the time stuff)
	Write fake eth header
	Write actual ip load data
	NOTE: supplied data must be max size 65521, due to specs in general header
	readon cause of fakeeth and me liking 65535 as a number :-)
*/
void writepcaprec(HANDLE hFile,void *data,int datalen){
	pcaprec_hdr *recHeader;
	DWORD numWritten;
	time_t seconds;
	//fake eth header
	byte fakeeth[14] = {0xde,0xde,0xde,0xde,0xde,0xad,0xbe,0xbe,0xbe,0xbe,0xbe,0xef,0x08,0x00};
	seconds = time(NULL);
	//write pcap record header stuff
	recHeader = (pcaprec_hdr *)malloc(sizeof(pcaprec_hdr));
	memset(recHeader,0,sizeof(pcaprec_hdr));
	recHeader->incl_len = datalen+sizeof(fakeeth);
	recHeader->orig_len = datalen+sizeof(fakeeth);
	recHeader->ts_sec = (unsigned int)seconds;
	recHeader->ts_usec = 0;
	printf("Writing record pcap header\n");
	WriteFile(hFile,recHeader,sizeof(pcaprec_hdr),&numWritten,NULL);
	free(recHeader);
	printf("Writing fake eth header\n");
	//write fake eth header, to fix wireshark
	WriteFile(hFile,fakeeth,sizeof(fakeeth),&numWritten,NULL);
	printf("Writing record data\n");
	//write pcap data stuff
	WriteFile(hFile,data,datalen,&numWritten,NULL);
}

/*
	Prolly hardly used but ohwell...
*/
void closepcap(HANDLE hFile){
	CloseHandle(hFile);
}