typedef struct pcap_hdr_s {
        unsigned int magic_number;   /* magic number */
        unsigned short version_major;  /* major version number */
        unsigned short version_minor;  /* minor version number */
        int  thiszone;       /* GMT to local correction */
        unsigned int sigfigs;        /* accuracy of timestamps */
        unsigned int snaplen;        /* max length of captured packets, in octets */
        unsigned int network;        /* data link type */
} pcap_hdr;

typedef struct pcaprec_hdr_s {
        unsigned int ts_sec;         /* timestamp seconds */
        unsigned int ts_usec;        /* timestamp microseconds */
        unsigned int incl_len;       /* number of octets of packet saved in file */
        unsigned int orig_len;       /* actual length of packet */
} pcaprec_hdr;

HANDLE openpcap(LPCWSTR);
void writepcaprec(HANDLE,void *,int);
void closepcap(HANDLE);