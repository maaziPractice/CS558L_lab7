#ifndef MAIN_H
#define MAIN_H


#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <linux/icmp.h> //check all the header afterwards
#include <net/if.h>
#include <pthread.h>
#include <assert.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <linux/sockios.h>

#include <stdlib.h>

#define PACKET_LEN 1518
#define NUMBER_OF_PACKETS 10000
#define INTERFACE_NAME_LEN 10
#define ICMP_DATA_LEN 28
#define NUMBER_OF_INTERFACES 10

#define NOTHING -1
#define NETWORK_UNREACHABLE 0
#define NETWORK_FOUND 1
#define HOST_UNREACHABLE 2


typedef struct {

	struct in_addr networkAddress;
	struct in_addr nextHopIPAddress;
	struct in_addr networkMask;
	u_char interface[10];
	u_char nextHopMACAddress[ETHER_ADDR_LEN];

}IPTableEntry;

typedef struct{
	u_char myMac[6];
	uint32_t myIP;
	u_char *interfaceName;

}myDetails;



/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

#endif
