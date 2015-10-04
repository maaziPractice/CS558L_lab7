#ifndef LAB7_H
#define LAB7_H

#include "main.h"



#define FPT_CONTROL_PORT 21
#define FPT_DATA_PORT 20


char *dataPacket[100000];

int routing(uint32_t , char *, u_char **);
void inject_packet(const struct pcap_pkthdr *, const u_char *, char *);

int handle_time_exceeded(const struct pcap_pkthdr *, const u_char *, u_char * , u_char , u_char );

void handle_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
int readDevice(char *);
void readKernelRoutingTable(char *);

IPTableEntry IPTable[10];

#endif
