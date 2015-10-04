#include "lab61.h"

int IPTableCounter = 0;

char* ntop(void *src){
	
	char *dest = (char *)malloc(sizeof(char) * INET_ADDRSTRLEN);
	inet_ntop(AF_INET, src, dest, INET_ADDRSTRLEN);
	return dest;
	
}

void printIPTableEntry(IPTableEntry iPTableEntry){

	//printf("Network Address \n");
	char *dest;
	dest = ntop( &iPTableEntry.networkAddress);
	printf("\n Network Address %s\n\n", dest);
	
	free(dest);
	
	char *dest1;
	dest1 = ntop( &iPTableEntry.nextHopIPAddress);
	printf("\n Next hop IP address %s\n\n", dest1);

	free(dest1);
	char *dest2;
	dest2 = ntop( &iPTableEntry.networkMask);
	printf("\n Network Mask %s\n\n", dest2);
	
	free(dest2);

	printf("\n Network interface %s\n\n", iPTableEntry.interface);
	
}


u_char *ethernet_mactoa(struct sockaddr *addr) 
{ 
	u_char *buff = (u_char*)malloc(sizeof(u_char) * 20); 
	u_char *mac  = (u_char*)malloc(sizeof(u_char) * 6);
	unsigned char *ptr = (unsigned char *) addr->sa_data;

	memcpy(mac, ptr, 6);

	int result = sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X", 
			(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377), 
			(ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377)); 
	printf("\n result %d", result);

	free (buff);
	return (mac);

} 

u_char* getMACforIP(IPTableEntry iPTableEntry){

	int                 s;
	struct arpreq       areq;
	struct sockaddr_in *sin;

	printIPTableEntry(iPTableEntry);
	/* Get an internet domain socket. */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		//exit(1);
	}
	
	/* Make the ARP request. */
	memset(&areq, 0, sizeof(areq));
	sin = (struct sockaddr_in *) &areq.arp_pa;
	sin->sin_family = AF_INET;

	//inet_pton(AF_INET, "10.99.0.2", &(sin->sin_addr));
	//char* ipaddress = ntop(&iPTableEntry.nextHopIPAddress);
	//strcat ("ping ", );
	sin->sin_addr = iPTableEntry.nextHopIPAddress;
	sin = (struct sockaddr_in *) &areq.arp_ha;
	sin->sin_family = ARPHRD_ETHER;

	printf(" printing %s  %d\n",iPTableEntry.interface, strlen(iPTableEntry.interface));	
	strncpy(areq.arp_dev, iPTableEntry.interface, strlen(iPTableEntry.interface) + 1);
	//strncpy(areq.arp_dev, "eth1", 5);

	//FILE *pingHandle = popen("ping ");usRTR.lab6-IP-Router.USC558L
	
	if (ioctl(s, SIOCGARP, (caddr_t) &areq) == -1) {
		perror("-- Error: unable to make ARP request, error");
		//exit(1);
	}
	u_char *mac_addr = ethernet_mactoa(&areq.arp_ha);
	printf("%s (%s) -> %s\n", ntop(&iPTableEntry.nextHopIPAddress), 
			ntop(&(((struct sockaddr_in *) &areq.arp_pa)->sin_addr)), 
			mac_addr);
	return mac_addr;
	
}

u_char* routing(uint32_t destIP, char *interface_name){
	int i, entry=-1;
	uint32_t network = 0;
	for(i = 0; i < IPTableCounter; i++) {
		uint32_t result = (uint32_t)(IPTable[i].networkMask.s_addr) & destIP;
		if (result == (uint32_t)(IPTable[i].networkAddress.s_addr)){
			//Still have to do LPM
			if(result > network){
				network = result;
				entry = i;		
			}
		}

	}
	if(entry != -1){
		char *nextHopIP = ntop(&IPTable[entry].nextHopIPAddress);
		if(strcmp(nextHopIP, "0.0.0.0") != 0){
			printf("Network seleted %d\n", entry);
			u_char *mac_addr = getMACforIP(IPTable[entry]);
			strcpy(interface_name, IPTable[entry].interface);		//shak
			return mac_addr;
		}
	}
	return NULL;
	
}


void inject_packet(const struct pcap_pkthdr *header, const u_char *packet, char *dest_interface){

	char errbuf [ PCAP_ERRBUF_SIZE ];
	pcap_t* inject_int_desc;

	if ( ( inject_int_desc = pcap_open_live ( dest_interface, PACKET_LEN, 1, -1, errbuf ) ) == NULL )
    	{
        	printf ( "\nError: %s\n", errbuf );
	        exit ( 1 );
	}

	pcap_inject ( inject_int_desc, packet, header->len );
    
	pcap_close ( inject_int_desc );
}

//this handle time exceeded and sends out icmp message
int handle_time_exceeded(const struct pcap_pkthdr *header, const u_char *packet){

	int size_of_ether_packet = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 28; // do #define afterwards //shak
	char *icmp_reply_ether_packet = malloc(size_of_ether_packet);

	struct ether_header *in_ether,*out_ether;
	struct iphdr *in_ip,*out_ip;
	
	in_ether = (struct ether_header*) packet;
	out_ether = (struct ether_header*) icmp_reply_ether_packet;

	// creating ethernet frame header
	memcpy(out_ether -> ether_shost, in_ether -> ether_dhost, ETHER_ADDR_LEN);
        memcpy(out_ether -> ether_dhost, in_ether -> ether_shost, ETHER_ADDR_LEN);
	out_ether -> ether_type = in_ether -> ether_type;

	// creating IP header

	//call routing 
	
	out_ip = (struct iphdr *)(icmp_reply_ether_packet + sizeof(struct ether_header) ) ;
	in_ip  = (struct iphdr *)(packet + sizeof(struct ether_header) ) ;
	out_ip -> saddr = //my address;
	out_ip -> daddr = in_ip -> saddr;
		
	
	
	
	


}

void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

	printf("Got packet Length %d  another len%d\n", header->len, header->caplen);
	struct ether_header *ether;
	
	ether = (struct ether_header*) packet;
	printf("Packet type %d\n", ether->ether_type);
	if(ether -> ether_type == IP_TYPE){
		
		struct iphdr *IPHeader;
		IPHeader = (struct iphdr *) (packet + ETHERNET_LEN);

		int size_ip = (IPHeader -> ihl) * 4;
		printf("IP header lenght %d\n", size_ip);
	
		char destip[32], srcip[32];
		inet_ntop(AF_INET, &IPHeader->daddr, destip, INET_ADDRSTRLEN);	
		inet_ntop(AF_INET, &IPHeader->saddr, srcip, INET_ADDRSTRLEN);
		printf("From: %s\n To: %s\n", destip, srcip);
		
		char dest_interface[INTERFACE_NAME_LEN];
		// handle TTL calculations here
		
		uint16_t ttl_value = IPHeader -> ttl;
		
		printf("\nTTL value is : %u actual value %u\n",ttl_value,IPHeader -> ttl);
		
		// This is routing
		if (ttl_value > 1){
			u_char *dest_mac_addr = routing(IPHeader -> daddr, dest_interface);
			if(dest_mac_addr != NULL){
				// if in promiscious mode this wont work, we will have to get our own mac addr
				memcpy(ether -> ether_shost, ether -> ether_dhost, ETHER_ADDR_LEN);
				memcpy(ether -> ether_dhost, dest_mac_addr, ETHER_ADDR_LEN);
				free (dest_mac_addr);
				inject_packet(header, packet, dest_interface);
			}	
		}
		else if(ttl_value == 1)
		{
			printf("\nCAN SEND TIME EXCEEDED NOW !!!!\n");
			int handle_time_exceeded(header, packet);
		}
	}	
}





int readDevice(char *dev){
	
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net, mask;

	printf("Device %s\n", dev);

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
		printf("Error getting mask %s\n", dev);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, PACKET_LEN, 1, 1000, errbuf);
	if(handle == NULL){
		printf("Error opening device %s : %s\n", dev, errbuf);
		return -1;
	}

	pcap_loop(handle, NUMBER_OF_PACKETS, handle_packet, NULL);
	pcap_close(handle);

}


void readKernelRoutingTable(){
	FILE *fp = fopen("usrtr_route", "r");
	char fileLine[1000];

	fgets(fileLine, 1000, fp);
	fgets(fileLine, 1000, fp);
	
	while(fgets(fileLine, 1000, fp)) {
		
		//printf("%s", fileLine);
		char *lineSplit;
		
		lineSplit = strtok(fileLine, " ");
		printf(" %s \n", lineSplit);
		inet_pton(AF_INET, lineSplit, &(IPTable[IPTableCounter].networkAddress));

		lineSplit = strtok(NULL, " ");
		printf(" %s \n", lineSplit);
		inet_pton(AF_INET, lineSplit, &(IPTable[IPTableCounter].nextHopIPAddress));

		lineSplit = strtok(NULL, " ");
		printf(" %s \n", lineSplit);
		inet_pton(AF_INET, lineSplit, &(IPTable[IPTableCounter].networkMask));
			
		lineSplit = strtok(NULL, " ");
		lineSplit = strtok(NULL, " ");
		lineSplit = strtok(NULL, " ");
		lineSplit = strtok(NULL, " ");
		
		lineSplit = strtok(NULL, " ");
		printf(" %s \n", lineSplit);
		//inet_pton(AF_INET, lineSplit, &(IPTable[IPTableCounter].interface));
		strncpy(IPTable[IPTableCounter].interface, lineSplit, strlen(lineSplit)-1);
		printIPTableEntry(IPTable[IPTableCounter]);
		IPTableCounter++;
		
	}
		
	
	pclose(fp);
}

int main(int argc, char* argv[]){
	readKernelRoutingTable();
	//struct in_addr dummy;
	//inet_pton(AF_INET, argv[1], &dummy);
	//routing((uint32_t)dummy.s_addr);
	
	//if (argc == 2){
		readDevice(argv[1]);
	//}
}
