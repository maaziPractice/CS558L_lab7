#include "lab7.h"
#include "utility.h"

int IPTableCounter = 0;
unsigned int  dataPacketCounter = 0;
u_int serverSeqNumber;
u_int clientSeqNumber;
u_int originalServerSeqNumber;
u_int originalClientSeqNumber;

int routing(uint32_t destIP, char *interface_name, u_char **mac_addr){
	int i, IPEntry=-1;
	uint32_t network = 0;
	for(i = 0; i < IPTableCounter; i++) {
		uint32_t result = (uint32_t)(IPTable[i].networkMask.s_addr) & destIP;
		if (result == (uint32_t)(IPTable[i].networkAddress.s_addr)){
			//Still have to do LPM
			if(result > network){
				network = result;
				IPEntry = i;
			}
		}

	}

	if(IPEntry != -1){
		char *nextHopIP = ntop(&IPTable[IPEntry].nextHopIPAddress);
		if(strcmp(nextHopIP, "0.0.0.0") != 0){

			//*mac_addr = getMACforIP(IPTable[IPEntry]);
			*mac_addr = IPTable[IPEntry].nextHopMACAddress;

			strcpy(interface_name, IPTable[IPEntry].interface);		//shak
			return NETWORK_FOUND;		// has the network
		}

		//		// next hop not found. dont care. May be in my network
		else{
			IPTableEntry iPTableEntry;
			iPTableEntry.nextHopIPAddress.s_addr = destIP;
			strcpy(iPTableEntry.interface, IPTable[IPEntry].interface);

			u_char* mac = getMACforIP(iPTableEntry);

			u_char tempMac[ETHER_ADDR_LEN];
			memset(&tempMac,0x00,sizeof(tempMac));
			int memcmpResult = memcmp(mac, tempMac,ETHER_ADDR_LEN);

			if(memcmpResult == 0){
				return HOST_UNREACHABLE;
			}

			return NOTHING;
		}
	}
	return NETWORK_UNREACHABLE;			// Network not found

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
int handle_time_exceeded(const struct pcap_pkthdr *header, const u_char *packet, u_char * interfaceName, u_char icmp_type, u_char icmp_code){

	int size_of_headers = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	int size_of_ether_packet = size_of_headers + ICMP_DATA_LEN; // do #define afterwards //shak
//	printf("\nSIZES header %d total %d\n",size_of_headers,size_of_ether_packet);
	char *icmp_reply_ether_packet = (char *)malloc(size_of_ether_packet);

	if(icmp_reply_ether_packet == NULL)
		printf("\n Error in malloc\n");
	struct ether_header *in_ether,*out_ether;
	struct iphdr *in_ip,*out_ip;
	struct icmphdr *out_icmp;
	char *icmp_data;

	in_ether = (struct ether_header*) packet;
	out_ether = (struct ether_header*) icmp_reply_ether_packet;

	// creating ethernet frame header
	// right now just cross assignment may want to think again
	memcpy(out_ether -> ether_shost, in_ether -> ether_dhost, ETHER_ADDR_LEN);   // shaq
        memcpy(out_ether -> ether_dhost, in_ether -> ether_shost, ETHER_ADDR_LEN);
	out_ether -> ether_type = in_ether -> ether_type;

	// creating IP header

	out_ip = (struct iphdr *)(icmp_reply_ether_packet + sizeof(struct ether_header));
	in_ip  = (struct iphdr *)(packet + sizeof(struct ether_header));

//	char my_corr_interface[INTERFACE_NAME_LEN];

	// getting the interface
//	u_char *dest_mac_addr = routing(in_ip -> saddr, my_corr_interface);

//	printf("\nPapi interface %s\n",my_corr_interface);
	// setting up ip addresses for new packet
	out_ip -> saddr = (__u32)get_my_ip_address(interfaceName);
	out_ip -> daddr = (__u32)in_ip -> saddr;

	//ttl for new packet
	out_ip -> ttl = (__u8)IPDEFTTL; // may want to use htons or htonl here

	// setting up the ip header length from previous packet // shak
//	out_ip -> ihl = in_ip -> ihl;  // can be changed to 5
	out_ip -> ihl = (__u8)(sizeof(struct iphdr)/4);
	out_ip -> version = (__u8)IPVERSION;
//	out_ip -> tos = in_ip -> tos; //low delay //can be set to 16
	out_ip -> tos = (__u8)IPTOS_LOWDELAY;

	int tot_len1 = (size_of_ether_packet - sizeof(struct ether_header));
	out_ip -> tot_len = htons(tot_len1);
	out_ip -> id = htons(111);
	out_ip -> protocol = (__u8)IPPROTO_ICMP; // ICMP type may want to check this
//	out_ip -> frag_off = in_ip -> frag_off; // check later
	out_ip -> frag_off = 0;
	out_ip -> check = 0;
	out_ip -> check = (uint16_t)csum((unsigned short *)out_ip,sizeof(struct iphdr)/2);

	// creating ICMP packet

	out_icmp = (struct icmphdr *) (icmp_reply_ether_packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	out_icmp -> type = icmp_type; // may need to do htons here
	out_icmp -> code = icmp_code;  //may need to do htons here
	out_icmp -> checksum = 0;

/*	if(in_ip -> protocol == IPPROTO_ICMP){
		struct icmphdr *in_icmp = (struct icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
		(out_icmp -> un).echo.sequence = (in_icmp -> un).echo.sequence;
		(out_icmp -> un).echo.id = (in_icmp -> un).echo.id;
	}*/
//	icmp_data = (char *) (out_icmp + sizeof(struct icmphdr));
	icmp_data = (icmp_reply_ether_packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));

	memcpy((char *) icmp_data,(char *)in_ip,ICMP_DATA_LEN); //may want to do a #define here

	out_icmp -> checksum = (uint16_t)csum((unsigned short *)out_icmp,(sizeof(struct icmphdr) + ICMP_DATA_LEN)/2); //may want to do #define here

	struct pcap_pkthdr header1;

	header1.len = (uint16_t)size_of_ether_packet;

	inject_packet(&header1, icmp_reply_ether_packet, interfaceName);

}


void handle_packet(u_char *myInfo, const struct pcap_pkthdr *header, const u_char *packet){

	myDetails myAddress = *(myDetails*) myInfo;
	char mac_address[ETHER_ADDR_LEN];
//	printf("Got packet Length %d  another len%d\n", header->len, header->caplen);
	struct ether_header *ether;

	ether = (struct ether_header*) packet;
//	printf("Packet type %d\n", ether->ether_type);

	if(!memcmp(ether -> ether_dhost, myAddress.myMac, ETHER_ADDR_LEN))
	{
		if(ether -> ether_type == 8){		/// It is IP packet

			struct iphdr *IPHeader;
			IPHeader = (struct iphdr *) (packet + sizeof (struct ether_header));

			int size_ip = (IPHeader -> ihl) * 4;
			struct in_addr my_other_ip;

			//printIP(IPHeader);

			// handle TTL calculations here
			//printf("myAddress.myIP %d IPHeader -> daddr  %d",myAddress.myIP,IPHeader -> daddr);

			//int pton_result = inet_pton(AF_INET,"10.10.0.2",&my_other_ip);
			//if(myAddress.myIP == IPHeader -> daddr || my_other_ip.s_addr == IPHeader -> daddr){
			if(isThisMyIPAddress(IPHeader -> daddr)){

				//printf("Paket for me \n");
				if(IPHeader -> protocol == IPPROTO_ICMP){
					// Send ICMP echo reply
					//printf("\n Sending echo reply\n ");

					IPTableEntry iPTableEntry;
					iPTableEntry.nextHopIPAddress.s_addr = IPHeader -> saddr;
					strcpy(iPTableEntry.interface, myAddress.interfaceName);

					u_char* mac = getMACforIP(iPTableEntry);

					if(mac == NULL){

						char temp[ETHER_ADDR_LEN];
						memcpy(temp, ether -> ether_shost, ETHER_ADDR_LEN);
						memcpy(ether -> ether_shost, ether -> ether_dhost, ETHER_ADDR_LEN);
						memcpy(ether -> ether_dhost, temp, ETHER_ADDR_LEN);

						uint32_t tempIP;
						tempIP = IPHeader -> saddr;
						IPHeader -> saddr =  IPHeader -> daddr;
						IPHeader -> daddr = tempIP;

						IPHeader -> check = 0;
						IPHeader -> check = (uint16_t)csum((unsigned short *)IPHeader,sizeof(struct iphdr)/2);

						struct icmphdr *ICMPHeader;
						ICMPHeader = (struct icmphdr *) (packet + sizeof (struct ether_header) +sizeof (struct iphdr));
						ICMPHeader -> type = ICMP_ECHOREPLY;
						ICMPHeader -> code = ICMP_NET_UNREACH;

						ICMPHeader -> checksum = 0;
						ICMPHeader -> checksum = (uint16_t)csum((unsigned short *)ICMPHeader,(header -> len - (sizeof(struct ether_header) + sizeof (struct iphdr)))/2);

						inject_packet(header, packet, myAddress.interfaceName);
					}
				}
				else if(IPHeader -> protocol == IPPROTO_UDP){			// WORKING This is for tracepath destined to me
					//printf("\n Sending traceroute reply\n ");
					handle_time_exceeded(header, packet, myAddress.interfaceName, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH);
				}

			}

			else {

				uint16_t ttl_value = IPHeader -> ttl;

				//printf("packet not for me \n ");
				// This is routing
				if (ttl_value > 1){
					//printf("IP protocol %d", IPHeader -> protocol);
					if(IPHeader -> protocol == IPPROTO_TCP){
						struct sniff_tcp *tcp = (struct sniff_tcp*) (packet + sizeof (struct ether_header) + size_ip);

						int size_tcp = TH_OFF(tcp)*4;
						if(size_tcp < 20){
							printf("Invalid TCP header \n");
						}

						printf("   My interface %s     Src port: %d    ",myAddress.interfaceName,  ntohs(tcp->th_sport));
						printf("   Dst port: %d\n", ntohs(tcp->th_dport));

						if(ntohs(tcp->th_dport) == FPT_CONTROL_PORT){
							//printf("It is control packet \n");
						}

						else if(ntohs(tcp->th_dport) == FPT_DATA_PORT ||  ntohs(tcp->th_sport) == FPT_DATA_PORT){
							//printf("It is data packet \n");

							// It is a SYN and NOT ACK packet
							if((tcp -> th_flags & TH_SYN) && !(tcp -> th_flags & TH_ACK)){

								originalServerSeqNumber = ntohl(tcp -> th_seq);
								serverSeqNumber = ntohl(tcp -> th_seq);
								printf("  My interface %s   Flags  %u   Caught a SYN packet   serverSeqNumber %u\n",myAddress.interfaceName, tcp -> th_flags, serverSeqNumber);
							}

							// It is a SYN - ACK packet
							else if((tcp -> th_flags & TH_SYN) && (tcp -> th_flags & TH_ACK)){

								originalClientSeqNumber = ntohl(tcp -> th_seq);
								clientSeqNumber = ntohl(tcp -> th_seq);
								printf("My interface %s   Flags  %u    Caught a SYN - ACK packet    clientSeqNumber   %u\n",myAddress.interfaceName, tcp -> th_flags,clientSeqNumber);
							}

							// IT is ACK and NOT SYN
							else if(!(tcp -> th_flags & TH_SYN) && (tcp -> th_flags & TH_ACK) &&  (ntohl(tcp -> th_seq) - originalServerSeqNumber == 1)){
								printf("My interface %s   Flags  %u     Caught the 3rd ACK packet\n",myAddress.interfaceName, tcp -> th_flags);
								serverSeqNumber = ntohl(tcp -> th_seq);
							}


							// This is all DATA
							else {

								char * new_data = (char *) malloc (header -> len - sizeof (struct ether_header));
								memcpy(new_data, (char *)(packet + sizeof (struct ether_header)), header -> len - sizeof (struct ether_header));

								dataPacket[dataPacketCounter++] = new_data;
								assert(dataPacketCounter < 100000);

								uint32_t tempIP = IPHeader -> daddr;
								IPHeader -> daddr = IPHeader -> saddr;
								IPHeader -> saddr = tempIP;

								u_short tempTCP = tcp ->  th_dport;
								tcp -> th_dport = tcp -> th_sport;
								tcp -> th_sport = tempTCP;

								u_char * payload = (u_char *)(packet +  sizeof (struct ether_header) + size_ip + size_tcp);

								//compute tcp payload (segment) size
								int size_payload = ntohs(IPHeader->tot_len) - (size_ip + size_tcp);

								tcp->th_ack = htonl(ntohl(tcp->th_seq) + size_payload);

								printf("I stored it seq number %u Packet lenght  %u  Expecting  %u  \n", ntohl(tcp -> th_seq), size_payload, ntohl(tcp->th_ack));

								tcp->th_seq = htonl(serverSeqNumber);

								IPHeader -> tot_len = htons(size_ip + size_tcp);
								printf("IP header lenght %u", size_ip + size_tcp);

								tcp->th_sum = 0;  //Checksum field has to be set to 0 before checksumming
								tcp->th_sum = (unsigned short) tcp_sum_calc((unsigned short) (size_ip + size_tcp),
											(unsigned short *) &IPHeader -> saddr, (unsigned short *) &IPHeader -> daddr, (unsigned short *) &tcp);

								IPHeader -> check = 0;
								IPHeader -> check = (uint16_t)csum((unsigned short *)IPHeader,sizeof(struct iphdr)/2);

								char tempMAC[ETHER_ADDR_LEN];
								memcpy(tempMAC, ether -> ether_shost, ETHER_ADDR_LEN);
								memcpy(ether -> ether_shost, ether -> ether_dhost, ETHER_ADDR_LEN);
								memcpy(ether -> ether_dhost, tempMAC, ETHER_ADDR_LEN);

								struct pcap_pkthdr new_header;
								new_header.len =  sizeof (struct ether_header) + size_ip + size_tcp;
								inject_packet(&new_header, packet, myAddress.interfaceName);
							}
						}
					}

					char dest_interface[INTERFACE_NAME_LEN];
					u_char *dest_mac_addr;
					int routingResult = routing(IPHeader -> daddr, dest_interface, &dest_mac_addr);

					if(routingResult == NETWORK_FOUND){

					// if in promiscious mode this wont work, we will have to get our own mac addr
						memcpy(ether -> ether_shost, myAddress.myMac, ETHER_ADDR_LEN);
						memcpy(ether -> ether_dhost, dest_mac_addr, ETHER_ADDR_LEN);
						IPHeader -> ttl--;

						IPHeader -> check = 0;
						IPHeader -> check = (uint16_t)csum((unsigned short *)IPHeader,sizeof(struct iphdr)/2);

						//free (dest_mac_addr);
						inject_packet(header, packet, dest_interface);
					}
					else if(routingResult == NETWORK_UNREACHABLE){				// Doing Network unreachable
						handle_time_exceeded(header, packet, myAddress.interfaceName, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
					}
					else if(routingResult == HOST_UNREACHABLE){
						handle_time_exceeded(header, packet, myAddress.interfaceName, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
					}



				}
				else if(ttl_value == 1)
				{
//					printf("\nCAN SEND TIME EXCEEDED NOW !!!!\n");
					handle_time_exceeded(header, packet, myAddress.interfaceName, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
				}
			}
		}
	}
}

int readDevice(char *dev){

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net, mask;
	myDetails myAddress;

	printf("Device %s started\n", dev);

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
		printf("Error getting mask %s\n", dev);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, PACKET_LEN, 0, 1000, errbuf);
	if(handle == NULL){
		printf("Error opening device %s : %s\n", dev, errbuf);
		return -1;
	}

	get_my_mac_addr(dev, myAddress.myMac);
	myAddress.myIP = get_my_ip_address(dev);
	myAddress.interfaceName = dev;

	pcap_loop(handle, NUMBER_OF_PACKETS, handle_packet, (u_char*)&myAddress);
	pcap_close(handle);

}


void readKernelRoutingTable(char *filename){
	FILE *fp = fopen(filename, "r");
	char fileLine[1000];

	fgets(fileLine, 1000, fp);
	fgets(fileLine, 1000, fp);

	while(fgets(fileLine, 1000, fp)) {

		char *lineSplit;

		lineSplit = strtok(fileLine, " ");

		inet_pton(AF_INET, lineSplit, &(IPTable[IPTableCounter].networkAddress));



		lineSplit = strtok(NULL, " ");

		inet_pton(AF_INET, lineSplit, &(IPTable[IPTableCounter].nextHopIPAddress));

		lineSplit = strtok(NULL, " ");

		inet_pton(AF_INET, lineSplit, &(IPTable[IPTableCounter].networkMask));

		lineSplit = strtok(NULL, " ");
		lineSplit = strtok(NULL, " ");
		lineSplit = strtok(NULL, " ");
		lineSplit = strtok(NULL, " ");

		lineSplit = strtok(NULL, " ");


		strncpy(IPTable[IPTableCounter].interface, lineSplit, strlen(lineSplit)-1);

		char *nextHopIP = ntop(&IPTable[IPTableCounter].nextHopIPAddress);
		if(strcmp(nextHopIP, "0.0.0.0") != 0){
					char cmd[40];
					sprintf(cmd, "ping %s -c 1 > /dev/null", nextHopIP);
					//printf("cmd %s", cmd);
					FILE *handle = popen(cmd, "r");
					pclose(handle);
					u_char *myMac = getMACforIP(IPTable[IPTableCounter]);
					memcpy(IPTable[IPTableCounter].nextHopMACAddress, myMac, ETHER_ADDR_LEN);
		}
		//printIPTableEntry(IPTable[IPTableCounter]);
		IPTableCounter++;

	}
	pclose(fp);
}


