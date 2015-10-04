#include "utility.h"

char* ntop(void *src){

	char *dest = (char *)malloc(sizeof(char) * INET_ADDRSTRLEN);
	inet_ntop(AF_INET, src, dest, INET_ADDRSTRLEN);
	return dest;

}



void printIP(struct iphdr *IPHeader){
	char destip[32], srcip[32];
	inet_ntop(AF_INET, &IPHeader->daddr, destip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &IPHeader->saddr, srcip, INET_ADDRSTRLEN);
	printf("From: %s\n To: %s\n",  srcip, destip);
}


int get_my_mac_addr(char *my_interface,char *my_mac_addr)
{
        int s;
        struct ifreq buffer;

        s = socket(PF_INET,SOCK_DGRAM,0);
        memset(&buffer,0x00,sizeof(buffer));
        strcpy(buffer.ifr_name,my_interface);

        if(ioctl(s,SIOCGIFHWADDR,&buffer) == -1) {
                perror("Error in getting my mac addr:");
                close(s);
               // exit(1);
        }
  //      printf("my mac -> %s\n",ethernet_mactoa(&buffer.ifr_hwaddr));
        memcpy((char *)my_mac_addr,(char *)buffer.ifr_hwaddr.sa_data,ETHER_ADDR_LEN);
        close(s);
}


uint32_t get_my_ip_address(char *interfaceName)
{
	int fd;
 	struct ifreq ifr;
	uint32_t my_ip;
	struct sockaddr_in *tmp;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;
	/* I want IP address attached to "eth0" */
	strncpy(ifr.ifr_name, interfaceName, strlen(interfaceName)+1);

	if(ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
	                perror("Error in getting my IP addr:");
	                close(fd);
	               // exit(1);
	        }

	close(fd);
	/* display result */
//	printf("My IP address %s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
//	my_ip = (uint32_t)((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;

	tmp = (struct sockaddr_in *)&ifr.ifr_addr;
	my_ip = (uint32_t)tmp->sin_addr.s_addr;
	return my_ip;
}

int isThisMyIPAddress(uint32_t myIP){

	   struct ifreq *ifr;
	   struct ifconf ifc;
	   int s, i;
	   int numif;

	   // find number of interfaces.
	   memset(&ifc, 0, sizeof(ifc));
	   ifc.ifc_ifcu.ifcu_req = NULL;
	   ifc.ifc_len = 0;

	   if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	     perror("socket");
	     exit(1);
	   }

	   if (ioctl(s, SIOCGIFCONF, &ifc) < 0) {
	     perror("ioctl");
	     exit(2);
	   }

	   if ((ifr = malloc(ifc.ifc_len)) == NULL) {
	     perror("malloc");
	     exit(3);
	   }
	   ifc.ifc_ifcu.ifcu_req = ifr;

	   if (ioctl(s, SIOCGIFCONF, &ifc) < 0) {
	     perror("ioctl2");
	     exit(4);
	   }
	   close(s);

	   numif = ifc.ifc_len / sizeof(struct ifreq);
	   for (i = 0; i < numif; i++) {
			 struct ifreq *r = &ifr[i];
			 struct sockaddr_in *sin = (struct sockaddr_in *)&r->ifr_addr;

			if(myIP == (sin -> sin_addr).s_addr){
				free(ifr);
				return 1;
			}

			 //printf("%-8s : %s\n", r->ifr_name, inet_ntoa(sin->sin_addr));
	   }

	   free(ifr);
	   return 0;

}

// standard csum function used
unsigned short csum(unsigned short *buf, int len)
{
        unsigned long sum;
        for(sum=0; len>0; len--)
                sum += *buf++;
        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);
        return (unsigned short)(~sum);
}
void printIPTableEntry(IPTableEntry iPTableEntry){

	printf("Network Address \n");
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
	printf("\n Mac Address  %s\n\n", iPTableEntry.nextHopMACAddress);

}


u_char *ethernet_mactoa(struct sockaddr *addr)
{

	u_char *mac  = (u_char*)malloc(sizeof(u_char) * ETHER_ADDR_LEN);
	unsigned char *ptr = (unsigned char *) addr->sa_data;
	memcpy(mac, ptr, ETHER_ADDR_LEN);
	return (mac);

}

u_char* getMACforIP(IPTableEntry iPTableEntry){

	int                 s;
	struct arpreq       areq;
	struct sockaddr_in *sin;

	//printIPTableEntry(iPTableEntry);
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

//	printf(" printing %s  %d\n",iPTableEntry.interface, strlen(iPTableEntry.interface));
	strncpy(areq.arp_dev, iPTableEntry.interface, strlen(iPTableEntry.interface) + 1);
	//strncpy(areq.arp_dev, "eth1", 5);

	//FILE *pingHandle = popen("ping ");usRTR.lab6-IP-Router.USC558L
	int result = ioctl(s, SIOCGARP, (caddr_t) &areq);
	if (result == -1) {
		//perror("-- Error: unable to make ARP request, error");
		return NULL;
		//exit(1);
	}

	u_char *mac_addr = ethernet_mactoa(&areq.arp_ha);
//	printf("%s (%s) -> %s\n", ntop(&iPTableEntry.nextHopIPAddress),
//			ntop(&(((struct sockaddr_in *) &areq.arp_pa)->sin_addr)),
//			mac_addr);
	close(s);
	return mac_addr;

}

void printMac(u_char *ptr){

	u_char *buff = (u_char*)malloc(sizeof(u_char) * 20);
	int result = sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X",
			(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
			(ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));
	printf(" Mac result %d buff %s \n", result, buff);

	free (buff);
}


unsigned short tcp_sum_calc(unsigned short len_tcp, unsigned short src_addr[],unsigned short dest_addr[], unsigned short buff[])
{
    unsigned char prot_tcp=6;
    unsigned long sum;
    int nleft;
    unsigned short *w;

    sum = 0;
    nleft = len_tcp;
    w=buff;

    /* calculate the checksum for the tcp header and payload */
    while(nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* if nleft is 1 there ist still on byte left. We add a padding byte (0xFF) to build a 16bit word */
    if(nleft>0)
    {
    	/* sum += *w&0xFF; */
             sum += *w&ntohs(0xFF00);   /* Thanks to Dalton */
    }

    /* add the pseudo header */
    sum += src_addr[0];
    sum += src_addr[1];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += htons(len_tcp);
    sum += htons(prot_tcp);

    // keep only the last 16 bits of the 32 bit calculated sum and add the carries
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    // Take the one's complement of sum
    sum = ~sum;

return ((unsigned short) sum);
}


