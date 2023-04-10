//including libraries
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

//CALLBACK FUNCTION TO PRINT USEFUL INFORMATION OUT OF CAPTURED PACKET
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr,
	const u_char *packet)
{
	//VARIABLES, STRUCTS INITIALIZATION HERE     
	struct ether_header *ep;
	struct ip *iph;
	unsigned short ether_type;
	int chcnt = 0;
	int len = pkthdr->len;
	static int count = 1;
	int i;
    
	// GET ETHERNET HEADER BY TYPECASTING PACKET
	ep = (struct ether_header *)packet;
	// GET PROTOCOL TYPE OF LAYER 2
	ether_type = ntohs(ep->ether_type);

	//PACKET NUMBER IS SIMPLY THE NO. OF TIMES CALLBACK FUNCTION IS CALLED. THIS IS PRINTED USING A SIMPLE COUNT VARIABLE INCREMENTED.
    	printf("\nPacket number [%d]\n", count++);
    	
	//CHECK IF ETHERNET FRAME HAS IP DATAGRAM ENCAPSULATED INSIDE IT
	//PRINT SOURCE AND DESTINATION MAC ADDRESSES FROM ETHERNET HEADER
	if (ether_type == ETHERTYPE_IP) 
	{
	    	printf("ETHER Source Address = ");
	    	for (i=0; i<ETH_ALEN; ++i)
			printf("%.2X ", ep->ether_shost[i]);
	    	printf("\n");
	    	printf("ETHER Dest Address = ");
	    	for (i=0; i<ETH_ALEN; ++i)
			printf("%.2X ", ep->ether_dhost[i]);
	    	printf("\n");
	    	
	    	// IF CONDIITON CHECKS IF UPPER LAYER PROTOCOL IS OTHER THAN IP
	    	if(ether_type != ETHERTYPE_IP)
	    	{
		    	printf("ETHER Type = %d",ether_type);
		    	printf("\n");
	    	}
	    	//OUTSIDE IF CONDITION, UPPER LAYER IS DEFINITELY IP, SO PRINT IT OUT
	    	printf("ETHER Type = %s","Internet Protocol version 4 (IPv4)");
	    	printf("\n");
	   	  
	    	//PACKET POINTER IS CURRENTLY POINTING AT THE ETHERNET HEADER, WHICH IS PLACED AT THE BEGINNING INISDE PACKET.
	    	//NEXT TO ETHER IS IP HEADER, WHICH IS LOCATED AT MEMEORY ADDRESS OF ETH HEADER + SIZE OF ETH HEADER
	    	// SO SIMPLY INCREMENT VALUE OF PACKET POINTER BY SIZE OF ETH HEADER, AND IT WILL START POINTING TO IP HEADER
	    	packet += sizeof(struct ether_header);
	    	
	    	// GET IP HEADER BY TYPECASTING PACKET
	    	iph = (struct ip *)packet;
	    	
	    	//REST OF THE INFO CAN BE PRINTED BY CALLING MEMBERS OF PACKET STRUCTURE
	    	printf("IP Header len = %d\n", iph->ip_hl<<2);
	    	printf("IP Total len = %d\n", iph->ip_len);
	    	if(iph->ip_p == 6)
	    	{
	   		 printf("Next Level Protocol = %s\n", "TCP");
	    	}
	    	else if(iph->ip_p == 1)
	    	{
	   		 printf("Next Level Protocol = %s\n", "ICMP");
	    	}
	    	else if(iph->ip_p == 4)
	    	{
	   		 printf("Next Level Protocol = %s\n", "IPv4 Encapsulation");
	    	}
	    	else if (iph->ip_p == 17)
	    	{
	   		 printf("Next Level Protocol = %s\n", "UDP");
	    	}
	    	else
	    	{
	   		 printf("Next Level Protocol = %d\n", iph->ip_p);
	    	}
	   	 
	    	//INET_NTOA() CONVERTS NETWORK ADDRESS FROM BYTE ORDER TO STRING IN IPV4 DOTTED DECIMAL NOTATION
	    	printf("IP Source Address = %s\n", inet_ntoa(iph->ip_src));
	    	printf("IP Dest Address = %s\n", inet_ntoa(iph->ip_dst));
   	 
	}
}

int main(int argc, char **argv)
{
	//VARIABLES, CHARACTERS, STRUCTS INITIALIZATION HERE
	char *dev;
	char *packet_no;
	char *net;
	char *mask;
	char errbuf[PCAP_ERRBUF_SIZE]; //HOLDS ANY ERROR STRING GENERATED
	struct bpf_program fp;  //HOLDS COMPILED FILTER PROGRAM
	pcap_t *pcd; //LIVE CAPTURE SESSION (packet capture descriptor.)
	bpf_u_int32 netp;  //HOLDS NETWORK ADDRESS ON WHICH LIVE SESSION IS OPENED
	bpf_u_int32 maskp;  ////HOLDS MASK OF NETWORK ADDRESS ON WHICH LIVE SESSION IS OPENED
	struct in_addr net_addr, mask_addr; //STRUCTURE OF TAG IN_ADDR TO HOLD NETWORK AND MASK ADDRESSES RETURENED BY A FUNCTION
	pcap_if_t *alldevs, *d; //HOLD INTERFACES
	char dev_buff[64] = {0};
	char packet_buff[64] = {0};
	int i =0;

	// PREPARE A LIST OF ALL DEVICES
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		printf("%s\n", errbuf);
		exit(1);
	}
	
	// DISPLAY LIST OF DEVICES(INTERFACES) TO USER, SO A CHOISE CAN BE MADE
	printf("\nHere is a list of available devices on your system:\n\n");
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (Sorry, No description available for this device)\n");
	}

	// GET INTERFACE FROM USER
	printf("\nEnter the interface name on which you want to run the packet sniffer: ");
	fgets(dev_buff, sizeof(dev_buff)-1, stdin);

	//CLEAR OFF TRAINLING NEW LINE THAT FGETS SETS
	dev_buff[strlen(dev_buff)-1] = '\0';
	dev = dev_buff;
	 
	//ASK USER FOR NUMBER OF PACKETS
	printf("\nEnter the number of packets you want to capture : ");
	fgets(packet_buff, sizeof(packet_buff)-1, stdin);

	//CLEAR OFF TRAINLING NEW LINE THAT FGETS SETS
	packet_buff[strlen(packet_buff)-1] = '\0';
	packet_no = packet_buff;
	printf("\n ---You opted for device [%s] to capture [%s] packets---\n\n Starting capture...",dev, packet_no);	 

	if(packet_no == NULL || dev == NULL )
	{
		printf("\n[%s]\n", errbuf);
		return -1;
	}
    
	// GET NETADDRESS AND NET MASK OF DEVICE
	if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1) 
	{
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}
	net_addr.s_addr = netp;
	net = inet_ntoa(net_addr);
	printf("\nStarting sniffing on NETWORK : %s\n", net);
	mask_addr.s_addr = maskp;
	mask = inet_ntoa(mask_addr);
	printf("MASK : %s\n", mask);


	// GET PACKET CAPTURE DESCRIPTOR, INITIALIZING A "SESSION" HERE, pcd IS THE SESSION HANDLE
	pcd = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);
	if (pcd == NULL) 
	{
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}

	// SET COMPILE OPTIONS
	if (pcap_compile(pcd, &fp, "tcp", 0, netp) == -1) 
	{
		fprintf(stderr, "compile error\n");
		return 1; 
	}

	// SPECIFY THE FILTER PROGRAM (COMPILED ABOVE) ON REQUIRED LIVE SESSION
	if (pcap_setfilter(pcd, &fp) == -1) {
		fprintf(stderr, "set filter error\n");
		return 1;
	}

	// START PACKET CAPTURE. WHENEVER A PACKET IS CAPTURED, CALL THE CALLBACK FUNCTION FOR ITS ANALYSIS
	pcap_loop(pcd, atoi(packet_no), callback, NULL);
	return 0;
}

