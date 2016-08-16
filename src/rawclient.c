# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <netinet/in.h>
# include <sys/socket.h>
# include <sys/ioctl.h>
# include <netpacket/packet.h>
# include <net/ethernet.h>
# include <net/if.h>
# include <linux/if_ether.h>
# include <arpa/inet.h>
# include "../hdr/func.h"

# define PCKT_LEN 1024
# define SRV_PORT 4444
# define CLNT_PORT 5555
# define DEFAULT_IF "eth0"

void main ()
{
	int raw_sock, from_clnt_buf, i;
	const int on = 1;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll s_addr, clnt_addr;
	char ifName[IFNAMSIZ];
	char *datagram;
	struct ps_header *ps_hdr;
	struct ether_header *eth_hdr;
	struct ipv4_header *ip_hdr;
	struct udp_header *udp_hdr;    
	unsigned char src_mac[6] = {0x54, 0x04, 0xa6, 0x11, 0xe2, 0x67};
	unsigned char dest_mac[6] = {0x54, 0x04, 0xa6, 0x11, 0xe2, 0x67};
/*
 * Allocate memory for sending packet.
 */
    datagram = malloc (sizeof (char) * PCKT_LEN);
	memset (datagram, 0, PCKT_LEN);
	strcpy (ifName, DEFAULT_IF);

/* 
 * Create socket and set his options.
 */
	raw_sock = socket (AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (raw_sock < 0)	
	{
		perror ("Client socket initiate error");
		exit (1);
	}
/* 
 * Save mac and eth-index.
 */
	memset (&if_idx, 0, sizeof (struct ifreq));
	strncpy (if_idx.ifr_name, ifName, IFNAMSIZ - 1);
	if (ioctl (raw_sock, SIOCGIFINDEX, &if_idx) < 0)
	{
		perror ("SIOCGIFINDEX error!");
	}
	memset (&if_mac, 0, sizeof (struct ifreq));
	strncpy (if_mac.ifr_name, ifName, IFNAMSIZ -1);
	if (ioctl (raw_sock, SIOCGIFHWADDR, &if_mac) < 0)
	{
		perror ("SIOCGIFHWADDR error!");
	}
/* 
 * Fabricate destination sockaddr_ll.
 */
	s_addr.sll_family = AF_PACKET;
	s_addr.sll_protocol = 0;
	s_addr.sll_ifindex = if_idx.ifr_ifindex;
	s_addr.sll_hatype = 0;
	s_addr.sll_pkttype = 0;
	s_addr.sll_halen = ETH_ALEN;
	memcpy (s_addr.sll_addr, if_mac.ifr_hwaddr.sa_data, ETH_ALEN);
	s_addr.sll_addr[6] = 0x0; // MAC adress lenth is 8 byte, we need only 6, this byte not using
	s_addr.sll_addr[7] = 0x0; // MAC adress lenth is 8 byte, we need only 6, this byte not using
/* 
 * Fabricate ethernet header.
 */
	eth_hdr = malloc (sizeof (struct ether_header));
	memcpy (eth_hdr -> ether_shost, src_mac, sizeof (src_mac));
	memcpy (eth_hdr -> ether_dhost, dest_mac, sizeof (dest_mac));
	eth_hdr -> ether_type = htons (ETH_P_IP);	
/*
 * First packet part to sending.
 */
	memcpy (datagram, eth_hdr, sizeof (*eth_hdr));
/* 
 * Fabricate IP header.
 */
	ip_hdr = malloc (sizeof (struct ipv4_header));
	ip_hdr -> ihl = 0x5;
	ip_hdr -> version = 0x4;
	ip_hdr -> tos = 0x0;
	ip_hdr -> tot_len = 60;
	ip_hdr -> id = htons(12830);
	ip_hdr -> frag_off = 0x0;
	ip_hdr -> ttl = 70;
	ip_hdr -> protocol = IPPROTO_UDP;
	ip_hdr -> check = 0x0;
	ip_hdr -> saddr = inet_addr ("192.168.2.42");
	ip_hdr -> daddr = inet_addr ("192.168.2.42");
	ip_hdr -> check = checksum ((u_short *) ip_hdr, sizeof (*ip_hdr));
/* 
 * Second packet part to sending.
 */
	memcpy (datagram + sizeof (*eth_hdr), ip_hdr, sizeof (*ip_hdr));
/* 
 * Fabricate UDP header.
 */
	udp_hdr = malloc (sizeof (struct udp_header));
	udp_hdr -> uh_sport = htons (CLNT_PORT);
	udp_hdr -> uh_dport = htons (SRV_PORT);
	udp_hdr -> uh_ulen = htons (sizeof (struct udp_header));
	udp_hdr -> uh_sum = 0x0000;
/* 
 * Third packet part to sending.
 */
	memcpy (datagram + sizeof (*eth_hdr) + sizeof (*ip_hdr), udp_hdr, 
            sizeof (*udp_hdr));
    while (1)
    {
        printf ("Sending!\n");
		sleep (2);
		if (sendto (raw_sock, datagram, PCKT_LEN, 0, 
                (struct sockaddr *)&s_addr, sizeof (struct sockaddr_ll)) < 0)
		{
			perror ("Sendto error!");
			exit (1);
		}	
    }
	free (datagram);	
	close (raw_sock);
}
