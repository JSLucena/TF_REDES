#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#define PROTO_UDP	17
#define PROTO_TCP	6
#define DST_PORT	8000

#define ETH_LEN	1518
#define ETHER_TYPE	0x0800


char mac_router[6] = {0x00, 0x00, 0x00, 0xaa, 0x00, 0x04};
char mac_app[6] = {0x00, 0x00, 0x00, 0xaa, 0x00, 0x03};

struct eth_hdr_s {
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t eth_type;
};

struct ip_hdr_s {
	uint8_t ver;			/* version, header length */
	uint8_t tos;			/* type of service */
	int16_t len;			/* total length */
	uint16_t id;			/* identification */
	int16_t off;			/* fragment offset field */
	uint8_t ttl;			/* time to live */
	uint8_t proto;			/* protocol */
	uint16_t sum;			/* checksum */
	uint8_t src[4];			/* source address */
	uint8_t dst[4];			/* destination address */
};

struct udp_hdr_s {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t udp_len;
	uint16_t udp_chksum;
};

struct eth_frame_s {
	struct eth_hdr_s ethernet;
	struct ip_hdr_s ip;
	struct udp_hdr_s udp;
};

// function to change MACs
void c_mac(struct eth_frame_s * eth_frame);


// Struct to firewall
struct firewall {
    char removed_ip[20];
    uint16_t port;
    int type; // ip_port_peer = 0, ip_only = 1, port_only = 2
};





int main(int argc, char *argv[])
{
	struct ifreq ifopts;
	struct sockaddr_ll socket_address;
	struct ifreq if_idx;
	char ifName[IFNAMSIZ];
	int sockfd, numbytes;
	char *p;
	struct firewall deny_array[30];
	FILE * f;
	char line[30];
    int result;
    int i, j;
	int ip_port;
	int only_ip;
	int index;
	int firewall_size;
	int block;
	char ip_parsed[30];
	uint16_t port_parsed;
	
	
	uint8_t raw_buffer[ETH_LEN];
	struct eth_frame_s *raw = (struct eth_frame_s *)&raw_buffer;
	
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");
	
	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
	
	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	/* End of configuration. Now we can receive data using raw sockets. */
	printf("Listening \n");
        

	while (1){
		numbytes = recvfrom(sockfd, raw_buffer, ETH_LEN, 0, NULL, NULL);
		
		/*printf("received packet : src mac %02x:%02x:%02x:%02x:%02x:%02x : dst mac %02x:%02x:%02x:%02x:%02x:%02x \n", raw->ethernet.src_addr[0], raw->ethernet.src_addr[1], raw->ethernet.src_addr[2],
																						raw->ethernet.src_addr[3], raw->ethernet.src_addr[4], raw->ethernet.src_addr[5],
																						raw->ethernet.dst_addr[0], raw->ethernet.dst_addr[1], raw->ethernet.dst_addr[2],
																						raw->ethernet.dst_addr[3], raw->ethernet.dst_addr[4], raw->ethernet.dst_addr[5]);*/
		
		if(raw->ethernet.eth_type == ntohs(ETH_P_IP))
		{
			if(raw->ip.proto == PROTO_UDP || raw->ip.proto == PROTO_TCP)
			{
				printf("<%d.%d.%d.%d:%d> <%d.%d.%d.%d:%d> proto: %d : n_bytes %d\n", raw->ip.src[0], raw->ip.src[1], raw->ip.src[2], raw->ip.src[3], ntohs(raw->udp.src_port),
																					 raw->ip.dst[0], raw->ip.dst[1], raw->ip.dst[2], raw->ip.dst[3], ntohs(raw->udp.dst_port),
																					 raw->ip.proto, numbytes);
			}
			else
			{
				printf("<%d.%d.%d.%d> <%d.%d.%d.%d> proto: %d : n_bytes %d\n", raw->ip.src[0], raw->ip.src[1], raw->ip.src[2], raw->ip.src[3],
																			   raw->ip.dst[0], raw->ip.dst[1], raw->ip.dst[2], raw->ip.dst[3],
																			   raw->ip.proto, numbytes);
			}
		}
		
		// firewall
		i = 0;
		firewall_size = 0;
		f = fopen("firewall.txt", "rt");
		while (!feof(f))
        {
            ip_port = 0;
            only_ip = 0;
            
            // get line from file
            fgets(line, 100, f);
          
            // check line format
            j = 0;
            while(line[j] != '\0')
            {
                if(line[j] == ':')
                {
                    index = j;
                    ip_port = 1;
                }
                else if(line[j] == '.')
                {
                    only_ip = 1;
                }
                j++;
            }
            
            // parse to struct firewall
            if(ip_port == 1)
            {
                strncpy(deny_array[firewall_size].removed_ip, line, index);
                deny_array[firewall_size].removed_ip[index] = '\0';
                deny_array[firewall_size].port = atoi(&line[index+1]);
                deny_array[firewall_size].type = 0;
            }
            else if(only_ip == 1 && ip_port == 0)
            {
                strcpy(deny_array[firewall_size].removed_ip, line);
                deny_array[firewall_size].type = 1;
            }
            else
            {
                deny_array[firewall_size].port = atoi(line);
                deny_array[firewall_size].type = 2;
            }
            
            firewall_size++;
            i++;
        }
        fclose(f);
		
		
		// parse ip and port from received packet
		sprintf(ip_parsed, "%d.%d.%d.%d", raw->ip.dst[0], raw->ip.dst[1], raw->ip.dst[2], raw->ip.dst[3]);
		port_parsed = ntohs(raw->udp.dst_port);
		
		printf("Parsed ip %s\n", ip_parsed);
		printf("Parsed port %d\n", port_parsed);

		

		// if ip and port are on firewall, block
		block = 0;
		for(i = 0; i < firewall_size; i++)
		{
		    if(deny_array[i].type == 0) // ip and port
		    {
		        if(strcmp(ip_parsed, deny_array[i].removed_ip) == 0 && port_parsed == deny_array[i].port)
		        {
		            printf("blocked \n");
		            block = 1;
		            break;
		        }
		    }
		    else if(deny_array[i].type == 1) // ip only
		    {
		        if(strcmp(ip_parsed, deny_array[i].removed_ip) == 0)
		        {
		            printf("blocked \n");
		            block = 1;
		            break;
		        }
		    }
		    else if(deny_array[i].type == 2) // port only
		    {
		        if (port_parsed == deny_array[i].port)
		        {
		            printf("blocked \n");
		            block = 1;
		            break;
		        }
		    }
		}

        if(block == 1)
            continue;
		

		// change mac addresses
		c_mac(raw);
	
		// send if isnt a ARP packet
		if (ntohs(raw->ethernet.eth_type) != 0x0806) {
			if (sendto(sockfd, raw_buffer, numbytes, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
				printf("Send failed\n");

			//printf("sent packet, %d bytes\n", numbytes);
		}
	}

	return 0;
}

void c_mac(struct eth_frame_s * eth_frame)
{
	int i;
	for(i = 0; i < 6; i++)
	{
		eth_frame->ethernet.dst_addr[i] = mac_router[i];
		eth_frame->ethernet.src_addr[i] = mac_app[i];
	}
}





