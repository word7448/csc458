/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

 /* Global */
static uint32_t* crc32Lookup;
uint32_t crc32_bitwise(const void* data, size_t length, uint32_t previousCrc32);
int sanity_check(unsigned int len, sr_ip_hdr_t *ipheader);
void handle_arp(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void handle_ip(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
	/* REQUIRES */
	assert(sr);

	/* Initialize cache and cache cleanup thread */
	sr_arpcache_init(&(sr->cache));

	pthread_attr_init(&(sr->attr));
	pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_t thread;

	pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

	/* Add initialization code here! */
	printf("size of sr_ethernet_hdr_t %d\n", sizeof(sr_ethernet_hdr_t));
	printf("size of sr_arp_hdr_t %d\n", sizeof(sr_arp_hdr_t));
	printf("size of sr_ip_hdr_t %d\n", sizeof(sr_ip_hdr_t));	



} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
	uint8_t * packet/* lent */,
	unsigned int len,
	char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n", len);	
	
	sr_ethernet_hdr_t *header = (sr_ethernet_hdr_t*)packet;

	print_hdr_eth(packet);
	

	uint16_t useable_type = ethertype(packet);

	switch (useable_type) {
	case ethertype_arp:
	{
		handle_arp(sr,packet, len, interface);
		break;
	}
	case ethertype_ip:
	{
		handle_ip(sr, packet, len, interface);
		break;
	}
	default:
		printf("got something mysterious\n");

	}
}/* end sr_ForwardPacket */




// Keeping methods out of the sr_handle
// Make another file for it?

// Takes an ARP packet and deals with it
void handle_arp(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
	sr_arp_hdr_t *arpheader = (packet + sizeof(sr_ethernet_hdr_t));
	print_hdr_arp(arpheader);
	struct sr_arpreq *result = sr_arpcache_queuereq(&(sr->cache), arpheader->ar_tip, packet, len, interface); /*not doing anything with the result currently*/

}

// Takes an IP packet and deals with it
void handle_ip(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
    
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    
    /* Get ethernet header */
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;
    
    /* Get IP header */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    
	print_hdr_ip(ip_header);
	printf("got an ip packet\n");
    
    int check_packet = sanity_check(len, ip_header);
    if (check_packet == 1) {
        fprintf(stderr, "Packet dropped\n");
        return;
    }
    
    /* get packet interface*/
    struct sr_if *node = 0;
    interface = sr->if_list;
    
    while(node){
        if(node->ip == ip_header->ip_dst){
            break;
        }
        node = node->next;
    }

    if (sr_get_interface(sr, interface) != 0) {
        uint8_t ip_type = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
        /* Get ICMP header */
        sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
        switch (ip_type) {
            
            case ip_protocol_tcp:
            case ip_protocol_udp:
                
                fprintf(stdout,"Recieved TCP or UDP Packet. Sending 'ICMP: Port Unreachable' to Source. \n");
                
                int size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                uint8_t *reply_packet = malloc(size);
                
                sr_ethernet_hdr_t *eth_hdr = malloc(sizeof(sr_ethernet_hdr_t));
                memcpy(eth_hdr, (sr_ethernet_hdr_t *) packet, sizeof(sr_ethernet_hdr_t));
                
                /* Make IP header */
                sr_ip_hdr_t *reply_ip_hdr = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
                reply_ip_hdr->ip_v = 4;
                reply_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t)/4;
                reply_ip_hdr->ip_tos = 0;
                reply_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
                reply_ip_hdr->ip_id = htons(0);
                reply_ip_hdr->ip_off = htons(IP_DF);
                reply_ip_hdr->ip_ttl = 64;
                reply_ip_hdr->ip_dst = ip_header->ip_src;
                reply_ip_hdr->ip_p = ip_protocol_icmp;
                reply_ip_hdr->ip_src = node->ip;
                reply_ip_hdr->ip_sum = 0;
                reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, sizeof(sr_ip_hdr_t));

                
                /* Make ethernet header */
                sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)reply_packet;
                memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(sr_ethernet_hdr_t));
                memcpy(reply_eth_hdr->ether_shost, sr_get_interface(sr, interface)->addr, sizeof(sr_ethernet_hdr_t));
                reply_eth_hdr->ether_type = htons(ethertype_ip);
                
                
                /* Make ICMP Header */
                sr_icmp_t3_hdr_t *reply_icmp_hdr = (sr_icmp_t3_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                reply_icmp_hdr->icmp_type = ICMP_UNREACHABLE;
                reply_icmp_hdr->icmp_code = 3;
                reply_icmp_hdr->unused = 0;
                reply_icmp_hdr->next_mtu = 0;
                reply_icmp_hdr->icmp_sum = 0;
                memcpy(reply_icmp_hdr->data, ip_header, ICMP_DATA_SIZE);
                reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
                sr_send_packet(sr, reply_packet, len, interface);
                
                break;
                
            case ip_protocol_icmp:
                
                if (icmp_header->icmp_type == ICMP_ECHO_REQ) {
                    /* Make ethernet header */
                    memcpy(ethernet_header->ether_dhost, ethernet_header->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
                    memcpy(ethernet_header->ether_shost, sr_get_interface(sr, interface)->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
                    
                    /* Make IP header */
                    /* Now update it */
                    uint32_t new_dest = ip_header->ip_src;
                    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
                    ip_header->ip_src = ip_header->ip_dst;
                    ip_header->ip_dst = new_dest;
                    ip_header->ip_sum = 0;

                    
                    /* Make ICMP Header */
                    icmp_header->icmp_type = ICMP_ECHO_REPLY;
                    icmp_header->icmp_code = 0;
                    icmp_header->icmp_sum = 0;
                    icmp_header->icmp_sum = cksum(icmp_header, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
                    print_hdrs(packet, len);
                    sr_send_packet(sr, packet, len, interface);
                    
                }
                break;
    
    
            default:
                fprintf(stdout,"Recieved unknown ICMP Message type.\n");
                break;
        }
        return;
    }
    /* packet is not for router, dest somewhere else, do TTL decrement*/
    
}



const uint32_t Polynomial = 0xEDB88320;

uint32_t crc32_bitwise(const void* data, size_t length, uint32_t previousCrc32)
{

	uint32_t crc = ~previousCrc32;
	unsigned char* current = (unsigned char*)data;
	while (length--)
	{
		crc ^= *current++;
		unsigned int j;
		for (j = 0; j < 8; j++)
			crc = (crc >> 1) ^ (-1 * (int)(crc & 1) & Polynomial);
	}
	return ~crc; // same as crc ^ 0xFFFFFFFF
}

int sanity_check(unsigned int len, sr_ip_hdr_t *ip_header){
    
    int minimun_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    
    uint16_t received_checksum = ip_header->ip_sum;
    uint16_t computed_checksum = cksum(ip_header, ip_header->ip_hl * 4);
    ip_header->ip_sum = 0;
    
    if (received_checksum != computed_checksum){
        fprintf(stderr, "Checksum does not match, dropping packet\n");
        return 1;
    }
    
    if (len < minimun_length){
        fprintf(stderr, "length too short, dropping packet\n");
        return 1;
    }
    
    fprintf(stdout, "Sanity Checks Passed");
    return 0;
}




