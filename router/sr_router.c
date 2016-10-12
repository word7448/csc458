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
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


/*Global*/

static uint32_t* crc32Lookup;
void handle_arp(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void handle_ip(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
uint32_t crc32_bitwise(const void* data, size_t length, uint32_t previousCrc32);
int sanity_check(sr_ip_hdr_t *ipheader);
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
	

    /* Ethernet Header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) packet;
    print_hdr_eth((uint8_t *)eth_hdr);
    
    
    uint16_t ethernet_type = ethertype((uint8_t*) eth_hdr);
    
    
     if (ethernet_type == ethertype_arp){
        
        fprintf(stdout,"ARP Packet Received\n");
        handle_arp(sr, packet, len, interface);
    }
     else if (ethernet_type == ethertype_ip){
         
         fprintf(stdout,"IP Packet Received\n");
         handle_ip(sr, packet, len, interface);
     }
    
     else{
         fprintf(stderr,"Unknown Packet Type Dropping Packet\n");
         return;
     }
}/* end sr_ForwardPacket */




/* Keeping methods out of the sr_handle
 Make another file for it?*/

/* Takes an ARP packet and deals with it */
void handle_arp(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
	/*easy references to the original packet internals*/
    sr_ethernet_hdr_t *orig_eth = (sr_ethernet_hdr_t*) packet;
	sr_arp_hdr_t *orig_arp = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
	print_hdr_arp(orig_arp);

	/*assume if it's broadcasted to me, it must be for something connected to me*/
    uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if(memcmp(orig_eth->ether_dhost, broadcast_mac, 6) == 0)
    {
    	uint8_t dest_mac[6] = {0, 0, 0, 0, 0, 0};

    	/*check the cache first to see if the ip<--> mac mapping is already there*/
    	struct sr_arpentry *cache_hit = sr_arpcache_lookup(&(sr->cache), orig_arp->ar_dest_ip);
    	if(cache_hit != NULL)
    	{
    		memcpy(dest_mac, cache_hit->mac, 6);
    		free(cache_hit);
    	}
    	else /*if the cache didn't have a hit then you've gotta look for the mapping*/
    	{
			struct sr_if *interface_listing = sr->if_list;
			struct sr_arpreq *backlog;
			while(interface_listing != NULL) /*loop through the if_list to find a matching gateway for the request*/
			{
				if(interface_listing->ip == orig_arp->ar_dest_ip)
				{
					memcpy(dest_mac, interface_listing->mac, 6);
					backlog = sr_arpcache_insert(&(sr->cache), dest_mac, orig_arp->ar_dest_ip);

					/*only proccess the backlog if there is one. otherwise backlog->packet will give a memory read exception*/
					if(backlog != NULL)
					{
						/*proccess the backlog of ip packets with the already existing handle_ip*/
						struct sr_packet *backlog_packet = backlog->packets;
						while(backlog_packet != NULL)
						{
							handle_ip(sr, backlog_packet->buf, backlog_packet->len, backlog_packet->iface);
							backlog_packet = backlog_packet->next;
						}

						/*backlog has been completed, get rid of this request*/
						sr_arpreq_destroy(&(sr->cache), backlog);
					}
					break;
				}
				interface_listing = interface_listing->next;
			}
	    	if(interface_listing == NULL)
	    	{
	    		printf("reached the end of sr->if_list. couldn't find a match for the arp request\n");
	    	}
    	}

		/*now that you have the mac for the ip, make a reply*/
		int reply_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
		uint8_t *reply = malloc(reply_size);

		/**
		 * Assemble ethernet header.
		 * Destination is the source of the original ethernet header
		 * Source is the router's gateway port.
		 */
		sr_ethernet_hdr_t *reply_eheader = (sr_ethernet_hdr_t*) reply;
		memcpy(reply_eheader->ether_dhost, orig_eth->ether_shost, 6);
		memcpy(reply_eheader->ether_shost, dest_mac, 6);
		reply_eheader->ether_type = orig_eth->ether_type;

		/**
		 * Assemble arp header.
		 * Destination is the source of the original arp header
		 * Source is the router's gateway port.
		 */
		sr_arp_hdr_t *reply_arp = reply + sizeof(sr_ethernet_hdr_t);
		reply_arp->ar_hardware_type = orig_arp->ar_hardware_type;
		reply_arp->ar_protocol_type = orig_arp->ar_protocol_type;
		reply_arp->ar_mac_addr_len = orig_arp->ar_mac_addr_len;
		reply_arp->ar_ip_addr_len = orig_arp->ar_ip_addr_len;
		reply_arp->ar_op = htons(arp_op_reply);
		memcpy(reply_arp->ar_src_mac, dest_mac, 6);
		reply_arp->ar_src_ip = orig_arp->ar_dest_ip;
		memcpy(reply_arp->ar_dest_mac, orig_arp->ar_src_mac, 6);
		reply_arp->ar_dest_ip = orig_arp->ar_src_ip;

		/*Print what's in the reply before sending it*/
		printf("the reply\n");
		print_hdrs(reply, reply_size);

		/*send it*/
		int result = sr_send_packet(sr, reply, reply_size, interface);
		if (result != 0)
		{
			fprintf(stderr, "error has occurred sending the packet.\n");
		}
    }
}

/* Takes an IP packet and deals with it */
void handle_ip(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
    
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    
    /* Get ethernet header */
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;
    
    /* Get IP header */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    
	/* Get this packet out early if the length is too short*/
	if (len < sizeof(sr_ip_hdr_t)) { 
		fprintf(stderr, "length too short, dropping packet\n");
		return;
	}

	print_hdr_ip(ip_header);
	printf("got an ip packet\n");
    
    int check_packet = sanity_check(ip_header);
    if (check_packet == 1) {
        fprintf(stderr, "Packet dropped\n");
        return;
    }
    
    /* get packet interface*/
    struct sr_if *node = 0;
    node = sr->if_list;
    
    while(node){
        if(node->ip == ip_header->ip_dst){
            fprintf(stdout,"\n");
            fprintf(stdout,"\n");
            fprintf(stdout,"\n");
            fprintf(stdout,"\n");
            fprintf("node %" PRIu32 "\n",node->ip);
            fprintf("dst %" PRIu32 "\n",ip_header->ip_dst);
            
            fprintf(stdout,"\n");
            fprintf(stdout,"\n");
            fprintf(stdout,"\n");
            fprintf(stdout,"\n");
            break;
        }
        node = node->next;
    }
    
    
    
    /* Decrement TTL */
    if (ip_header->ip_ttl > 0){
        ip_header->ip_ttl = ip_header->ip_ttl - 1;
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum(ip_header, ip_header->ip_hl * 4);
        

    } else {

        int size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
        uint8_t *reply_packet = malloc(size);
        
        sr_ethernet_hdr_t *eth_hdr = malloc(sizeof(sr_ethernet_hdr_t));
        memcpy(eth_hdr, (sr_ethernet_hdr_t *) packet, sizeof(sr_ethernet_hdr_t));
        
        /* Ethernet header */
        sr_ethernet_hdr_t *response_ethernet_header = (sr_ethernet_hdr_t *)reply_packet;
        memcpy(response_ethernet_header->ether_dhost, eth_hdr->ether_shost, sizeof(sr_ethernet_hdr_t));
        memcpy(response_ethernet_header->ether_shost, sr_get_interface(sr, interface)->mac, sizeof(sr_ethernet_hdr_t));
        response_ethernet_header->ether_type = htons(ethertype_ip);
        
        
        /* IP header */
        sr_ip_hdr_t *response_ip_header = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
        
        response_ip_header->ip_dst = ip_header->ip_src;
        response_ip_header->ip_p = ip_protocol_icmp;
        response_ip_header->ip_ttl = 255;
        response_ip_header->ip_tos = 0;
        response_ip_header->ip_v = 4;
        response_ip_header->ip_hl = sizeof(sr_ip_hdr_t)/4;
        response_ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
        response_ip_header->ip_id = htons(0);
        response_ip_header->ip_off = htons(IP_DF);
        response_ip_header->ip_src = sr_get_interface(sr, interface)->ip;
        response_ip_header->ip_sum = 0;
        response_ip_header->ip_sum = cksum(response_ip_header, sizeof(sr_ip_hdr_t));
        
        /* ICMP Header */
        sr_icmp_hdr_t *response_icmp_header = (sr_icmp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        response_icmp_header->icmp_type = ICMP_TIME_EXCEEDED;
        response_icmp_header->icmp_code = 0;
        memcpy(response_icmp_header->data, response_ip_header, ICMP_DATA_SIZE);
        response_icmp_header->icmp_sum = 0;
        response_icmp_header->icmp_sum = cksum(response_icmp_header, sizeof(sr_icmp_hdr_t));
        

        struct sr_arpentry *exists = sr_arpcache_lookup(&sr->cache,response_ip_header->ip_dst);
        if (exists != NULL) {            fprintf(stdout,"IP Dest exists in ARP Cache, Sending ICMP ECHO \n");
            sr_send_packet(sr, reply_packet, len, interface);
           
        }
        else{
        fprintf(stdout,"IP Dest doesn't exists in ARP Cache \n");
        sr_arpcache_queuereq(&sr->cache,response_ip_header->ip_dst, reply_packet, size, interface);
        }
        return;
    }


    if (node != NULL) {
        uint8_t ip_type = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
        /* Get ICMP header */
        sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
        switch (ip_type) {
            
            case ip_protocol_tcp:
            case ip_protocol_udp:
                
                fprintf(stdout,"Recieved TCP or UDP Packet. Sending 'ICMP: Port Unreachable' to Source. \n");
                
                int size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                uint8_t *reply_packet = (uint8_t *) malloc(size);
                
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
                memcpy(reply_eth_hdr->ether_shost, sr_get_interface(sr, interface)->mac, sizeof(sr_ethernet_hdr_t));
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
                sr_send_packet(sr, reply_packet, size, interface);
                
                
                break;
                
            case ip_protocol_icmp:
                
                if (icmp_header->icmp_type == ICMP_ECHO_REQ) {

                    memcpy(ethernet_header->ether_dhost, ethernet_header->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
                    memcpy(ethernet_header->ether_shost, sr_get_interface(sr, interface)->mac, sizeof(uint8_t)*ETHER_ADDR_LEN);
                    
                    /* Make ICMP Header */
                    icmp_header->icmp_type = ICMP_ECHO_REPLY;
                    icmp_header->icmp_code = 0;
                    icmp_header->icmp_sum = 0;
                    icmp_header->icmp_sum = cksum(icmp_header, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
                    
                    /* Make IP header */
                    ip_header->ip_sum = 0;
                    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
                    ip_header->ip_src = ip_header->ip_dst;
                    uint32_t new_dest = ip_header->ip_src;
                    ip_header->ip_dst = new_dest;
                    
                    
                    struct sr_arpentry *exists = sr_arpcache_lookup(&sr->cache,ip_header->ip_dst);
                    if (exists != NULL) {
                        fprintf(stdout,"IP Dest exists in ARP Cache, Sending ICMP ECHO \n");
                        sr_send_packet(sr, packet, len, interface);
                        
                    }
                    else{
                        fprintf(stdout,"IP Dest doesn't exists in ARP Cache \n");
                        sr_arpcache_queuereq(&sr->cache,ip_header->ip_dst, packet, len, interface);
                    }

                }
                break;
    
    
            default:
                fprintf(stdout,"Recieved unknown ICMP message type.\n");
                break;
        }
        return;
    }
    /* packet is not for router, dest somewhere else, do TTL decrement*/
     fprintf(stdout,"nothing in the if_list to match the destination, packet not for me.\n");
    return;
    
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

	return ~crc; /* same as crc ^ 0xFFFFFFFF*/
}

/* Finds excuses to get rid of an IP packet */
int sanity_check(sr_ip_hdr_t *ip_header) {

	uint16_t received_checksum = ip_header->ip_sum;
	ip_header->ip_sum = 0;
	uint16_t computed_checksum = cksum(ip_header, ip_header->ip_hl * 4);

	printf("Original CS: %d\n", received_checksum);
	printf("Computed CS: %d\n", computed_checksum);


	if (received_checksum != computed_checksum) {
		fprintf(stderr, "Alt checksum does not match, dropping packet\n");
		return 1;
	}

	fprintf(stdout, "Alt Sanity Checks Passed\n");
	return 0;
}
