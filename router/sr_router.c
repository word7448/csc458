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
#include <stdbool.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


/*Global*/
int sanity_check(sr_ip_hdr_t *ipheader);
struct sr_rt *longest_prefix_match(struct sr_instance *sr, uint32_t ipdest);

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
    char *ever_pointed = ever_pointer(sr, interface);
    
    uint16_t ethernet_type = ethertype((uint8_t*) eth_hdr);
    
    
     if (ethernet_type == ethertype_arp){
        
        fprintf(stdout,"ARP Packet Received\n");
        handle_arp(sr, packet, len, ever_pointed, false);
    }
     else if (ethernet_type == ethertype_ip){
         
         fprintf(stdout,"IP Packet Received\n");
         handle_ip(sr, packet, len, ever_pointed, true);
     }
    
     else{
         fprintf(stderr,"Unknown Packet Type Dropping Packet\n");
         return;
     }
}/* end sr_ForwardPacket */




/* Keeping methods out of the sr_handle
 Make another file for it?*/

/* Takes an ARP packet and deals with it */
void handle_arp(struct sr_instance* sr, uint8_t * incoming_packet, unsigned int incoming_len, char* incoming_interface, bool is_initiative)
{
	/*easy references to the incoming packet internals*/
    sr_ethernet_hdr_t *incoming_eth = (sr_ethernet_hdr_t*) incoming_packet;
	sr_arp_hdr_t *incoming_arp = (sr_arp_hdr_t*)(incoming_packet + sizeof(sr_ethernet_hdr_t));

	/*double check this arp packet is for the router if not, no point of continuing*/
	struct sr_if *interface_listing = sr->if_list;
	while (interface_listing != NULL)
	{
		if (interface_listing->ip == incoming_arp->ar_dest_ip)
		{
			break;
		}
		interface_listing = interface_listing->next;
	}

	if(interface_listing == NULL)
	{
		printf("arp packet for unknown gateway. can't do anything\n");
		return;
	}

    if(ntohs(incoming_arp->ar_op) == arp_op_request)
    {
    	printf("got an incoming arp request\n");

		/*now that you have the mac for the ip, make a reply*/
		int reply_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
		uint8_t *reply = malloc(reply_size);

		/*get info about the incoming interface for source info*/
		struct sr_if *incoming_info = sr_get_interface(sr, incoming_interface);

		/*Assemble ethernet header.*/
		sr_ethernet_hdr_t *reply_eheader = (sr_ethernet_hdr_t*) reply;
		memcpy(reply_eheader->ether_dhost, incoming_eth->ether_shost, 6);
		memcpy(reply_eheader->ether_shost, sr_get_interface(sr, incoming_interface)->mac, 6);
		reply_eheader->ether_type = incoming_eth->ether_type;

		/* Assemble arp header*/
		sr_arp_hdr_t *reply_arp = (sr_arp_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t));
		reply_arp->ar_hardware_type = incoming_arp->ar_hardware_type;
		reply_arp->ar_protocol_type = incoming_arp->ar_protocol_type;
		reply_arp->ar_mac_addr_len = incoming_arp->ar_mac_addr_len;
		reply_arp->ar_ip_addr_len = incoming_arp->ar_ip_addr_len;
		reply_arp->ar_op = htons(arp_op_reply);
		memcpy(reply_arp->ar_src_mac, sr_get_interface(sr, incoming_interface)->mac, 6);
		reply_arp->ar_src_ip = incoming_info->ip;
		memcpy(reply_arp->ar_dest_mac, incoming_arp->ar_src_mac, 6);
		reply_arp->ar_dest_ip = incoming_arp->ar_src_ip;

		/*Print what's in the reply before sending it*/
		printf("the reply\n");
		print_hdrs(reply, reply_size);

		/*send it*/
		int result = sr_send_packet(sr, reply, reply_size, incoming_interface);
		if (result != 0)
		{
			fprintf(stderr, "error has occurred sending the packet.\n");
		}
		free(reply);
    }
    else if (ntohs(incoming_arp->ar_op) == arp_op_reply)
    {
    	printf("got an incoming arp reply\n");

    	/*BLINDLY add it to the arp cache*/
		struct sr_arpreq *arp_reply_backlog;
		arp_reply_backlog = sr_arpcache_insert(&(sr->cache), incoming_arp->ar_src_mac, incoming_arp->ar_src_ip);

		/*straight up copy and paste from ar_op == arp_op_request*/
		/*only process the backlog if there is one. otherwise backlog->packet will give a memory read exception*/
		if(arp_reply_backlog != NULL)
		{
			/*process the backlog of packets based on its type*/
			struct sr_packet *backlog_packet = arp_reply_backlog->packets;
			while (backlog_packet != NULL)
			{
				sr_ethernet_hdr_t *backlog_eheader = (sr_ethernet_hdr_t*)(backlog_packet->buf);
				memcpy(backlog_eheader->ether_dhost, incoming_arp->ar_src_mac, 6);
				memcpy(backlog_eheader->ether_shost, sr_get_interface(sr, backlog_packet->iface), 6)
				printf("sending out backlog packet: \n");
				print_hdrs(backlog_packet->buf, backlog_packet->len);
				sr_send_packet(sr, backlog_packet->buf, backlog_packet->len, backlog_packet->iface);

				backlog_packet = backlog_packet->next;
			}
			/*backlog has been completed, get rid of this request*/
			sr_arpreq_destroy(&(sr->cache), arp_reply_backlog);
		}
    }
}

/* Takes an IP packet and deals with it */
void handle_ip(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, bool flag) {
    
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

	print_hdr_ip((uint8_t*)ip_header);
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
            break;
        }
        node = node->next;
    }
    
    if (flag) {
        if (ip_header->ip_ttl > 1) {
            fprintf(stdout, "TTL Decremented\n");
            ip_header->ip_ttl = ip_header->ip_ttl - 1;
            ip_header->ip_sum = 0;
            ip_header->ip_sum = cksum(ip_header, ip_header->ip_hl * 4);
        }
        else{
            fprintf(stdout, "TTL EXCEEDED!!!!!!!!!!!!!!!!\n");
            send_icmp(sr, interface, packet, ip_header,len, ICMP_TIME_EXCEEDED, ICMP_ECHO_REPLY);
        }
    }



    if (node != NULL) {
        uint8_t ip_type = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
        /* Get ICMP header */
        sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
        switch (ip_type) {
            
            case ip_protocol_tcp:
            case ip_protocol_udp:
                
                fprintf(stdout,"Recieved TCP or UDP Packet. Sending 'ICMP: Port Unreachable' to Source. \n");
                send_icmp(sr, interface, packet, ip_header, len, ICMP_UNREACHABLE, ICMP_UNREACHABLE);
                
                break;
                
            case ip_protocol_icmp:
                
				ethernet_header = (sr_ethernet_hdr_t *)packet;


                if (icmp_header->icmp_type == ICMP_ECHO_REQ) {

					/* Performance hax? Modifies the 0,0 icmp and sends it back */

                    memcpy(ethernet_header->ether_dhost, ethernet_header->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
                    memcpy(ethernet_header->ether_shost, sr_get_interface(sr, interface)->mac, sizeof(uint8_t)*ETHER_ADDR_LEN);
                    
                    /* update ICMP Header from current packet */
                    icmp_header->icmp_type = ICMP_ECHO_REPLY;
                    icmp_header->icmp_code = 0;
                    icmp_header->icmp_sum = 0;
                    icmp_header->icmp_sum = cksum(icmp_header, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
                    
                    /* update IP header from current packet*/
                    ip_header->ip_sum = 0;
                    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
                    uint32_t new_dest = ip_header->ip_src;
                    ip_header->ip_src = ip_header->ip_dst;
                    ip_header->ip_dst = new_dest;
                    sr_arpcache_queuereq(&sr->cache, ip_header->ip_dst, packet, len, interface);
                    sr_send_packet(sr, packet, len, interface);
                }
                break;
    
    
            default:
                fprintf(stdout,"Recieved unknown ICMP message type.\n");
                break;
        }
        return;
    }
    else {
        fprintf(stdout,"The packet wasn't directed to this router\n");
        struct sr_rt *prefix_match = longest_prefix_match(sr, ip_header->ip_dst);
        
        if (prefix_match){
            fprintf(stdout,"longest prefix match found\n");
            struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, prefix_match->gw.s_addr);
            
            if (entry){
                struct sr_if *interface = sr_get_interface(sr, prefix_match->interface);
                
                /* Make ethernet header */
                sr_ethernet_hdr_t *reply_ethernet_header = (sr_ethernet_hdr_t *)packet;
                memcpy(reply_ethernet_header->ether_dhost, entry->mac, sizeof(unsigned char)*6);
                memcpy(reply_ethernet_header->ether_shost, interface->mac, sizeof(uint8_t)*ETHER_ADDR_LEN);
                reply_ethernet_header->ether_type = ethernet_header->ether_type;
                
               /* print_hdrs(packet, len);*/
                sr_send_packet(sr, packet, len, interface->name);
                free(entry);
            } else {
                fprintf(stdout,"ARP Cache miss\n");
                prepare_arp(sr, packet, len, interface);
                sr_arpcache_queuereq(&(sr->cache), ip_header->ip_dst, packet, len, interface);
                
            }
        } else {
            fprintf(stdout,"No match. Sending ICMP net unreachable...\n");
            
            send_icmp(sr, interface, packet, ip_header,len, ICMP_UNREACHABLE, ICMP_ECHO_REPLY);
        }
    
    }
    return;
}

/* Finds excuses to get rid of an IP packet */
int sanity_check(sr_ip_hdr_t *ip_header) {

	uint16_t received_checksum = ip_header->ip_sum;
	ip_header->ip_sum = 0;
	uint16_t computed_checksum = cksum(ip_header, ip_header->ip_hl * 4);

	printf("Original CS: %d\n", received_checksum);
	printf("Computed CS: %d\n", computed_checksum);


	if (received_checksum != computed_checksum) {
		fprintf(stderr, "checksum does not match, dropping packet\n");
		return 1;
	}

	fprintf(stdout, "Sanity Checks Passed\n");
	return 0;
}

/* longest prefix match lookup...please fuckin work */
struct sr_rt *longest_prefix_match(struct sr_instance *sr, uint32_t ipdest)
{
    /* -- REQUIRES -- */
    assert(sr);
    
    if(sr->routing_table == 0){
        printf("No entries in routing table. Dropping packet\n");
        return NULL;
    }
    
    int len = 0;
    struct sr_rt *entry = 0;
    struct sr_rt *lprefix = 0;
    
    entry = sr->routing_table;
    while(entry != NULL){
        if ((ipdest & entry->mask.s_addr) == (entry->dest.s_addr & entry->mask.s_addr)){
            if((entry->mask.s_addr & ipdest) > len){
                lprefix = entry;
                len = (entry->mask.s_addr & ipdest);
            }
        }
        entry = entry->next;
    }
    return lprefix;
}

/* sends ICMP message for net unreachable */

void send_icmp(struct sr_instance* sr, char* interface, uint8_t * packet, sr_ip_hdr_t *ip_header,unsigned int len, int type, int code) {
    /* REQUIRES */
    assert(sr);
    assert(interface);
    assert(packet);
    
    printf("************************************************************************ -> Received ICMP REQ with type %d and code %d \n", type,code);
    
	int size = 0;
	if (type == ICMP_UNREACHABLE) {
		size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	}
	else {
		size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
	}
    
    uint8_t *response_packet = malloc(size);
    
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;
    
    /* build ethernet header */
    sr_ethernet_hdr_t *response_ethernet_header = (sr_ethernet_hdr_t *)response_packet;
    memcpy(response_ethernet_header->ether_dhost, ethernet_header->ether_shost, sizeof(sr_ethernet_hdr_t));
    memcpy(response_ethernet_header->ether_shost, ethernet_header->ether_dhost, sizeof(sr_ethernet_hdr_t));
    response_ethernet_header->ether_type = htons(ethertype_ip);
    
    
    /* build IP header */
    sr_ip_hdr_t *response_ip_header = (sr_ip_hdr_t *)(response_packet + sizeof(sr_ethernet_hdr_t));
    response_ip_header->ip_v = 4;
    response_ip_header->ip_hl = sizeof(sr_ip_hdr_t)/4;
    response_ip_header->ip_tos = 0;
    response_ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    response_ip_header->ip_id = htons(0);
    response_ip_header->ip_off = htons(IP_DF);
    response_ip_header->ip_ttl = 64;
    response_ip_header->ip_dst = ip_header->ip_src;
    response_ip_header->ip_p = ip_protocol_icmp;
    response_ip_header->ip_src = sr_get_interface(sr, interface)->ip;
    response_ip_header->ip_sum = 0;
    response_ip_header->ip_sum = cksum(response_ip_header, sizeof(sr_ip_hdr_t));
    
    /* build ICMP Header */

	if (type == ICMP_UNREACHABLE) {
		sr_icmp_t3_hdr_t *response_icmp_header = (sr_icmp_t3_hdr_t *)(response_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		response_icmp_header->icmp_type = ICMP_UNREACHABLE;
		response_icmp_header->icmp_code = code;
		response_icmp_header->unused = 0;
		response_icmp_header->next_mtu = 0; 
		response_icmp_header->icmp_sum = 0;
		memcpy(response_icmp_header->data, ip_header, ICMP_DATA_SIZE);
		response_icmp_header->icmp_sum = cksum(response_icmp_header, sizeof(sr_icmp_t3_hdr_t));
	}
	else
	{
		sr_icmp_hdr_t *response_icmp_header = (sr_icmp_hdr_t *)(response_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		response_icmp_header->icmp_type = type;
		response_icmp_header->icmp_code = code;
		response_icmp_header->icmp_sum = 0;
		memcpy(response_icmp_header->data, ip_header, ICMP_DATA_SIZE);
		response_icmp_header->icmp_sum = cksum(response_icmp_header, sizeof(sr_icmp_hdr_t));
	}
    
    if (type == ICMP_TIME_EXCEEDED){
        struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, response_ip_header->ip_dst);
        if (entry) {
            sr_send_packet (sr, response_packet, size, interface);
            free(response_packet);
        } else {
        	prepare_arp(sr, packet, len, interface);
              sr_arpcache_queuereq(&sr->cache, response_ip_header->ip_dst, packet, len, interface);
        }
        

    }

    else{
    sr_send_packet (sr, response_packet, size, interface);
    free(response_packet);
    }

}

/*generates an arp request for the packet and asks handle_arp to take care of it*/
void prepare_arp(struct sr_instance *sr, uint8_t *packet, int length, char *interface)
{
	   sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t*)packet;
	   uint8_t mac_unknown[6] = {0, 0, 0, 0, 0, 0};

	   /*get source and destination based on packet type*/
	   uint32_t source = 0, dest = 0;
	   if(ntohs(eth_header->ether_type) == ethertype_ip)
	   {
		   sr_ip_hdr_t *orig_ipheader = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
		   source = orig_ipheader->ip_src;
		   dest = orig_ipheader->ip_dst;
	   }
	   else /*if(ntohs(orig_eheader->ether_type) = ethertype_arp)*/
	   {
		   sr_arp_hdr_t *orig_arpheader = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
		   source = orig_arpheader->ar_src_ip;
		   dest = orig_arpheader->ar_dest_ip;
	   }

	   /**
	   	   The source of this request IS WRONG. That's ok. This function isn't doing longest prefix
	   	   match. handle_arp which is called at the end will fix up this arp request before sending it
	    */
	   int arp_request_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	   uint8_t *arp_request = malloc(arp_request_size);
	   sr_ethernet_hdr_t *request_eheader = (sr_ethernet_hdr_t*)arp_request;
	   sr_arp_hdr_t *request_aheader = (sr_arp_hdr_t*)(arp_request + sizeof(sr_ethernet_hdr_t));

	   /*copy the ethernet header*/
	   memcpy(request_eheader, eth_header, sizeof(sr_ethernet_hdr_t));
	   uint8_t mac_broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	   memcpy(request_eheader->ether_dhost, mac_broadcast, 6); /*make sure it is sent to the broadcast mac*/
	   request_eheader->ether_type = htons(ethertype_arp);

	   /*make the arp request*/
	   request_aheader->ar_hardware_type = htons(arp_hdr_ethernet);
	   request_aheader->ar_protocol_type = htons(arp_hdr_ip);
	   request_aheader->ar_mac_addr_len = 6;
	   request_aheader->ar_ip_addr_len = 4;
	   request_aheader->ar_op = htons(arp_op_request);
	   memcpy(request_aheader->ar_src_mac, eth_header->ether_shost, 6);
	   request_aheader->ar_src_ip = source;
	   memcpy(request_aheader->ar_dest_mac, mac_unknown, 6);
	   request_aheader->ar_dest_ip = dest;

	   printf("helper function arp request headers\n");
	   print_hdrs(arp_request, arp_request_size);

	   /*send the arp request for the first packet from the interface it came from*/
	   handle_arp(sr, arp_request, arp_request_size, interface, true);
	   free(arp_request);
}
