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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

 // Global
static uint32_t* crc32Lookup;
uint32_t crc32_bitwise(const void* data, size_t length, uint32_t previousCrc32);

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

	sr_ethernet_hdr_t *header = packet;

	sr_ip_hdr_t *iphdr = packet + sizeof(sr_ethernet_hdr_t);

	printf("source mac\n");
	print_addr_eth(header->ether_shost);
	printf("dest mac\n");
	print_addr_eth(header->ether_dhost);
	uint32_t *crc = packet + len - 4;
	printf("crc in decimal and hexadecimal, %d, %x\n", *crc, *crc); // I get the feeling they're not giving us the ethernet crc, struct is too small for it

	uint32_t ccrc = (crc32_bitwise(packet, len - 4, 0));
	//printf("crc in decimal and hexadecimal, %d, %x\n", ccrc, ccrc);
	uint16_t cccrc = cksum(packet, len - 4);
	//printf("crc in decimal and hexadecimal, %d, %x\n", cccrc, cccrc);


	uint16_t useable_type = ethertype(packet);

	switch (useable_type) {
	case ethertype_arp:
	{
		sr_arp_hdr_t *arpheader = (packet + sizeof(sr_ethernet_hdr_t));
		print_hdr_arp(arpheader);
		printf("arp request for ip: \n");
		struct sr_arpreq *result = sr_arpcache_queuereq(&(sr->cache), arpheader->ar_tip, packet, len, interface); /*not doing anything with the result currently*/
		break;
	}
	case ethertype_ip:
	{
		sr_ip_hdr_t *ipheader = (packet + sizeof(sr_ethernet_hdr_t));
		print_hdr_ip(ipheader);
		printf("got an ip packet\n");
	}
	default:
		printf("got something mysterious\n");

	}
}/* end sr_ForwardPacket */


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