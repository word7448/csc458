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

  printf("*** -> Received packet of length %d \n",len);

  sr_ethernet_hdr_t *header = packet;
  printf("source mac\n");
  print_addr_eth(header->ether_shost);
  printf("dest mac\n");
  print_addr_eth(header->ether_dhost);
  switch(ethertype(packet))
  {
  case ethertype_arp:
	  sr_arp_hdr_t *arpheader = (packet + sizeof(sr_ethernet_hdr_t));
	  printf("arp request for ip: \n");
	  print_addr_ip(arpheader->ar_tip);
	  struct sr_arpreq *sr_arpcache_queuereq(sr->cache, arpheader->ar_tip, packet, len, interface); //not doing anything with the result currently
	  break;
  case ethertype_ip:
	  printf("got an ip packet\n");
	  break;
  default:
	  printf("got something mysterious\n");
	  break;
  }
  /* fill in code here */

}/* end sr_ForwardPacket */

