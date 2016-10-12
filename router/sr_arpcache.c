#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr)
{
   struct sr_arpreq *request = sr->cache.requests;
   struct sr_arpreq *next;
   while(request != NULL)
   {
	   next = request->next; /*DT*save the next right away just in case the request disappears because it was too many times*/
	   time_t now = time(NULL); /*DT* in seconds since new years 1970*/
	   time_t diff = now - request->sent; /*OH* supposed to be "now -" not "now =" right? /

	   if(request->times_sent >= 5)
	   {
		   struct sr_packet *failed_packet = request->packets;
		   while(failed_packet != NULL)
		   {
			   /*DT*make original packet internals easily accessible*/
			   sr_ethernet_hdr_t *orig_eheader = failed_packet->buf;
			   sr_ip_hdr_t *orig_ipheader = failed_packet->buf + sizeof(sr_ethernet_hdr_t);

			   /*DT*create icmp fail and make its internals easily accessible*/
			   int fail_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
			   uint8_t *fail = malloc(fail_length);
			   sr_ethernet_hdr_t *fail_eheader = fail;
			   sr_ip_hdr_t *fail_ipheader = fail + sizeof(sr_ethernet_hdr_t);
			   sr_icmp_t3_hdr_t*fail_icmp = fail + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);

			   /*DT*fill in ethernet header*/
			   memcpy(fail_eheader->ether_dhost, orig_eheader->ether_shost, 6);
			   memcpy(fail_eheader->ether_shost, whats_my_mac(sr, failed_packet->iface), 6);
			   fail_eheader->ether_type = htons(ethertype_ip);

			   /*DT*fill in ip header*/
			   fail_ipheader->ip_tos = 0;
			   fail_ipheader->ip_len = htons(fail_length - sizeof(sr_ethernet_hdr_t)); /*DT*everything but the ethernet header*/
			   fail_ipheader->ip_id = 0;
			   fail_ipheader->ip_off = 0;
			   fail_ipheader->ip_ttl = 64;
			   fail_ipheader->ip_p = ip_protocol_icmp;
			   fail_ipheader->ip_src = whats_my_ip(sr, failed_packet->iface);
			   fail_ipheader->ip_dst = orig_ipheader->ip_src;
			   fail_ipheader->ip_sum = 0; /*zero out before calculating*/
			   uint16_t ip_checksum = cksum(fail_ipheader, sizeof(sr_ip_hdr_t));
			   fail_ipheader->ip_sum = htons(ip_checksum);

			   /*DT* fill in the icmp stuff*/
			   /*DT* wikipedia: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol */
			   fail_icmp->icmp_type = 3;
			   fail_icmp->icmp_code = 1;
			   fail_icmp->unused = 0; /*DT* zero out to make sure old heap garbage doesn't screw this up */
			   fail_icmp->next_mtu = 0; /*DT* according to wikipedia, you only fill this in for code 4*/
			   bzero(fail_icmp->data, 28); /*zero out the data area to guarantee any unused space is zero padding*/
			   memcpy(fail_icmp->data, fail_ipheader, sizeof(sr_ip_hdr_t));
			   fail_icmp->icmp_sum = 0;
			   uint16_t icmp_checksum = cksum(fail_icmp, sizeof(sr_icmp_t3_hdr_t));
			   fail_icmp->icmp_sum = htons(icmp_checksum);

			   sr_send_packet(sr, fail, fail_length, failed_packet->iface);

			   failed_packet = failed_packet->next;
		   }
		   sr_arpreq_destroy(sr, request); /*DT* this request is hopeless. failures have been sent. get rid of it*/
	   }
	   else if(diff >= 1)
	   {
		   /*update the counters*/
		   request->sent = now;
		   request->times_sent++;

		   /*all destination ips will be the same for an arp request since there can be only 1 ip/mac pairing*/
		   /*just pull the destination ip from the first packet*/
		   struct sr_packet *first_packet = request->packets;
		   sr_ethernet_hdr_t *first_eheader = first_packet->buf;
		   sr_ip_hdr_t *first_ipheader = first_packet->buf + sizeof(sr_ethernet_hdr_t);
		   uint8_t mac_unknown[6] = {0, 0, 0, 0, 0, 0};

		   /**
		    * This request is actually for the first packet. While each ip packet in this arp request is for
		    * the same destination they could all have different sources. However a source must be filled in for
		    * the request. Therefore the response will be for the first packet in the requests. HOWEVER, the other
		    * packets in the request will be answered by sr_handlepacket because when the ip/mac pairing is inserted
		    * into the cache, sr_handlepacket will get the packet Q waiting for this pairing. sr_handlepacket will
		    * then proceed to sending out all the rest of the answers.
		    */
		   int request_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
		   uint8_t request = malloc(request_size);
		   sr_ethernet_hdr_t *request_eheader = request;
		   sr_arp_hdr_t *request_aheader = request + sizeof(sr_ethernet_hdr_t);

		   /*copy the ethernet header*/
		   memcpy(request_eheader, first_eheader, sizeof(sr_ethernet_hdr_t)); /*OH* Segfault*/
		   uint8_t mac_broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
		   memcpy(request_eheader->ether_dhost, mac_broadcast, 6); /*make sure it is sent to the broadcast mac*/

		   /*make the arp request*/
		   request_aheader->ar_hardware_type = htons(arp_hdr_ethernet);
		   request_aheader->ar_protocol_type = htons(arp_hdr_ip);
		   request_aheader->ar_mac_addr_len = 6;
		   request_aheader->ar_ip_addr_len = 4;
		   request_aheader->ar_op = htons(arp_op_request);
		   memcpy(request_aheader->ar_src_mac, first_eheader->ether_shost, 6);
		   request_aheader->ar_src_ip = first_ipheader->ip_src;
		   memcpy(request_aheader->ar_dest_mac, mac_unknown, 6);
		   request_aheader->ar_dest_ip = first_ipheader->ip_dst;

		   /*send the arp request for the first packet from the interface it came from*/
		   sr_send_packet(sr, request, request_size, first_packet->iface);
	   }
	   else
	   {
		   printf("difference is less than 1 (%d). it's too soon to try again\n", diff);
	   }
	   request = next;
   }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) { /*OH* This is effectively a count to 100 when there's nothing to process*/
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

