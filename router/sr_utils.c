#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_router.h"


uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}





uint32_t tcp_cksum(sr_ip_hdr_t *ipHdr, sr_tcp_hdr_t *tcpHdr, int total_len) {
    
    uint8_t *full_tcp;
    sr_tcp_psuedo_hdr_t *tcp_psuedo_hdr;
    
    int tcp_len = total_len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    int full_tcp_len = sizeof(sr_tcp_psuedo_hdr_t) + tcp_len;
    
    tcp_psuedo_hdr = malloc(sizeof(sr_tcp_psuedo_hdr_t));
    memset(tcp_psuedo_hdr, 0, sizeof(sr_tcp_psuedo_hdr_t));
    
    tcp_psuedo_hdr->ip_src = ipHdr->ip_src;
    tcp_psuedo_hdr->ip_dst = ipHdr->ip_dst;
    tcp_psuedo_hdr->ip_p = ipHdr->ip_p;
    tcp_psuedo_hdr->tcp_len = htons(tcp_len);
    
    uint16_t currCksum = tcpHdr->checksum;
    tcpHdr->checksum = 0;
    
    full_tcp = malloc(sizeof(sr_tcp_psuedo_hdr_t) + tcp_len);
    memcpy(full_tcp, (uint8_t *) tcp_psuedo_hdr, sizeof(sr_tcp_psuedo_hdr_t));
    memcpy(&(full_tcp[sizeof(sr_tcp_psuedo_hdr_t)]), (uint8_t *) tcpHdr, tcp_len);
    tcpHdr->checksum = currCksum;
    
    uint16_t calcCksum = cksum(full_tcp, full_tcp_len);
    
    /* Clear out memory used for creation of complete tcp packet */
    free(tcp_psuedo_hdr);
    free(full_tcp);
    
    return calcCksum;
}


uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  if(ntohs(ehdr->ether_type) == ethertype_ip)
  {
	  fprintf(stderr, "\ttype: ip\n");
  }
  else if(ntohs(ehdr->ether_type) == ethertype_arp)
  {
	  fprintf(stderr, "\ttype: arp\n");
  }
  else
  {
	  fprintf(stderr, "\ttype UNKNOWN: %d\n", ntohs(ehdr->ether_type));
  }
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/*prints out just the source and destination addresses*/
void print_addrs(uint8_t *buf, uint32_t length)
{
	sr_ip_hdr_t *iphdr = (buf + sizeof(sr_ethernet_hdr_t));

	fprintf(stderr, "\tsource: ");
	print_addr_ip_int(ntohl(iphdr->ip_src));

	fprintf(stderr, "\tdestination: ");
	print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hardware_type));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_protocol_type));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_mac_addr_len);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_ip_addr_len);
  if(ntohs(arp_hdr->ar_op) == arp_op_request)
  {
	  fprintf(stderr, "\topcode: request\n");
  }
  else if(ntohs(arp_hdr->ar_op) == arp_op_reply)
  {
	  fprintf(stderr, "\topcode: reply\n");
  }
  else
  {
	  fprintf(stderr, "\topcode UNKNOWN: %d\n", ntohs(arp_hdr->ar_op));
  }

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_src_mac);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_src_ip));

  fprintf(stderr, "\tdestination hardware address: ");
  print_addr_eth(arp_hdr->ar_dest_mac);
  fprintf(stderr, "\tdestination ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_dest_ip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

/*DT* Returns the mac address of an interface*/
unsigned char* whats_my_mac(struct sr_instance *sr, char *interface)
{
	struct sr_if *list_entry = sr->if_list;
	while(list_entry != NULL)
	{
		if(strcmp(interface, list_entry->name) == 0)
		{
			return list_entry->mac;
		}
		list_entry = list_entry->next;
	}

	fprintf(stderr, "could not find a MAC address for interface name %s\n", interface);
	return NULL;
}

/*DT* Returns the ip of an interface*/
uint32_t whats_my_ip(struct sr_instance *sr, char *interface)
{
	struct sr_if *list_entry = sr->if_list;
	while(list_entry != NULL)
	{
		if(strcmp(interface, list_entry->name) == 0)
		{
			return list_entry->ip;
		}
		list_entry = list_entry->next;
	}

	fprintf(stderr, "could not find an IP address for interface name %s\n", interface);
	return 0;
}

char* ever_pointer(struct sr_instance *sr, char *interface)
{
	struct sr_if *list_entry = sr->if_list;
	while(list_entry != NULL)
	{
		if(strcmp(interface, list_entry->name) == 0)
		{
			return list_entry->name;
		}
		list_entry = list_entry->next;
	}

	fprintf(stderr, "interface %s doesn't exist\n", interface);
	return NULL;
}
