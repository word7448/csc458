#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>

#define USEABLE_EXTERNALS 64511

typedef enum
{
	nat_mapping_icmp,
    nat_mapping_tcp,
	nat_mapping_tcp_old,
	nat_mapping_tcp_new
/* nat_mapping_udp, */
} sr_nat_mapping_type;



typedef enum {
    tcp_state_closed,
    tcp_state_listen,
    tcp_state_syn_sent,
    tcp_state_syn_received,
    tcp_state_established,
    tcp_state_close_wait,
    tcp_state_last_ack,
    tcp_state_fin_wait_1,
    tcp_state_fin_wait_2,
    tcp_state_closing,
    tcp_state_time_wait
} sr_nat_tcp_state;



struct sr_nat_connection
{
	/* add TCP connection state data members here */

	struct sr_nat_connection *next;
    uint32_t isn_client;
    uint32_t isn_server;
    uint32_t ip;
    time_t last_update;
    sr_nat_tcp_state state;
};

struct sr_nat_mapping
{
	sr_nat_mapping_type type;
	uint32_t ip_int; /* internal ip addr */
	uint32_t ip_ext; /* external ip addr */
	uint16_t aux_int; /* internal port or icmp id */
	uint16_t aux_ext; /* external port or icmp id */
	time_t last_updated; /* use to timeout mappings */
	struct sr_nat_connection *conns; /* list of connections. null for ICMP */
	struct sr_nat_mapping *next;
};
struct sr_tcp_syn {
    uint32_t ip_src;
    uint16_t src_port;
    time_t last_received;
    
    uint8_t *packet;
    unsigned int len;
    char *interface;
    struct sr_tcp_syn *next;
};
struct sr_nat
{
	/* add any fields here */
	struct sr_nat_mapping *mappings;
	bool port_taken[USEABLE_EXTERNALS]; /*1024-65535*/
	bool icmp_id_taken[USEABLE_EXTERNALS]; /*1024-65535*/
    int icmp_ko;
    int tcp_old_ko;
    int tcp_new_ko;
    struct sr_tcp_syn *incoming;

	/* threading */
	pthread_mutex_t lock;
	pthread_mutexattr_t attr;
	pthread_attr_t thread_attr;
	pthread_t thread;
};

int sr_nat_init(struct sr_nat *nat, int icmp_ko, int tcp_new_ko, int tcp_old_ko);
int sr_nat_destroy(struct sr_nat *nat); /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *sr_ptr); /* Periodic Timout */

/* Get the mapping associated with given external port.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat, uint16_t aux_ext, sr_nat_mapping_type type);

/* Get the mapping associated with given internal (ip, port) pair.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type);

/* Insert a new mapping into the nat's mapping table.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type);

#endif
