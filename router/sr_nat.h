#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>

#define USEABLE_PORTS 64511

/*
 * Allocate ping sequences in "blocks" of 100. Since global ping seq usage changes with EACH reply, to figure
 * out if a sequence number is available you will need to update the sr_nat_mapping for every ping reply. (Annoying and error prone)
 * There might be a condition where a BOTH a sequence number is needed for a new stream of pings (ex 2016)
 * and an old ping stream reply was just send with seq 2016. If the new stream does the check first, it will see
 * 2016 as available. Then when the old ping stream is sent out, it will be a duplicate 2016.
 *
 * Allocate ping seq #s in blocks of 100 in hopes to avoid the race condition above by making the assumption nobody
 * will have a ping stream sequence of >100 pings. This way no sequences will overlap which means no need to update the usage table with each reply.
 * Also allows for 655 concurrent ping streams which should be enough for this sr.
 */
#define USEABLE_PING_BLOCKS 655 /*0-654*/
typedef enum
{
	nat_mapping_icmp,
	nat_mapping_tcp_old,
	nat_mapping_tcp_new
/* nat_mapping_udp, */
} sr_nat_mapping_type;

struct sr_nat_connection
{
	/* add TCP connection state data members here */

	struct sr_nat_connection *next;
};

struct sr_nat_mapping
{
	sr_nat_mapping_type type;
	uint32_t ip_int; /* internal ip addr */
	uint32_t ip_ext; /* external ip addr */
	uint16_t aux_int; /* internal port or icmp id */
	uint16_t aux_ext; /* external port or icmp id */
	time_t last_updated; /* use to timeout mappings */
	/*struct sr_nat_connection *conns*/;
	/* list of connections. null for ICMP */
	struct sr_nat_mapping *next;
};

struct sr_nat
{
	/* add any fields here */
	struct sr_nat_mapping *mappings;
	bool port_taken[USEABLE_PORTS]; /*65535-1024*/
	bool icmp_seq_block_taken[USEABLE_PING_BLOCKS];
    int icmp_ko;
    int tcp_old_ko;
    int tcp_new_ko;

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
