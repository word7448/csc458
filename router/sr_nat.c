#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include "sr_router.h"

int sr_nat_init(struct sr_instance *sr)
{ /* Initializes the nat */

	assert(sr);
	struct sr_nat *nat = &(sr->the_nat);

	/* Acquire mutex lock */
	pthread_mutexattr_init(&(nat->attr));
	pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
	int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

	/* Initialize timeout thread */

	pthread_attr_init(&(nat->thread_attr));
	pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
	pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, sr);

	/* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

	nat->mappings = NULL;
	/* Initialize any variables here */

	return success;
}

int sr_nat_destroy(struct sr_nat *nat)
{ /* Destroys the nat (free memory) */

	pthread_mutex_lock(&(nat->lock));

	/* free nat memory here */

	pthread_kill(nat->thread, SIGKILL);
	return pthread_mutex_destroy(&(nat->lock)) && pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *sr_ptr)
{ /* Periodic Timout handling */
	struct sr_instance *sr = (struct sr_instance*) sr_ptr;
	struct sr_nat *nat = (struct sr_nat*) sr->the_nat;
	while (1)
	{
		sleep(1.0);
		pthread_mutex_lock(&(nat->lock));

		time_t now = time(NULL);
		time_t diff;
		
		struct sr_nat_mapping current = sr->the_nat->mappings;
		struct sr_nat_mapping previous = current;
		
		while (current != NULL)
		{
			diff = now - current->last_updated;
			if((current->type == nat_mapping_icmp) && (diff % sr->icmp_ko == 0))
			{

			}
			else if((current->type == nat_mapping_tcp_old) && (diff % sr->tcp_old_ko == 0))
			{
				
			}
			else if((current->type == nat_mapping_tcp_new) && (diff % sr->tcp_new_ko == 0))
			{
				
			}
			previous = current;
			current = current->next;
		}

		pthread_mutex_unlock(&(nat->lock));
	}
	return NULL;
}

/* Get the mapping associated with given external port.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat, uint16_t aux_ext, sr_nat_mapping_type type)
{

	pthread_mutex_lock(&(nat->lock));

	/* handle lookup here, malloc and assign to copy */
	struct sr_nat_mapping *copy = NULL;

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type)
{

	pthread_mutex_lock(&(nat->lock));

	/* handle lookup here, malloc and assign to copy. */
	struct sr_nat_mapping *copy = NULL;

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

/* Insert a new mapping into the nat's mapping table.
 Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type)
{

	pthread_mutex_lock(&(nat->lock));

	/* handle insert here, create a mapping, and then return a copy of it */
	struct sr_nat_mapping *mapping = NULL;

	pthread_mutex_unlock(&(nat->lock));
	return mapping;
}
