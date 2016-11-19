#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int sr_nat_init(struct sr_nat *nat, int icmp_ko, int tcp_new_ko, int tcp_old_ko)
{ /* Initializes the nat */

	assert(nat);

	/* Acquire mutex lock */
	pthread_mutexattr_init(&(nat->attr));
	pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
	int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

	/* Initialize timeout thread */

	pthread_attr_init(&(nat->thread_attr));
	pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
	pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

	/* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

	nat->mappings = NULL;
	nat->icmp_ko = icmp_ko;
	nat->tcp_new_ko = tcp_new_ko;
	nat->tcp_old_ko = tcp_old_ko;

	/*nothing is taken at the begining*/
	int i;
	for(i=0; i<USEABLE_PORTS; i++)
	{
		nat->port_taken[i] = false;
	}
	for(i=0; i<USEABLE_PING_BLOCKS; i++)
	{
		nat->icmp_seq_block_taken[i] = false;
	}
	return success;
}

int sr_nat_destroy(struct sr_nat *nat)
{ /* Destroys the nat (free memory) */

	pthread_mutex_lock(&(nat->lock));

	/* free nat memory here */

	pthread_kill(nat->thread, SIGKILL);
	return pthread_mutex_destroy(&(nat->lock)) && pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr)
{ /* Periodic Timout handling */
	struct sr_nat *nat = (struct sr_nat*) nat_ptr;
	while (1)
	{
		sleep(1.0);
		pthread_mutex_lock(&(nat->lock));

		time_t now = time(NULL);
		time_t diff;
		bool untouched = true;
		
		struct sr_nat_mapping *current = nat->mappings;
		struct sr_nat_mapping *previous = current;
		
		while (current != NULL)
		{
			diff = now - current->last_updated;
			if((current->type == nat_mapping_icmp) && (diff > nat->icmp_ko))
			{
				untouched = false;
				previous->next = current->next;
				nat->icmp_seq_block_taken[(current->aux_ext)/100] = false; /*just chops off the last 2 #s to get the sequence block*/
				free(current);
				current = previous->next;
			}
			else if((current->type == nat_mapping_tcp_old) && (diff > nat->tcp_old_ko))
			{
				untouched = false;
				previous->next = current->next;
				nat->port_taken[current->aux_ext+1024] = false;
				free(current);
				current = previous->next;
			}
			else if((current->type == nat_mapping_tcp_new) && (diff > nat->tcp_new_ko))
			{
				untouched = false;
				previous->next = current->next;
				nat->port_taken[current->aux_ext+1024] = false;
				free(current);
				current = previous->next;
			}

			/*only change both pointers if an entry was not removed.
			 * if an entry was removed then when it goes, the removed entry's next
			 * is the current. that means what is now "current" hasn't been inspected yet.
			 * don't skip over what' in "current"*/
			if(untouched)
			{
				previous = current;
				current = current->next;
			}
			untouched = true;
		}
		//printf("done nat cleanup for now\n");
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
	struct sr_nat_mapping *pointer = nat->mappings;

	while(pointer != NULL)
	{
		if(pointer->aux_ext == aux_ext && pointer->type == type)
		{
			pointer->last_updated = time(NULL);
			break;
			/*probably can't just do return because you have to unlock nat->lock*/
		}
		pointer = pointer->next;
	}

	pthread_mutex_unlock(&(nat->lock));
	return pointer;
}

/* Get the mapping associated with given internal (ip, port) pair.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type)
{

	pthread_mutex_lock(&(nat->lock));

	/* handle lookup here, malloc and assign to copy. */
	struct sr_nat_mapping *pointer = nat->mappings;

	while(pointer != NULL)
	{
		if(pointer->ip_int == ip_int && pointer->aux_int == aux_int && pointer->type == type)
		{
			pointer->last_updated = time(NULL);
			break;
			/*probably can't just do return because you have to unlock nat->lock*/
		}
		pointer = pointer->next;
	}
	pthread_mutex_unlock(&(nat->lock));
	return pointer;
}

/* Insert a new mapping into the nat's mapping table.
 Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type)
{

	pthread_mutex_lock(&(nat->lock));

	int external;
	if (type == nat_mapping_tcp_new) /*you're never going to be inserting an established/old tcp mapping*/
	{
		external = rand() % USEABLE_PORTS;
		while (nat->port_taken[external])
		{
			external = rand() % USEABLE_PORTS;
		}
		external = external + 1024;
	}
	else if (type == nat_mapping_icmp)
	{
		external = rand() % USEABLE_PING_BLOCKS;
		while (nat->icmp_seq_block_taken[external])
		{
			external = rand() % USEABLE_PING_BLOCKS;
		}
		external = external*100;
	}

	struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping));
	mapping->ip_int = ip_int;
	mapping->aux_int = aux_int;
	mapping->aux_ext = external;
	mapping->type = type;
	mapping->last_updated = time(NULL);
	mapping->next = nat->mappings; /*put the new one at the front of the list*/
	nat->mappings = mapping;

	pthread_mutex_unlock(&(nat->lock));
	return mapping;
}
