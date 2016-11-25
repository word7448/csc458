#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include "sr_utils.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_router.h"

int sr_nat_init(void *sr_ptr, int icmp_ko, int tcp_new_ko, int tcp_old_ko)
{ /* Initializes the nat */

	assert(sr_ptr);
	struct sr_instance *sr = (struct sr_instance*)sr_ptr;
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
	nat->icmp_ko = icmp_ko;
	nat->tcp_new_ko = tcp_new_ko;
	nat->tcp_old_ko = tcp_old_ko;

	/*nothing is taken at the begining*/
	int i;
	for(i=0; i<USEABLE_EXTERNALS; i++)
	{
		nat->port_taken[i] = false;
	}
	for(i=0; i<USEABLE_EXTERNALS; i++)
	{
		nat->icmp_id_taken[i] = false;
	}
	return success;
}

int sr_nat_destroy(struct sr_nat *nat)
{ /* Destroys the nat (free memory) */

	pthread_mutex_lock(&(nat->lock));

	/*remove the mapping*/
	struct sr_nat_mapping *current_mapping = nat->mappings;
	struct sr_nat_mapping *previous_mapping = current_mapping;
	while(current_mapping != NULL)
	{
		/*reset the "taken" array*/
		if(current_mapping->type == nat_mapping_icmp)
		{
			nat->icmp_id_taken[ntohs(current_mapping->aux_ext)-1024] = false;
		}
		else
		{
			nat->port_taken[ntohs(current_mapping->aux_ext)-1024] = false;
		}

		/*remove the mapping's connection and then itself*/
		previous_mapping = current_mapping;
		current_mapping = current_mapping->next;
		remove_nat_connections(previous_mapping->conns);
		free(previous_mapping);
	}
	nat->mappings = NULL;

	/*remove the sr_tcp_syn*/
	struct sr_tcp_syn *current_syn = nat->incoming;
	struct sr_tcp_syn *previous_syn = current_syn;
	while(current_syn != NULL)
	{
		previous_syn = current_syn;
		current_syn = current_syn->next;
		free(previous_syn->packet); /*still using ever pointer for interface name so don't have to free it*/
		free(previous_syn);
	}
	nat->incoming = NULL;

	pthread_kill(nat->thread, SIGKILL);
	return pthread_mutex_destroy(&(nat->lock)) && pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *sr_ptr)
{ /* Periodic Timout handling */
	struct sr_instance *sr = (struct sr_instance*)sr_ptr;
	struct sr_nat *nat = &(sr->the_nat);
	while (1)
	{
		sleep(1.0);
		pthread_mutex_lock(&(nat->lock));

		time_t now = time(NULL);
		time_t diff;
		bool untouched = true;
		
		struct sr_nat_mapping *current = nat->mappings;
		struct sr_nat_mapping *previous = NULL;
		
		while (current != NULL)
		{
			bool head_mode = false;
			if(previous == NULL)
			{
				/*head of the list requires special treatment
				 * the normal "splice out the middle" doesn't work on the head because it isn't in the middle*/
				head_mode = true;
			}
			diff = now - current->last_updated;
			if ((current->type == nat_mapping_icmp) && (diff > nat->icmp_ko))
			{
				printf("NAT: Removing ICMP mapping of internal identifier %d (%d) to external identifier %d (%d)\n", current->aux_int, ntohs(current->aux_int), current->aux_ext, ntohs(current->aux_ext));
				untouched = false;
				if (head_mode)
				{/*for the head of the list, replace the actual head of the_nat->mappings*/
					nat->mappings = current->next;
				}
				else
				{/*for an entry that is in the middle of the list, splice it out*/
					previous->next = current->next;
				}
				nat->icmp_id_taken[ntohs(current->aux_ext) - 1024] = false;
				remove_nat_connections(current->conns);
				free(current);
				if (head_mode)
				{
					/*for the head of the list, the next thing you're going to inspect is... the head of the list again,
					 * but this time it's a different head. set everything up for "head_mode again" just like before the while loop started*/
					current = nat->mappings;
					previous = NULL;
				}
				else
				{
					/*for the middle of the list the next thing you're inspecting is the deleted entry's next
					 * because the deleted entry was spliced out, its next is right after the "previous"*/
					current = previous->next;
				}
			}
			else if ((current->type == nat_mapping_tcp_old) && (diff > nat->tcp_old_ko))
			{
				printf("NAT: Removing OLD tcp mapping of internal port %d (%d) to external port %d (%d)\n", current->aux_int, ntohs(current->aux_int), current->aux_ext, ntohs(current->aux_ext));
				untouched = false;
				if (head_mode)
				{/*for the head of the list, replace the actual head of the_nat->mappings*/
					nat->mappings = current->next;
				}
				else
				{/*for an entry that is in the middle of the list, splice it out*/
					previous->next = current->next;
				}
				nat->port_taken[ntohs(current->aux_ext) - 1024] = false;
				remove_nat_connections(current->conns);
				free(current);
				if (head_mode)
				{
					/*for the head of the list, the next thing you're going to inspect is... the head of the list again,
					 * but this time it's a different head. set everything up for "head_mode again" just like before the while loop started*/
					current = nat->mappings;
					previous = NULL;
				}
				else
				{
					/*for the middle of the list the next thing you're inspecting is the deleted entry's next
					 * because the deleted entry was spliced out, its next is right after the "previous"*/
					current = previous->next;
				}
			}
			else if (((current->type == nat_mapping_tcp_new_s1 ) || (current->type == nat_mapping_tcp_new_s2 ) || (current->type == nat_mapping_tcp_new_s3))
						&& (diff > nat->tcp_new_ko))
			{
				printf("NAT: Removing NEW tcp mapping (%s) of internal port %d (%d) to external port %d (%d)\n", get_nat_type(current->type), current->aux_int, ntohs(current->aux_int), current->aux_ext, ntohs(current->aux_ext));
				untouched = false;
				if (head_mode)
				{/*for the head of the list, replace the actual head of the_nat->mappings*/
					nat->mappings = current->next;
				}
				else
				{/*for an entry that is in the middle of the list, splice it out*/
					previous->next = current->next;
				}
				nat->port_taken[ntohs(current->aux_ext) - 1024] = false;
				remove_nat_connections(current->conns);
				free(current);
				if (head_mode)
				{
					/*for the head of the list, the next thing you're going to inspect is... the head of the list again,
					 * but this time it's a different head. set everything up for "head_mode again" just like before the while loop started*/
					current = nat->mappings;
					previous = NULL;
				}
				else
				{
					/*for the middle of the list the next thing you're inspecting is the deleted entry's next
					 * because the deleted entry was spliced out, its next is right after the "previous"*/
					current = previous->next;
				}
			}
			else if ((current->type == nat_mapping_tcp_unsolicited) && (diff > 6))
			{
				printf("NAT: sending out unsolicited tcp response\n");
				untouched = false;
				if(head_mode)
				{
					nat->mappings = current->next;
				}
				else
				{
					previous->next = current->next;
				}

				/*send icmp t3 code3*/
				/*assemble the bare minimum to use send_icmp*/
				int size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
				sr_ethernet_hdr_t *original = (sr_ethernet_hdr_t*)current->orig_ether_ip;
				sr_ethernet_hdr_t *macs = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t));
				bzero(macs, sizeof(sr_ethernet_hdr_t));
				memcpy(macs->ether_shost, sr_get_interface(sr, "eth2")->mac, 6);
				memcpy(macs->ether_dhost, original->ether_shost, 6);
				sr_ip_hdr_t *original_ip = (sr_ip_hdr_t*)(current->orig_ether_ip+sizeof(sr_ethernet_hdr_t));
				send_icmp(sr, "eth2", (uint8_t*)macs, original_ip, size, ICMP_UNREACHABLE, 3, 0);

				free(current->orig_ether_ip); /*the only time this field is used*/
				free(current);
				if (head_mode)
				{
					/*for the head of the list, the next thing you're going to inspect is... the head of the list again,
					 * but this time it's a different head. set everything up for "head_mode again" just like before the while loop started*/
					current = nat->mappings;
					previous = NULL;
				}
				else
				{
					/*for the middle of the list the next thing you're inspecting is the deleted entry's next
					 * because the deleted entry was spliced out, its next is right after the "previous"*/
					current = previous->next;
				}
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
		pthread_mutex_unlock(&(nat->lock));
	}
	return NULL;
}

void remove_nat_connections(struct sr_nat_connection *conn)
{
	struct sr_nat_connection *current = conn;
	struct sr_nat_connection *previous = conn;

	while(current != NULL)
	{
		previous = current;
		current = current->next;
		free(previous);
	}
}
/* Get the mapping associated with given external port.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat, uint16_t aux_ext, sr_nat_mapping_type type)
{

	pthread_mutex_lock(&(nat->lock));
	printf("NAT: got an external nat request; looking for type %s for external port/identifier %d (%d)\n", get_nat_type(type), aux_ext, ntohs(aux_ext));

	/* handle lookup here, malloc and assign to copy */
	struct sr_nat_mapping *pointer = nat->mappings;

	while(pointer != NULL)
	{
		printf("NAT: inspecting aux-external %d (%d), type %s\n", pointer->aux_ext, ntohs(pointer->aux_ext), get_nat_type(pointer->type));
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

	printf("NAT: got an internal nat request; looking for type %s for internal port/identifier %d (%d) for ip:\n", get_nat_type(type), aux_int, ntohs(aux_int));
	print_addr_ip_int(ip_int);

	/* handle lookup here, malloc and assign to copy. */
	struct sr_nat_mapping *pointer = nat->mappings;

	while(pointer != NULL)
	{
		printf("NAT: inspecting aux-internal %d (%d), type %s, ip:\n", pointer->aux_int, ntohs(pointer->aux_int), get_nat_type(pointer->type));
		print_addr_ip_int(pointer->ip_int);
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
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type, uint8_t *original)
{

	pthread_mutex_lock(&(nat->lock));

	/*setup mapping struct*/
	struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping));
	bzero(mapping, sizeof(struct sr_nat_mapping));
	mapping->last_updated = time(NULL);

	int external = 0;

	/*the normal case of making a mapping*/
	if (type == nat_mapping_tcp_new_s1 || type == nat_mapping_icmp)
	{
		if (type == nat_mapping_tcp_new_s1) /*you're never going to be inserting an established/old tcp mapping*/
		{
			external = rand() % USEABLE_EXTERNALS;
			while (nat->port_taken[external])
			{
				external = rand() % USEABLE_EXTERNALS;
			}
			nat->port_taken[external] = true;
			printf("NAT: Inserting new tcp nat mapping for internal port %d (%d) on external port %d\n", aux_int, ntohs(aux_int), external);
		}
		else if (type == nat_mapping_icmp)
		{
			external = rand() % USEABLE_EXTERNALS;
			while (nat->icmp_id_taken[external])
			{
				external = rand() % USEABLE_EXTERNALS;
			}
			nat->icmp_id_taken[external] = true;
			printf("NAT: Inserting ICMP nat mapping for internal identifier %d (%d) on external identifier %d\n", aux_int, ntohs(aux_int), external);
		}
		external = external + 1024;

		mapping->ip_int = ip_int;
		mapping->aux_int = aux_int;
		mapping->aux_ext = htons(external);
		mapping->type = type;
		mapping->next = nat->mappings; /*put the new one at the front of the list*/
		nat->mappings = mapping;
	}
	/*the hacky unusual case of making a nat entry to store the unsolicited syn information*/
	else if (type == nat_mapping_tcp_unsolicited)
	{
		printf("NAT: Inserting tcp unsolicited hacky mapping for \"Internal\" %d (%d)\n", aux_int, ntohs(aux_int));
		int partial_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
		mapping->type = nat_mapping_tcp_unsolicited;

		/*
		 * using internal ip and aux because an unsolicited syn is a tcp handshake stage 2.
		 * it will have no external mapping because there was no stage 1 from lan --> which would've setup the mapping.
		 * unsoliciteds need to be looked up by host and port to check for 1st, 2nd etc offense.
		 * nat_internal_lookup takes ip and aux so use that to check for previous offenses.
		 */
		mapping->ip_int = ip_int; /*really the external address but to use internal lookup it's stored on ip_int*/
		mapping->aux_int = aux_int;
		mapping->orig_ether_ip = malloc(partial_size);
		memcpy(mapping->orig_ether_ip, original, partial_size);
		nat->mappings = mapping;
	}


	pthread_mutex_unlock(&(nat->lock));
	return mapping;
}

const char* get_nat_type(sr_nat_mapping_type nat_type)
{
	switch(nat_type)
	{
	case nat_mapping_icmp: return "nat_mapping_icmp";
	case nat_mapping_tcp_unsolicited: return "nat_mapping_tcp_unsolicited";
	case nat_mapping_tcp_old: return "nat_mapping_tcp_old";
	case nat_mapping_tcp_new_s1: return "nat_mapping_tcp_new_s1";
	case nat_mapping_tcp_new_s2: return "nat_mapping_tcp_new_s2";
	case nat_mapping_tcp_new_s3: return "nat_mapping_tcp_new_s3";
	default: return "bad sr_nat_mapping_type value";
	}
}
