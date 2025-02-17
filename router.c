#include "queue.h"
#include "lib.h"
#include "protocols.h"

#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ETHERTYPE_IP 0x0800
#define MAX_TTL 64

static struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len;

struct route_table_entry *get_best_route(uint32_t destination_ip)
{
	int left = 0, right = rtable_len - 1;
	struct route_table_entry *best_match = NULL;

	while (left <= right)
	{
		int mid = (right + left) / 2;
		uint32_t masked_dest = destination_ip & rtable[mid].mask;

		// save the current match if it is the best so far
		if (masked_dest == rtable[mid].prefix)
		{
			if (!best_match || ntohl(rtable[mid].mask) > ntohl(best_match->mask))
			{
				best_match = &rtable[mid];
			}
		}

		// adjust search range
		if (ntohl(rtable[mid].prefix) < ntohl(destination_ip))
		{
			right = mid - 1;
		}
		else
		{
			left = mid + 1;
		}
	}
	return best_match;
}

struct arp_table_entry *get_arp_entry(uint32_t given_ip)
{
	for (int i = 0; i < arp_table_len; ++i)
	{
		if ((arp_table + i)->ip == given_ip)
			return (arp_table + i);
	}
	return NULL;
}

static inline int32_t compare_function(const void *p, const void *q)
{
	struct route_table_entry route1 = *(struct route_table_entry *)p;
	struct route_table_entry route2 = *(struct route_table_entry *)q;

	if (ntohl(route1.prefix) > ntohl(route2.prefix))
		return -1;

	if (ntohl(route1.prefix) == ntohl(route2.prefix))
		if (ntohl(route1.mask) > ntohl(route2.mask))
			return -1;

	return 1;
}

static void icmp_packet(struct ether_header *eth_hdr,
						   uint8_t type,
						   uint32_t interface)
{
	struct iphdr *ip_hdr = (struct iphdr *)((char *)eth_hdr + sizeof(*eth_hdr));
	struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + sizeof(*ip_hdr));

	// calculate the length of the ICMP payload
	uint32_t icmp_len = sizeof(*ip_hdr) + 8;
	int8_t *icmp_body = malloc(icmp_len);
	DIE(!icmp_body, "malloc() failed.\n");

	// get router IP and prepare IP header for the response
	uint32_t router_ip;
	inet_pton(AF_INET, get_interface_ip(interface), &router_ip);
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = router_ip;
	ip_hdr->ttl = htons(MAX_TTL);
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(*icmp_hdr) + sizeof(*ip_hdr) + icmp_len);

	// swap MAC addresses in the Ethernet header
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
	get_interface_mac(interface, eth_hdr->ether_shost);

	// prepare the ICMP header
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0; // Clear checksum for recalculation

	// copy original IP header and first 8 bytes of the payload to the ICMP body
	memcpy(icmp_body, ip_hdr, icmp_len);

	// calculate checksums for IP and ICMP headers
	ip_hdr->check = 0; // Clear IP checksum for recalculation
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(*icmp_hdr)));

	// place the ICMP body after the ICMP header in the packet
	memcpy((char *)icmp_hdr + sizeof(*icmp_hdr), icmp_body, icmp_len);

	send_to_link(interface, (char *)eth_hdr, sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*icmp_hdr) + icmp_len);

	free(icmp_body);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	int interface;

	arp_table = malloc(sizeof(struct mac_entry *) * 100);
	DIE(arp_table == NULL, "memory");

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");

	arp_table_len = parse_arp_table("arp_table.txt", arp_table);
	rtable_len = read_rtable(argv[1], rtable);

	qsort(rtable, rtable_len, sizeof(rtable[0]), compare_function);

	while (1)
	{

		size_t len;
		struct ether_header *eth_hdr = (struct ether_header *)buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// check if we got an IPv4 packet
		if (eth_hdr->ether_type != ntohs(ETHERTYPE_IP))
		{
			// ignore non-IPv4 packet
			continue;
		}

		if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != 0)
		{
			// checksum gone wrong
			fflush(stdout);
			continue;
		}

		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

		if (!best_route)
		{
			// ICMP "Destination unreachable"
			icmp_packet(eth_hdr, 3, interface);
			continue;
		}

		if (ip_hdr->ttl <= 1)
		{
			// expired
			icmp_packet(eth_hdr, 11, interface);
			continue;
		}

		if (eth_hdr->ether_type == ntohs(ETHERTYPE_IP))
		{
			if (ip_hdr->protocol == IPPROTO_ICMP)
			{
				struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + sizeof(struct iphdr));
				uint32_t router_ip;
				inet_pton(AF_INET, get_interface_ip(interface), &router_ip);
				if (icmp_hdr->type == 8 && icmp_hdr->code == 0 && ip_hdr->daddr == router_ip)
				{
					icmp_packet(eth_hdr, 0, interface);
					continue;
				}
			}
		}

		int auxcheck = ip_hdr->check, auxttl = ip_hdr->ttl;
		ip_hdr->ttl -= 1;
		ip_hdr->check = ~(~auxcheck + ~((uint16_t) auxttl) + (uint16_t)ip_hdr->ttl) - 1;

		// update the eth address from next jump: me->next_person->...
		// and i get the mac table from next_person
		struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);
		if (arp_entry == NULL)
		{
			// no mac entry found
			fflush(stdout);
			continue;
		}
		// update the eth address
		for (int i = 0; i < 6; ++i)
		{
			eth_hdr->ether_dhost[i] = arp_entry->mac[i];
		}
		uint8_t mac[6];
		// get the mac address of the interface
		get_interface_mac(best_route->interface, mac);

		// update the eth address with my interface
		for (int i = 0; i < 6; ++i)
		{
			eth_hdr->ether_shost[i] = mac[i];
		}
		send_to_link(best_route->interface, buf, len);

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
	}
	free(rtable);
	free(arp_table);
}
