/* Typical packet_parser.h */
#if !defined(PACKET_PARSER_H)
#define PACKET_PARSER_H

#include <stdio.h>
#include <stdatomic.h>
#include <netinet/in.h>
#include "constants.h"

/* ==================================================================================================== */
/*                                       STRUCTURE DEFINITIONS                                          */
/* ==================================================================================================== */

/* Ethernet header */
struct eth_header
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IPv4 header */
struct ip_header
{
    u_char ihl : IP_IHL_BITS;         // IP header length (4-byte words)
    u_char version : IP_VERSION_BITS; // IPv4
    u_char tos;                       // Type of service
    u_short tot_len;                  // Total length
    u_short id;                       // Identification
    u_short frag_off;                 // Fragment offset
    u_char ttl;                       // Time to live
    u_char protocol;                  // Protocol (TCP=6, UDP=17, ICMP=1)
    u_short check;                    // Checksum
    u_int saddr;                      // Source address (IPv4)
    u_int daddr;                      // Destination address (IPv4)
};

/* Packet statistics structure */
typedef struct
{
    atomic_int tcp_count;
    atomic_int udp_count;
    atomic_int icmp_count;
    atomic_int other_count;
    atomic_int total_packets;
} packet_stats_t;

/* ==================================================================================================== */
/*                                     PUBLIC FUNCTIONS DECLARATION                                     */
/* ==================================================================================================== */

/* Initialize packet stats */
void init_packet_stats(packet_stats_t *stats);
/* Process a packet and update stats */
void process_packet(const u_char *packet, u_int packet_legth, packet_stats_t *stats); // signature modified
/* Print current statistics */
void print_stats(const packet_stats_t *stats, FILE *out);

#endif /* PACKET_PARSER_H */