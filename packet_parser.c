#include "packet_parser.h"

/* ==================================================================================================== */
/*                                     PUBLIC FUNCTIONS IMPLEMENTATION                                  */
/* ==================================================================================================== */

void init_packet_stats(packet_stats_t *stats)
{
    atomic_init(&stats->tcp_count, 0);
    atomic_init(&stats->udp_count, 0);
    atomic_init(&stats->icmp_count, 0);
    atomic_init(&stats->other_count, 0);
    atomic_init(&stats->total_packets, 0);
}

void process_packet(const u_char *packet, u_int packet_length, packet_stats_t *stats)
{
    // Get packet protocol type (TCP/UDP/ICMP/OTHER or -1 for errors)
    int proto = get_packet_protocol(packet, packet_length);

    // Update protocol-specific counter based on packet type
    switch (proto)
    {
    case PROTO_TCP:
        atomic_fetch_add(&stats->tcp_count, 1); // Thread-safe TCP counter
        break;
    case PROTO_UDP:
        atomic_fetch_add(&stats->udp_count, 1); // Thread-safe UDP counter
        break;
    case PROTO_ICMP:
        atomic_fetch_add(&stats->icmp_count, 1); // Thread-safe ICMP counter
        break;
    case PROTO_OTHER:
        atomic_fetch_add(&stats->other_count, 1); // Other protocols
        break;
        // Note: No default case as get_packet_protocol only returns defined values or -1
    }

    // Always increment total if packet is captured
    atomic_fetch_add(&stats->total_packets, 1); // Thread-safe total counter
}

int get_packet_protocol(const u_char *packet, u_int packet_length)
{
    /* 1. Basic Packet Sanity Checks */
    if (validate_packet_structure(packet, packet_length) != 0)
    {
        return -1;
    }

    /* 2. Ethernet Header Processing */
    const struct eth_header *eth = (const struct eth_header *)packet;
    int ethernet_type = process_ethernet_header(eth);
    if (ethernet_type != 0)
    {
        return ethernet_type;
    }

    /* 3. IPv4 Header Processing */
    const struct ip_header *ip = (const struct ip_header *)(packet + ETH_HEADER_SIZE);
    if (validate_ip_header(ip, packet_length) != 0)
    {
        return -1;
    }

    /* 4. Protocol Identification */
    return identify_transport_protocol(ip->protocol);
}

void print_stats(const packet_stats_t *stats)
{
    // calculate protocol type percentages
    double tcp_pnt = (stats->total_packets != 0) ? ((double)stats->tcp_count / stats->total_packets) * 100 : 0;
    double udp_pnt = (stats->total_packets != 0) ? ((double)stats->udp_count / stats->total_packets) * 100 : 0;
    double icmp_pnt = (stats->total_packets != 0) ? ((double)stats->icmp_count / stats->total_packets) * 100 : 0;
    double other_pnt = (stats->total_packets != 0) ? ((double)stats->other_count / stats->total_packets) * 100 : 0;

    // print complete statistics
    printf("Packets captured: %d \n", stats->total_packets);
    printf("TCP:   %d (%.1f%%) \n", stats->tcp_count, tcp_pnt);
    printf("UDP:   %d (%.1f%%) \n", stats->udp_count, udp_pnt);
    printf("ICMP:  %d (%.1f%%) \n", stats->icmp_count, icmp_pnt);
    printf("Other: %d (%.1f%%) \n", stats->other_count, other_pnt);
}

/* ==================================================================================================== */
/*                                     HELPER FUNCTIONS IMPLEMENTATION                                  */
/* ==================================================================================================== */

static int validate_packet_structure(const u_char *packet, u_int packet_length)
{
    /* Reject if packet can't hold Eth+IP headers (14B+20B minimum) */
    if (!packet || packet_length < ETH_HEADER_SIZE + IP_MIN_SIZE)
    {
        return -1;
    }
    return 0;
}

static int process_ethernet_header(const struct eth_header *eth)
{
    /* Convert EtherType to host byte order and verify IPv4 */
    u_short eth_type = ntohs(eth->ether_type);
    if (eth_type != ETHERTYPE_IPV4)
    {
        return PROTO_OTHER; // Not an IPv4 packet
    }
    return 0;
}

static int validate_ip_header(const struct ip_header *ip, u_int packet_length)
{
    /* Verify IP version and header length */
    if (ip->version != 4 || ip->ihl < 5)
    {
        return -1;
    }

    /* Verify declared length doesn't exceed actual packet size */
    u_short total_ip_len = ip->ihl * 4;
    if (total_ip_len + ETH_HEADER_SIZE > packet_length)
    {
        return -1;
    }
    return 0;
}

static int identify_transport_protocol(u_char ip_protocol)
{
    switch (ip_protocol)
    {
    case IPPROTO_TCP:
        return PROTO_TCP;
    case IPPROTO_UDP:
        return PROTO_UDP;
    case IPPROTO_ICMP:
        return PROTO_ICMP;
    default:
        return PROTO_OTHER;
    }
}
