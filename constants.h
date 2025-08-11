#if !defined(CONSTANTS_H)
#define CONSTANTS_H

#include <stdint.h>

/* Protocol type definitions */
typedef enum
{
    PROTO_TCP = 6,
    PROTO_UDP = 17,
    PROTO_ICMP = 1,
    PROTO_OTHER = 255
} protocol;

/* Network constants */
#define ETH_HEADER_SIZE sizeof(struct eth_header) // Ethernet header is always 14 bytes
#define IP_MIN_SIZE sizeof(struct ip_header)      // Minimum IPv4 header is 20 bytes
#define ETHER_ADDR_LEN 6                          // Ethernet addresses are 6 bytes
#define ETHERTYPE_IPV4 0x0800                     //  Internet Protocol version 4
#define IP_VERSION_BITS 4                         // Bit-width for IP version field (4 bits)
#define IP_IHL_BITS 4                             // Bit-width for IP header length field (4 bits)
#define BUFFER_SIZE 100                           // Network capture buffer size (100 bytes)
#define PCAP_PROMISC 1                            // Enable promiscuous mode (all traffic)
#define PCAP_TIMEOUT_MS 1000                      // Packet read timeout (milliseconds)
#define PCAP_HDRS_ONLY 100                        // Ethernet+IP+Transport headers (no payload)

/* Type aliases for network programming */
typedef uint8_t u_char;   // 8-bit unsigned
typedef uint16_t u_short; // 16-bit unsigned
typedef uint32_t u_int;   // 32-bit unsigned

#endif // CONSTANTS_H
