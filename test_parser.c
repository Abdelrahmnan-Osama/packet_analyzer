#include <assert.h>        // For assert() checks in our tests
#include <string.h>        // For memset() to clear memory
#include "packet_parser.h" // Contains our packet parsing functions

/* ==================================================================================================== */
/*                          Helper Functions to Create Fake Network Packets                             */
/* ==================================================================================================== */

// Creates a fake IP packet that we can use for testing
void create_valid_ip_packet(u_char *packet, u_char protocol, size_t total_size)
{
    // First part is Ethernet header (like the envelope for our packet)
    struct eth_header *eth = (struct eth_header *)packet;

    // Fill in fake MAC addresses (like postal addresses for computers)
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
        eth->ether_shost[i] = 0xAA; // Source MAC: AA:AA:AA:AA:AA:AA
        eth->ether_dhost[i] = 0xBB; // Destination MAC: BB:BB:BB:BB:BB:BB
    }

    // Set type to IPv4 (like writing "Standard Mail" on the envelope)
    eth->ether_type = htons(ETHERTYPE_IPV4);

    // Now set up the IP header (like the letter inside the envelope)
    struct ip_header *ip = (struct ip_header *)(packet + ETH_HEADER_SIZE);
    ip->version = 4;         // Using IPv4
    ip->ihl = 5;             // Standard IP header length (5 * 4 = 20 bytes)
    ip->protocol = protocol; // What kind of data is inside (TCP/UDP/ICMP)

    // Fill any extra space with zeros (like padding a package with bubble wrap)
    if (total_size > ETH_HEADER_SIZE + IP_MIN_SIZE)
    {
        memset(packet + ETH_HEADER_SIZE + IP_MIN_SIZE, 0,
               total_size - (ETH_HEADER_SIZE + IP_MIN_SIZE));
    }
}

// Creates a fake non-IP packet (like ARP which is used for address resolution)
void create_non_ip_packet(u_char *packet, u_short ether_type, size_t total_size)
{
    // Set up Ethernet header with fake MACs
    struct eth_header *eth = (struct eth_header *)packet;
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
        eth->ether_shost[i] = 0xAA;
        eth->ether_dhost[i] = 0xBB;
    }
    // Set custom packet type (like marking it "Express Mail")
    eth->ether_type = htons(ether_type);

    // Fill any payload data with zeros if needed
    if (total_size > ETH_HEADER_SIZE)
    {
        memset(packet + ETH_HEADER_SIZE, 0, total_size - ETH_HEADER_SIZE);
    }
}

/* ==================================================================================================== */
/*                                         Individual Tests                                             */
/* ==================================================================================================== */

// Test 1: Check if TCP packets are counted correctly
void test_valid_tcp_packet()
{
    printf("1. Testing valid TCP packet...\n");

    // Create a fake TCP packet
    u_char packet[ETH_HEADER_SIZE + IP_MIN_SIZE];
    create_valid_ip_packet(packet, IPPROTO_TCP, sizeof(packet));

    // Initialize empty statistics
    packet_stats_t stats;
    init_packet_stats(&stats);

    // Process our fake packet
    process_packet(packet, sizeof(packet), &stats);

    // Verify results:
    assert(stats.tcp_count == 1);     // Should have 1 TCP packet
    assert(stats.total_packets == 1); // Should have 1 total packet
    assert(stats.other_count == 0);   // Shouldn't count as "other"

    printf("Passed!\n\n");
}

// Test 2: Check UDP packet counting (same structure as TCP test)
void test_valid_udp_packet()
{
    printf("2. Testing valid UDP packet...\n");
    u_char packet[ETH_HEADER_SIZE + IP_MIN_SIZE];
    create_valid_ip_packet(packet, IPPROTO_UDP, sizeof(packet));

    packet_stats_t stats;
    init_packet_stats(&stats);
    process_packet(packet, sizeof(packet), &stats);

    assert(stats.udp_count == 1);
    assert(stats.total_packets == 1);
    assert(stats.other_count == 0);
    printf("Passed!\n\n");
}

// Test 3: Check ICMP packet counting (like ping packets)
void test_valid_icmp_packet()
{
    printf("3. Testing valid ICMP packet...\n");
    u_char packet[ETH_HEADER_SIZE + IP_MIN_SIZE];
    create_valid_ip_packet(packet, IPPROTO_ICMP, sizeof(packet));

    packet_stats_t stats;
    init_packet_stats(&stats);
    process_packet(packet, sizeof(packet), &stats);

    assert(stats.icmp_count == 1);
    assert(stats.total_packets == 1);
    assert(stats.other_count == 0);
    printf("Passed!\n\n");
}

// Test 4: Check non-IP packets (like ARP)
void test_arp_packet()
{
    printf("4. Testing ARP packet (non-IP)...\n");
    u_char packet[ETH_HEADER_SIZE + 28]; // Typical ARP packet size

    // Create ARP packet (type 0x0806)
    create_non_ip_packet(packet, 0x0806, sizeof(packet));

    packet_stats_t stats;
    init_packet_stats(&stats);
    process_packet(packet, sizeof(packet), &stats);

    // Should count as "other" protocol
    assert(stats.other_count == 1);
    assert(stats.total_packets == 1);
    assert(stats.tcp_count == 0); // Make sure it didn't count as TCP
    printf("Passed!\n\n");
}

// Test 5: Smallest possible valid IP packet
void test_min_size_ip_packet()
{
    printf("5. Testing minimum size IP packet...\n");
    u_char packet[ETH_HEADER_SIZE + IP_MIN_SIZE];
    create_valid_ip_packet(packet, IPPROTO_UDP, sizeof(packet));

    packet_stats_t stats;
    init_packet_stats(&stats);
    process_packet(packet, sizeof(packet), &stats);

    assert(stats.udp_count == 1);
    assert(stats.total_packets == 1);
    printf("Passed!\n\n");
}

// Test 6: Large IP packet (typical maximum size)
void test_large_ip_packet()
{
    printf("6. Testing large IP packet...\n");
    u_char packet[ETH_HEADER_SIZE + 1500]; // Standard maximum size

    create_valid_ip_packet(packet, IPPROTO_TCP, sizeof(packet));

    packet_stats_t stats;
    init_packet_stats(&stats);
    process_packet(packet, sizeof(packet), &stats);

    assert(stats.tcp_count == 1);
    assert(stats.total_packets == 1);
    printf("Passed!\n\n");
}

// Test 7: Invalid IP version (should be ignored)
void test_invalid_ip_version()
{
    printf("7. Testing invalid IP version...\n");
    u_char packet[ETH_HEADER_SIZE + IP_MIN_SIZE];
    create_valid_ip_packet(packet, IPPROTO_TCP, sizeof(packet));

    // Break the version field (set to 6 instead of 4)
    struct ip_header *ip = (struct ip_header *)(packet + ETH_HEADER_SIZE);
    ip->version = 6;

    packet_stats_t stats;
    init_packet_stats(&stats);
    process_packet(packet, sizeof(packet), &stats);

    // Based on your spec, invalid packets should be ignored
    assert(stats.other_count == 0);
    assert(stats.total_packets == 1); // But still counted in total
    printf("Passed!\n\n");
}

// Test 8: Empty packet (0 bytes)
void test_zero_length_packet()
{
    printf("8. Testing zero-length packet...\n");
    u_char packet[1]; // Content doesn't matter since length is 0

    packet_stats_t stats;
    init_packet_stats(&stats);
    process_packet(packet, 0, &stats); // Length parameter is 0

    assert(stats.other_count == 0);
    assert(stats.total_packets == 1); // Still counted in total
    printf("Passed!\n\n");
}

// Test 9: NULL packet pointer (shouldn't crash)
void test_null_packet()
{
    printf("9. Testing NULL packet pointer...\n");

    packet_stats_t stats;
    init_packet_stats(&stats);
    process_packet(NULL, 100, &stats); // Pass NULL instead of real packet

    assert(stats.total_packets == 0); // Shouldn't count NULL packets
    printf("Passed!\n\n");
}

// Test 10: Multiple packets of same protocol (counter = 2)
void test_multiple_packets_same_protocol()
{
    printf("10. Testing multiple TCP packets...\n");

    // Create first TCP packet
    u_char packet1[ETH_HEADER_SIZE + IP_MIN_SIZE];
    create_valid_ip_packet(packet1, IPPROTO_TCP, sizeof(packet1));

    // Create second TCP packet
    u_char packet2[ETH_HEADER_SIZE + IP_MIN_SIZE];
    create_valid_ip_packet(packet2, IPPROTO_TCP, sizeof(packet2));

    packet_stats_t stats;
    init_packet_stats(&stats);

    // Process both packets
    process_packet(packet1, sizeof(packet1), &stats);
    process_packet(packet2, sizeof(packet2), &stats);

    // Verify counters
    assert(stats.tcp_count == 2);     // Should have 2 TCP packets
    assert(stats.total_packets == 2); // Should have 2 total packets
    assert(stats.other_count == 0);   // Shouldn't count as "other"

    printf("Passed!\n\n");
}

/* ==================================================================================================== */
/*                                         Main Test Runner                                             */
/* ==================================================================================================== */

int main()
{
    printf("=== Packet Parser Test Suite ===\n\n");

    /* Basic Protocol Tests */
    test_valid_tcp_packet();  // Test single TCP packet processing
    test_valid_udp_packet();  // Test single UDP packet processing
    test_valid_icmp_packet(); // Test single ICMP packet processing

    /* Special Case Tests */
    test_arp_packet();         // Test non-IP (ARP) packet handling
    test_min_size_ip_packet(); // Test minimum sized IP packet
    test_large_ip_packet();    // Test large (MTU-sized) IP packet

    /* Error Case Tests */
    test_invalid_ip_version(); // Test malformed IP version
    test_zero_length_packet(); // Test empty packet handling
    test_null_packet();        // Test NULL packet pointer safety

    /* Throughput Test */
    test_multiple_packets_same_protocol(); // Test multiple TCP packet counting

    printf("All tests passed successfully!\n");
    return 0;
}