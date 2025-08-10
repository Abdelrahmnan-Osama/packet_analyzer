#include "packet_parser.h"
#include <stdio.h>
#include <string.h>

typedef struct
{
    const char *name;
    const uint8_t *packet;
    size_t length;
    int expected_proto;
} test_case_t;

void run_batch_test(const test_case_t *tests, size_t num_tests)
{
    packet_stats_t stats;
    init_packet_stats(&stats);

    printf("=== Running Batch Test (%zu packets) ===\n", num_tests);

    // Process all test packets
    for (size_t i = 0; i < num_tests; i++)
    {
        process_packet(tests[i].packet, tests[i].length, &stats);
    }

    // Print final statistics
    printf("\nFinal Statistics:\n");
    print_stats(&stats);

    // Calculate expected counts
    int expected_tcp = 0, expected_udp = 0, expected_icmp = 0, expected_other = 0;
    int expected_total = 0;

    for (size_t i = 0; i < num_tests; i++)
    {
        if (tests[i].expected_proto == -1)
            continue;

        expected_total++;
        switch (tests[i].expected_proto)
        {
        case PROTO_TCP:
            expected_tcp++;
            break;
        case PROTO_UDP:
            expected_udp++;
            break;
        case PROTO_ICMP:
            expected_icmp++;
            break;
        case PROTO_OTHER:
            expected_other++;
            break;
        }
    }

    // Verify results
    printf("\nVerification:\n");
    int passed = 1;

    if (stats.tcp_count != expected_tcp)
    {
        printf("FAIL: TCP count mismatch (expected %d, got %d)\n", expected_tcp, stats.tcp_count);
        passed = 0;
    }
    if (stats.udp_count != expected_udp)
    {
        printf("FAIL: UDP count mismatch (expected %d, got %d)\n", expected_udp, stats.udp_count);
        passed = 0;
    }
    if (stats.icmp_count != expected_icmp)
    {
        printf("FAIL: ICMP count mismatch (expected %d, got %d)\n", expected_icmp, stats.icmp_count);
        passed = 0;
    }
    if (stats.other_count != expected_other)
    {
        printf("FAIL: Other count mismatch (expected %d, got %d)\n", expected_other, stats.other_count);
        passed = 0;
    }
    if (stats.total_packets != expected_total)
    {
        printf("FAIL: Total packets mismatch (expected %d, got %d)\n", expected_total, stats.total_packets);
        passed = 0;
    }

    if (passed)
    {
        printf("PASS: All counts match expected values\n");
    }
}

int main()
{
    // Define test packets
    uint8_t tcp_packet[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        0xaa, 0xbb, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    uint8_t udp_packet[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        0xaa, 0xbb, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00};

    uint8_t icmp_packet[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01};

    uint8_t arp_packet[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x06,
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x01};

    uint8_t truncated_packet[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x28};

    // Define test cases
    test_case_t tests[] = {
        {"TCP Packet 1", tcp_packet, sizeof(tcp_packet), PROTO_TCP},
        {"TCP Packet 2", tcp_packet, sizeof(tcp_packet), PROTO_TCP},
        {"UDP Packet", udp_packet, sizeof(udp_packet), PROTO_UDP},
        {"ICMP Packet", icmp_packet, sizeof(icmp_packet), PROTO_ICMP},
        {"ARP Packet", arp_packet, sizeof(arp_packet), PROTO_OTHER},
        {"Truncated Packet", truncated_packet, sizeof(truncated_packet), -1},
        {"TCP Packet 3", tcp_packet, sizeof(tcp_packet), PROTO_TCP},
        {"UDP Packet 2", udp_packet, sizeof(udp_packet), PROTO_UDP},
        {"Bad Packet", truncated_packet, sizeof(truncated_packet), -1},
        {"TCP Packet 4", tcp_packet, sizeof(tcp_packet), PROTO_TCP}};

    // Run the batch test
    run_batch_test(tests, sizeof(tests) / sizeof(tests[0]));

    return 0;
}