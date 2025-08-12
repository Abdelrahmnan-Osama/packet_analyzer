#include "main_utils.h"

/* ==================================================================================================== */
/*                                     GLOBAL VARIABLES DEFINITION                                      */
/* ==================================================================================================== */

packet_stats_t stats;                   // Tracks packet statistics
volatile sig_atomic_t keep_running = 1; // Safe signal handler flag (atomic + no compiler caching)
time_t start_time;                      // Program start timestamp
/* ==================================================================================================== */
/*                                    Static VARIABLE Definitions                                       */
/* ==================================================================================================== */

static pcap_t *handle = NULL; // Private capture handle

/* ==================================================================================================== */
/*                                     HELPER FUNCTIONS IMPLEMENTATION                                  */
/* ==================================================================================================== */

static void apply_filter(pcap_t *handle, const char *filter_str)
{
    struct bpf_program fp;

    // Compile the filter
    if (pcap_compile(handle, &fp, filter_str, FILTER_OPTIMIZE, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_str, pcap_geterr(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    // Apply the compiled filter
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_str, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    // Free the compiled filter code
    pcap_freecode(&fp);
}

/* Handles SIGINT (Ctrl+C) — stops capture gracefully */
static void handle_interrupt(int signal)
{
    printf("\nReceived signal %d, shutting down...\n \n", signal);
    keep_running = 0;
    if (handle)
    {
        pcap_breakloop(handle); // Immediately break from pcap_dispatch/pcap_loop
    }
}

/* PCAP callback — processes each captured packet */
static void packet_handler(u_char *user_data, const struct pcap_pkthdr *h, const u_char *packet)
{
    packet_stats_t *stats_ptr = (packet_stats_t *)user_data; // Cast user_data to stats pointer
    process_packet(packet, h->len, stats_ptr);               // Process packet and update stats
}

/* Prints program startup info (interface, filter, duration, etc.) */
static void print_banner(const char *device, const char *filter, int duration, const char *outfile)
{
    printf("Packet Analyzer (E-VAS Tel Team) \n");
    printf("--------------------------------- \n");
    printf("Interface: %s \n", device);
    printf("Buffer Size: %d packets \n", BUFFER_SIZE);
    printf("Filter: %s \n", filter);
    printf("Duration: %d seconds \n", duration);
    printf("Output File: %s \n \n", outfile);
}

/* Returns peak memory usage (KB) for current process */
static size_t get_memory_usage(void)
{

    struct rusage usage;            // Structure to hold resource usage data
    getrusage(RUSAGE_SELF, &usage); // Populate with current process statistics
    return usage.ru_maxrss;         // Return maximum resident set size (in KB)
}

// Output statistics to console or file
static void print_final_stats(const packet_stats_t *stats, const char *filename)
{
    // Open file if filename provided, otherwise use console
    FILE *output = filename ? fopen(filename, "w") : stdout;
    if (!output)
    {
        perror("Failed to open output file");
        return;
    }

    // Calculate program runtime
    int elapsed = (int)(time(NULL) - start_time);

    // Print statistics header
    fprintf(output, "Final Statistics:\n");
    fprintf(output, "================\n");
    fprintf(output, "[%d seconds elapsed]\n", elapsed);

    // Print packet counts and percentages
    print_stats(stats, output);

    // Print memory usage
    fprintf(output, "Memory usage: %.1f KB\n\n", get_memory_usage() / 1024.0);

    // Close file if we wrote to one
    if (filename)
    {
        fclose(output);
        printf("Statistics saved to %s\n\n", filename);
    }

    // Always print termination message to console
    printf("Packet analyzer terminated.\n");
}

/* ==================================================================================================== */
/*                                     PUBLIC FUNCTIONS IMPLEMENTATION                                  */
/* ==================================================================================================== */

void parse_arguments(int argc, char **argv, program_options_t *opts)
{
    /* Initialize options with defaults */
    opts->device = NULL;    /* (Must be set via -i) */
    opts->filter = "none";  /* Default: Capture all Packets */
    opts->outfile = "none"; /* Default: Output to stdout */
    opts->duration = 0;     /* Default: Run indefinitely */

    /* Configure getopt() */
    optind = 1; /* Reset parser state */

    /* Process each argument */
    int opt;
    while ((opt = getopt(argc, argv, "i:f:t:o:")) != -1)
    {
        switch (opt)
        {
        case 'i': /* Network interface (required) */
            opts->device = optarg;
            break;

        case 'f': /* Packet filter (optional) */
            opts->filter = optarg;
            break;

        case 't': /* Duration in seconds (optional) */
            /*Validate duration is positive integer*/
            opts->duration = atoi(optarg);
            if (opts->duration <= 0)
            {
                fprintf(stderr, "Error: -t value must be positive\n");
                exit(EXIT_FAILURE);
            }
            break;

        case 'o': /* Output file (optional) */
            opts->outfile = optarg;
            break;

        default: /* Handles invalid options */
            fprintf(stderr, "Valid Format: %s -i <interface> [-f <filter>] [-t <seconds>] [-o <output>]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    /* Verify mandatory -i was provided */
    if (!opts->device)
    {
        fprintf(stderr, "Error: Network interface must be specified with -i\n");
        exit(EXIT_FAILURE);
    }
}

void init_environment()
{
    init_packet_stats(&stats);        // Initialize packet statistics structure
    signal(SIGINT, handle_interrupt); // Set up Ctrl+C signal handler
    start_time = time(NULL);          // Record program start timestamp
}

/* Open network interface for packet capture */
pcap_t *open_capture(const program_options_t *opts)
{
    char errbuf[PCAP_ERRBUF_SIZE]; // PCAP error buffer

    // Open network interface in promiscuous mode
    handle = pcap_open_live(opts->device, PCAP_HDRS_ONLY, PCAP_PROMISC, PCAP_TIMEOUT_MS, errbuf);
    if (!handle) // Validate capture handle
    {
        fprintf(stderr, "Error opening interface: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // Verify interface uses Ethernet framing
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "%s: Unsupported link type (expected Ethernet)\n",
                opts->device);
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    // Apply filter if one was specified
    if (strcmp(opts->filter, "none") && strcmp(opts->filter, "") != 0)
    {
        apply_filter(handle, opts->filter);
    }

    print_banner(opts->device, opts->filter, opts->duration, opts->outfile);
    return handle;
}

void run_capture_loop(pcap_t *handle, const program_options_t *opts)
{
    // Loop until interrupted or duration expires
    while (keep_running)
    {
        // If duration is set and elapsed time reached, exit loop
        if (opts->duration && (time(NULL) - start_time) >= opts->duration)
            break;

        // Capture and process up to 100 packets in one call
        pcap_dispatch(handle, BUFFER_SIZE, packet_handler, (u_char *)&stats);
    }
}

// Close capture handle and output statistics
void cleanup_and_exit(pcap_t *handle, program_options_t *opts)
{
    // Close the packet capture handle
    pcap_close(handle);

    // Output stats to file if specified, otherwise print to console
    print_final_stats(&stats, (strcmp(opts->outfile, "none") == 0) ? NULL : opts->outfile);
}
