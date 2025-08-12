#if !defined(MAIN_UTILS_H)
#define MAIN_UTILS_H

#include "packet_parser.h" // Packet parsing definitions
#include <stdlib.h>        // exit(), atoi(), malloc/free
#include <string.h>        // strcmp()
#include <pcap.h>          // Packet capture API (libpcap)
#include <signal.h>        // Signals (SIGINT, sig_atomic_t)
#include <time.h>          // time(), time calculations
#include <getopt.h>        // getopt()
#include <unistd.h>        // sleep()
#include <sys/resource.h>  // getrusage(), memory stats

/* ==================================================================================================== */
/*                                       GLOBAL VARIABLE DECLARATIONS                                   */
/* ==================================================================================================== */

extern packet_stats_t stats;               // Stores packet counts and stats
extern volatile sig_atomic_t keep_running; // Loop control flag (safe in signal handlers)
extern time_t start_time;                  // Program start timestamp
static pcap_t *handle;                     // Private capture handle

/* ==================================================================================================== */
/*                                       STRUCTURE DEFINITIONS                                          */
/* ==================================================================================================== */

typedef struct
{
    char *device;
    char *filter;
    char *outfile;
    int duration;
} program_options_t;

/* ==================================================================================================== */
/*                                       PUBLIC FUNCTIONS DECLARATION                                   */
/* ==================================================================================================== */

// Parses command-line arguments and stores them in the program_options_t struct
void parse_arguments(int argc, char **argv, program_options_t *opts);
// Sets up global variables, packet statistics, and signal handling
void init_environment();
// Opens a live packet capture on the specified interface and prints the banner
pcap_t *open_capture(const program_options_t *opts);
// Runs the main packet capture loop until time limit or interrupt is reached
void run_capture_loop(pcap_t *handle, const program_options_t *opts);
// Closes the capture handle and prints final statistics before exiting
void cleanup_and_exit(pcap_t *handle);

/* ==================================================================================================== */
/*                                       HELPER FUNCTIONS DECLARATION                                   */
/* ==================================================================================================== */

/*Applies a BPF filter to the capture handle*/
static void apply_filter(pcap_t *handle, const char *filter_str);
/* Handles SIGINT (Ctrl+C) to stop the main loop */
static void handle_interrupt(int signal);
/* pcap callback: processes each captured packet */
static void packet_handler(u_char *user_data, const struct pcap_pkthdr *h, const u_char *packet);
/* Prints startup info (interface, buffer, filter, etc.) */
static void print_banner(const char *device, const char *filter, int duration, const char *outfile);
/* Prints final statistics after capture ends */
static void print_final_stats(const packet_stats_t *stats);
/* Returns peak memory usage in KB */
static size_t get_memory_usage(void);

#endif /* MAIN_UTILS_H */
