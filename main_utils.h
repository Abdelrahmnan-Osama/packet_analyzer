#if !defined(MAIN_UTILS_H)
#define MAIN_UTILS_H

#include "packet_parser.h" // Packet parsing definitions
#include <stdlib.h>        // exit(), atoi(), malloc/free
#include <string.h>        // strcmp()
#include <pcap.h>          // Packet capture API (libpcap)
#include <signal.h>        // Signals (SIGINT, sig_atomic_t)
#include <time.h>          // time(), time calculations
#include <getopt.h>        // getopt()
#include <sys/resource.h>  // getrusage(), memory stats

/* ==================================================================================================== */
/*                                    GLOBAL VARIABLE DECLARATIONS                                      */
/* ==================================================================================================== */

extern packet_stats_t stats;               // Stores packet counts and stats
extern volatile sig_atomic_t keep_running; // Loop control flag (safe in signal handlers)
extern time_t start_time;                  // Program start timestamp

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
void cleanup_and_exit(pcap_t *handle, program_options_t *opts);

#endif /* MAIN_UTILS_H */
