#include "main_utils.h"

int main(int argc, char **argv)
{
    program_options_t opts;
    parse_arguments(argc, argv, &opts);
    init_environment();
    pcap_t *handle = open_capture(&opts);
    run_capture_loop(handle, &opts);
    cleanup_and_exit(handle, &opts);
    return EXIT_SUCCESS;
}