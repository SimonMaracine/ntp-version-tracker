#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>

#include "sniff_session.h"
#include "args.h"
#include "logging.h"
#include "helpers.h"

static void packet_sniffed(const struct ether_header* ethernet_header, void* user) {
    (void) user;

    // Print MACs as they come
    char source[18];
    char destination[18];
    formatted_mac(ethernet_header->ether_shost, source);
    formatted_mac(ethernet_header->ether_dhost, destination);

    log_print("S %s --- D %s (T %hu)\n", source, destination, ethernet_header->ether_type);

    // Can do other stuff
}

static void interrupt_handler(int signal) {
    (void) signal;

    sniff_stop_signal();
}

int main(int argc, char** argv) {
    const Args* args = args_parse_arguments(argc, argv);

    if (args == NULL) {
        args_print_usage();
        return 1;
    }

    printf("device: %s, log_target: %u, log_file: %s\n", args->device, args->log_target_mask, args->log_file);

    if (set_interrupt_handler(interrupt_handler) < 0) {
        return 1;
    }

    if (log_initialize(args->log_file, args->log_target_mask) < 0) {
        return 1;
    }

    SniffSession session = {0};

    if (sniff_initialize_session(&session, args->device) < 0) {
        return 1;
    }

    // sniff_blocking(&session, 20, packet_sniffed, &macs);

    if (sniff(&session, packet_sniffed, NULL) < 0) {
        sniff_uninitialize_session(&session);
        return 1;
    }

    log_print("Quit\n");

    sniff_uninitialize_session(&session);
    log_uninitialize();

    return 0;
}
