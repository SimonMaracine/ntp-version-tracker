#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>

#include "sniff_session.h"
#include "args.h"
#include "logging.h"
#include "helpers.h"

typedef struct {
    uint8_t source[ETHER_ADDR_LEN];
    uint8_t destination[ETHER_ADDR_LEN];
} MacPair;

typedef struct {
    MacPair pairs[128];
    size_t count;
} Macs;

void print_all_macs(const Macs* macs) {
    char source[18];
    char destination[18];

    for (size_t i = 0; i < macs->count; i++) {
        formatted_mac(macs->pairs[i].source, source);
        formatted_mac(macs->pairs[i].destination, destination);

        log_print("src MAC: %s ---> dest MAC: %s\n", source, destination);
    }
}

void store_mac_pair(const uint8_t* mac_source, const uint8_t* mac_destination, void* user) {
    Macs* macs = (Macs*) user;

    MacPair pair;
    memcpy(pair.source, mac_source, ETHER_ADDR_LEN);
    memcpy(pair.destination, mac_destination, ETHER_ADDR_LEN);

    macs->pairs[macs->count] = pair;
    macs->count++;
}

static void packet_sniffed(const struct ether_header* ethernet_header, void* user) {
    // Print MACs as they come
    char source[18];
    char destination[18];
    formatted_mac(ethernet_header->ether_shost, source);
    formatted_mac(ethernet_header->ether_dhost, destination);

    log_print("S %s --- D %s (T %hu)\n", source, destination, ethernet_header->ether_type);

    // Store MACs for later
    // store_mac_pair(ethernet_header->ether_shost, ethernet_header->ether_dhost, user);
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

    printf("device: %s, log_file: %s, log_target: %d\n", args->device, args->log_file, args->log_target);

    log_initialize(args->log_file, (LogTarget) args->log_target);

    if (set_interrupt_handler(interrupt_handler) < 0) {
        log_print("Could not set interrupt handler\n");
        return 1;
    }

    SniffSession session = {0};

    if (sniff_initialize_session(&session, args->device) < 0) {
        return 1;
    }

    Macs macs = {0};

    // sniff_blocking(&session, 20, packet_sniffed, &macs);

    if (sniff(&session, packet_sniffed, &macs) < 0) {
        sniff_uninitialize_session(&session);
        return 1;
    }

    log_print("Quit\n");
    // print_all_macs(&macs);

    sniff_uninitialize_session(&session);
    log_uninitialize();

    return 0;
}
