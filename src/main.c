#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <signal.h>

#include "sniff_session.h"
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

        printf("src MAC: %s ---> dest MAC: %s\n", source, destination);
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
    printf("S ");
    print_mac(ethernet_header->ether_shost, "");
    printf(" --- D ");
    print_mac(ethernet_header->ether_dhost, "\n");

    // Store MACs for later
    // store_mac_pair(ethernet_header->ether_shost, ethernet_header->ether_dhost, user);
}

static void interrupt_handler(int signal) {
    (void) signal;

    sniff_stop_signal();
}

int main(int argc, char** argv) {
    printf("Is little endian: %d\n", is_little_endian());

    if (argc != 2) {
        fprintf(stderr, "No device provided\n");
        return 1;
    }

    const char* device = argv[1];

    if (set_interrupt_handler(interrupt_handler) < 0) {
        fprintf(stderr, "Could not set interrupt handler\n");
        return 1;
    }

    SniffSession session = {0};

    if (sniff_initialize_session(&session, device) < 0) {
        return 1;
    }

    Macs macs = {0};

    // sniff_blocking(&session, 20, packet_sniffed, &macs);

    if (sniff(&session, packet_sniffed, &macs) < 0) {
        goto err_sniff;
    }

    printf("Quit\n");
    // print_all_macs(&macs);

err_sniff:
    sniff_uninitialize_session(&session);
}
