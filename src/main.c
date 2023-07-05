#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

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

void print_all_macs(const Macs* macs, size_t count) {
    char source[18];
    char destination[18];

    for (size_t i = 0; i < count; i++) {
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
}

static void packet_sniffed(const struct ether_header* ethernet_header, void* user) {
    // Print MACs as they come
    printf("S ");
    print_mac(ethernet_header->ether_shost, "");
    printf(" --- D ");
    print_mac(ethernet_header->ether_dhost, "\n");

    // Store MACs for later
    store_mac_pair(ethernet_header->ether_shost, ethernet_header->ether_dhost, user);
}

int main(int argc, char** argv) {
    printf("Is little endian: %d\n", is_little_endian());

    if (argc != 2) {
        fprintf(stderr, "No device provided\n");
        return 1;
    }

    const char* device = argv[1];

    SniffSession session = {0};

    if (initialize_session(&session, device) < 0) {
        return 1;
    }

    Macs macs = {0};
    const int SNIFF_COUNT = 20;

    sniff_blocking(&session, SNIFF_COUNT, packet_sniffed, &macs);

    deinitialize_session(&session);

    printf("Optional:\n");
    print_all_macs(&macs, SNIFF_COUNT);
}
