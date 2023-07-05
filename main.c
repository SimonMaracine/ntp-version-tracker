#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

#define ETHERNET_ADDRESS_SIZE 6

typedef struct {
    uint8_t source[ETHERNET_ADDRESS_SIZE];
    uint8_t destination[ETHERNET_ADDRESS_SIZE];
} MacPair;

typedef struct {
    MacPair* mac_pairs;
    size_t count;
} SniffedMacs;

void init_sniffed_macs(SniffedMacs* macs, size_t count) {
    macs->mac_pairs = calloc(count, sizeof(MacPair));
    macs->count = 0;
}

void deinit_sniffed_macs(const SniffedMacs* macs) {
    free(macs->mac_pairs);
}

// size_t ip_ihl(const unsigned char* ip_header) {
//     // https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Header

//     unsigned char version_ihl = 0;

//     // Read the first byte and extract IHL
//     memcpy(&version_ihl, ip_header, sizeof(unsigned char));

//     return (size_t) ((version_ihl & 0b1111) * 4);  // FIXME endianess?
// }

void formatted_mac(const uint8_t* mac, char* out) {
    // FF:FF:FF:FF:FF:FF
    // out needs to be 18 bytes large

    // TODO this is dangerous
    sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_mac(const uint8_t* mac) {
    char format[17 + 1];
    formatted_mac(mac, format);

    printf("%s\n", format);
}

void print_all_macs(const SniffedMacs* macs) {
    char source[17 + 1];
    char destination[17 + 1];

    for (size_t i = 0; i < macs->count; i++) {
        formatted_mac(macs->mac_pairs[i].source, source);
        formatted_mac(macs->mac_pairs[i].destination, destination);

        printf("src MAC: %s ---> dest MAC: %s\n", source, destination);
    }
}

void store_mac_pair(const uint8_t* mac_source, const uint8_t* mac_destination, unsigned char* restrict user) {  // TODO ?
    SniffedMacs macs;

    // Read
    memcpy(&macs, user, sizeof(SniffedMacs));

    // Modify
    MacPair pair;
    memcpy(pair.source, mac_source, ETHERNET_ADDRESS_SIZE);
    memcpy(pair.destination, mac_destination, ETHERNET_ADDRESS_SIZE);

    macs.mac_pairs[macs.count] = pair;
    macs.count++;

    // Write back
    memcpy(user, &macs, sizeof(SniffedMacs));
}

void packet_sniffed(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* packet) {
    (void) header;  // Ignore

    // https://en.wikipedia.org/wiki/Ethernet_frame

    struct ether_header ethernet;  // Ethernet header
    // struct sniff_ip ip;  // IP header

    // Header sizes
    const size_t size_ethernet = 14;
    // size_t size_ip = 0;
    // size_t size_tcp = 0;

    // Obtain the data safely
    memcpy(&ethernet, packet, size_ethernet);
    // size_ip = ip_ihl(packet + size_ethernet);
    // memcpy(&ip, packet + size_ethernet, size_ip);

    // Print MACs as they come
    printf("s: ");
    print_mac(ethernet.ether_shost);
    printf("d: ");
    print_mac(ethernet.ether_dhost);

    // Store MACs for later
    store_mac_pair(ethernet.ether_shost, ethernet.ether_dhost, user);
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "No device provided\n");
        return 1;
    }

    const char* device = argv[1];

    char err_msg[PCAP_ERRBUF_SIZE];

    // Create a session for sniffing
    pcap_t* session_handle = pcap_open_live(device, 1024 * 4, 1, 2000, err_msg);

    if (session_handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, err_msg);
        return 1;
    }

    // Check the type of data-link headers
    const int headers_type = pcap_datalink(session_handle);

    if (headers_type != DLT_EN10MB) {
        fprintf(stderr, "Device %s does not provide Ethernet headers", device);
        goto err_session;
    }

    // Allocate memory for sniffed data
    SniffedMacs macs;
    init_sniffed_macs(&macs, 10);

    printf("Starting sniffing...\n");

    // Sniff only 10 packets, blocking mode
    const int result = pcap_loop(session_handle, 10, packet_sniffed, (unsigned char*) &macs);

    switch (result) {
        case 0:
            print_all_macs(&macs);
            printf("Successfully sniffed all packets\n");
            break;
        case PCAP_ERROR_BREAK:
        case PCAP_ERROR_NOT_ACTIVATED:
        case PCAP_ERROR:
            print_all_macs(&macs);
            printf("An error occurred\n");
            break;
    }

    deinit_sniffed_macs(&macs);

err_session:
    pcap_close(session_handle);
}
