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

void formatted_mac(const uint8_t* mac, char* out) {
    // FF:FF:FF:FF:FF:FF
    // out needs to be 18 bytes large

    // TODO this is dangerous
    sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_mac(const uint8_t* mac, const char* end) {
    // end must be a null terminated string

    char format[17 + 1];
    formatted_mac(mac, format);

    printf("%s%s", format, end);
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
    SniffedMacs macs = {0};

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

    const size_t size_ethernet = 14;
    struct ether_header ethernet;

    // Obtain the data safely
    memcpy(&ethernet, packet, size_ethernet);

    // Print MACs as they come
    printf("s: ");
    print_mac(ethernet.ether_shost, "");
    printf(" -- d: ");
    print_mac(ethernet.ether_dhost, "\n");

    // Store MACs for later
    store_mac_pair(ethernet.ether_shost, ethernet.ether_dhost, user);
}

int is_little_endian() {
    const volatile uint32_t whatever = 0x0001;
    return ((const volatile uint8_t*) &whatever)[0] == 1;
}

pcap_t* initialize_session(const char* device) {
    char err_msg[PCAP_ERRBUF_SIZE];

    if (pcap_init(PCAP_CHAR_ENC_UTF_8, err_msg) == PCAP_ERROR) {  // TODO deinit?
        fprintf(stderr, "Could not initialize pcap: %s\n", err_msg);
        return NULL;
    }

    // Create a session for sniffing
    pcap_t* handle = pcap_create(device, err_msg);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, err_msg);
        return NULL;
    }

    // Set options for handle
    if (pcap_set_snaplen(handle, 65535) == PCAP_ERROR_ACTIVATED) {
        fprintf(stderr, "Could not set snaplen: %s\n", err_msg);
        goto err_handle;
    }

    if (pcap_set_promisc(handle, 1) == PCAP_ERROR_ACTIVATED) {
        fprintf(stderr, "Could not set promisc: %s\n", err_msg);
        goto err_handle;
    }

    if (pcap_set_timeout(handle, 1000) == PCAP_ERROR_ACTIVATED) {
        fprintf(stderr, "Could not set timeout: %s\n", err_msg);
        goto err_handle;
    }

    if (pcap_set_buffer_size(handle, 4096) == PCAP_ERROR_ACTIVATED) {
        fprintf(stderr, "Could not set buffer_size: %s\n", err_msg);
        goto err_handle;
    }

    // After all options, activate the handle
    const int result = pcap_activate(handle);

    if (result > 0) {
        printf("Warning: %d\n", result);
    } if (result < 0) {
        fprintf(stderr, "An error occurred: %d\n", result);
        goto err_handle;
    }

    // Then check the type of data-link headers
    const int headers_type = pcap_datalink(handle);

    if (headers_type != DLT_EN10MB) {
        fprintf(stderr, "Device %s does not provide Ethernet headers\n", device);
        goto err_handle;
    }

    return handle;

err_handle:
    pcap_close(handle);
    return NULL;
}

void sniff(pcap_t* handle, int sniff_count, SniffedMacs* macs) {
    printf("Starting sniffing...\n");

    // https://www.tcpdump.org/manpages/libpcap-1.10.4/pcap_loop.3pcap.html
    const int result = pcap_loop(handle, sniff_count, packet_sniffed, (unsigned char*) macs);  // Blocking mode

    switch (result) {
        case 0:
            print_all_macs(macs);
            printf("Sniffed all packets\n");
            break;
        case PCAP_ERROR_BREAK:
        case PCAP_ERROR_NOT_ACTIVATED:
        case PCAP_ERROR:
            print_all_macs(macs);
            printf("An error occurred\n");
            break;
    }
}

int main(int argc, char** argv) {
    printf("Is little endian: %d\n", is_little_endian());

    if (argc != 2) {
        fprintf(stderr, "No device provided\n");
        return 1;
    }

    const char* device = argv[1];

    pcap_t* handle = initialize_session(device);

    if (!handle) {
        return 1;
    }

    const int SNIFF_COUNT = 20;

    // Allocate memory for sniffed data
    SniffedMacs macs;
    init_sniffed_macs(&macs, SNIFF_COUNT);

    sniff(handle, SNIFF_COUNT, &macs);

    deinit_sniffed_macs(&macs);

    pcap_close(handle);
}
