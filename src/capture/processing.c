#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>

#include "processing.h"
#include "session.h"
#include "../logging.h"

#define ETHERNET_HEADER_SIZE ETH_HLEN

static const struct ether_header* process_ethernet(const struct pcap_pkthdr* header,
        const unsigned char* packet) {
    if (header->caplen < ETHERNET_HEADER_SIZE) {
        return NULL;
    }

    return (const struct ether_header*) packet;
}

static const struct ip* process_ipv4(const struct pcap_pkthdr* header, const unsigned char* packet) {
    const unsigned int MIN_HEADER_SIZE = 20;

    if (header->caplen < ETHERNET_HEADER_SIZE + MIN_HEADER_SIZE) {
        return NULL;
    }

    const struct ip* ip_header = (const struct ip*) (packet + ETHERNET_HEADER_SIZE);

    if (ip_header->ip_v != 4) {
        // No IPv4
        return NULL;
    }

    if (ip_header->ip_hl * 4 < MIN_HEADER_SIZE) {
        // Invalid header size
        return NULL;
    }

    // Don't care about options

    return ip_header;
}

static const struct udphdr* process_udp(const struct pcap_pkthdr* header, const unsigned char* packet,
        unsigned int ip_header_size) {
    const unsigned int HEADER_SIZE = 8;

    if (header->caplen < ETHERNET_HEADER_SIZE + ip_header_size + HEADER_SIZE) {
        return NULL;
    }

    const struct udphdr* udp_header = (
        (const struct udphdr*) (packet + ETHERNET_HEADER_SIZE + ip_header_size)
    );

    if (udp_header->len < HEADER_SIZE) {
        // Invalid header size
        return NULL;
    }

    return udp_header;
}

// static const void* process_ntp(const struct pcap_pkthdr* header, const unsigned char* packet,
//         unsigned int ip_header_size, unsigned int udp_header_size) {
//     return NULL;
// }

void captured_packet(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* packet) {
    // https://en.wikipedia.org/wiki/Ethernet_frame
    // https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Header
    // https://en.wikipedia.org/wiki/User_Datagram_Protocol
    // http://what-when-how.com/computer-network-time-synchronization/ntp-packet-header-ntp-reference-implementation-computer-network-time-synchronization/

    CapSession* session = (CapSession*) user;

    const struct ether_header* ethernet_header = process_ethernet(header, packet);

    if (ethernet_header == NULL) {
        log_print("No Ethernet header\n");
        return;
    }

    if (session->callback_ethernet != NULL) {
        session->callback_ethernet(ethernet_header, session->user_data);
    }

    const struct ip* ip_header = process_ipv4(header, packet);

    if (ip_header == NULL) {
        log_print("No IPv4 header\n");
        return;
    }

    if (session->callback_ipv4 != NULL) {
        session->callback_ipv4(ip_header, session->user_data);
    }

    if (ip_header->ip_p != 17) {  // TODO
        log_print("No UDP header\n");
        return;
    }

    const struct udphdr* udp_header = process_udp(header, packet, ip_header->ip_hl * 4);

    if (udp_header == NULL) {
        log_print("No UDP header\n");
        return;
    }

    if (session->callback_udp != NULL) {
        session->callback_udp(udp_header, session->user_data);
    }

    // TODO NTP header
}
