#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>

#include "processing.h"
#include "session.h"
#include "ntp.h"
#include "../logging.h"

#define ETHERNET_HEADER_SIZE ETH_HLEN

static const struct ether_header* process_ethernet(const struct pcap_pkthdr* header,
        const unsigned char* packet, unsigned int* pointer) {
    if (header->caplen < *pointer + ETHERNET_HEADER_SIZE) {
        return NULL;
    }

    const struct ether_header* ethernet_header = (const struct ether_header*) (packet + *pointer);

    *pointer += ETHERNET_HEADER_SIZE;
    return ethernet_header;
}

static const struct ip* process_ipv4(const struct pcap_pkthdr* header, const unsigned char* packet,
        unsigned int* pointer) {
    const unsigned int MIN_HEADER_SIZE = 20;

    if (header->caplen < *pointer + MIN_HEADER_SIZE) {
        return NULL;
    }

    const struct ip* ip_header = (const struct ip*) (packet + *pointer);

    if (ip_header->ip_v != 4) {
        // No IPv4
        return NULL;
    }

    if (ip_header->ip_hl * 4 < MIN_HEADER_SIZE) {
        // Invalid header size
        return NULL;
    }

    // Don't care about options

    *pointer += ip_header->ip_hl * 4;
    return ip_header;
}

static const struct udphdr* process_udp(const struct pcap_pkthdr* header, const unsigned char* packet,
        unsigned int* pointer) {
    const unsigned int HEADER_SIZE = sizeof(struct udphdr);

    if (header->caplen < *pointer + HEADER_SIZE) {
        return NULL;
    }

    const struct udphdr* udp_header = (const struct udphdr*) (packet + *pointer);

    if (udp_header->len < HEADER_SIZE) {
        // Invalid header size
        return NULL;
    }

    *pointer += HEADER_SIZE;
    return udp_header;
}

static const NtpHeader* process_ntp(const struct pcap_pkthdr* header, const unsigned char* packet,
        unsigned int* pointer) {
    const unsigned int HEADER_SIZE = sizeof(NtpHeader);

    if (header->caplen < *pointer + HEADER_SIZE) {
        return NULL;
    }

    return (const NtpHeader*) packet;
}

void captured_packet(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* packet) {
    // https://en.wikipedia.org/wiki/Ethernet_frame
    // https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Header
    // https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    // https://en.wikipedia.org/wiki/User_Datagram_Protocol
    // https://www.eecis.udel.edu/~mills/database/rfc/rfc1305/rfc1305c.pdf
    // http://what-when-how.com/computer-network-time-synchronization/ntp-packet-header-ntp-reference-implementation-computer-network-time-synchronization/

    unsigned int pointer = 0;  // Incremented every time a header is processed
    CapSession* session = (CapSession*) user;

    const struct ether_header* ethernet_header = process_ethernet(header, packet, &pointer);

    if (ethernet_header == NULL) {
        log_print("(No Ethernet header)\n");
        return;
    }

    if (session->callback_ethernet != NULL) {
        session->callback_ethernet(ethernet_header, session->user_data);
    }

    const struct ip* ip_header = process_ipv4(header, packet, &pointer);

    if (ip_header == NULL) {
        log_print("(No IPv4 header)\n");
        return;
    }

    if (session->callback_ipv4 != NULL) {
        session->callback_ipv4(ip_header, session->user_data);
    }

    if (ip_header->ip_p != 17) {
        log_print("(No UDP header)\n");
        return;
    }

    const struct udphdr* udp_header = process_udp(header, packet, &pointer);

    if (udp_header == NULL) {
        log_print("(No UDP header)\n");
        return;
    }

    if (session->callback_udp != NULL) {
        session->callback_udp(udp_header, session->user_data);
    }

    if (udp_header->source != 123 && udp_header->dest != 123) {
        log_print("(No NTP header)\n");
        return;
    }

    const NtpHeader* ntp_header = process_ntp(header, packet, &pointer);

    if (ntp_header == NULL) {
        log_print("(No NTP header)\n");
        return;
    }

    if (session->callback_ntp != NULL) {
        session->callback_ntp(ntp_header, session->user_data);
    }
}
