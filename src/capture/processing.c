#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <assert.h>
#include <string.h>

#include "processing.h"
#include "session.h"
#include "ntp.h"
#include "../logging.h"

// https://en.wikipedia.org/wiki/Ethernet_frame
// https://en.wikipedia.org/wiki/EtherType#Values
// https://wiki.wireshark.org/Ethernet
// https://www.firewall.cx/networking/ethernet/ieee-8023-snap-frame.html
// https://www.ibm.com/support/pages/ethernet-version-2-versus-ieee-8023-ethernet
// https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Header
// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
// https://en.wikipedia.org/wiki/User_Datagram_Protocol
// https://en.wikipedia.org/wiki/Network_Time_Protocol
// https://www.eecis.udel.edu/~mills/database/rfc/rfc1305/rfc1305c.pdf
// http://what-when-how.com/computer-network-time-synchronization/ntp-packet-header-ntp-reference-implementation-computer-network-time-synchronization/

#define ETHERNET_HEADER_SIZE ETH_HLEN

static const struct ether_header* check_ethernet(const struct pcap_pkthdr* header,
        const unsigned char* packet, unsigned int* pointer) {
    if (header->caplen < *pointer + ETHERNET_HEADER_SIZE) {
        return NULL;
    }

    const struct ether_header* ethernet_header = (const struct ether_header*) (packet + *pointer);

    *pointer += ETHERNET_HEADER_SIZE;
    return ethernet_header;
}

static const struct ip* check_ip(const struct pcap_pkthdr* header, const unsigned char* packet,
        unsigned int* pointer) {
    const unsigned int MIN_HEADER_SIZE = 20;

    if (header->caplen < *pointer + MIN_HEADER_SIZE) {
        return NULL;
    }

    const struct ip* ip_header = (const struct ip*) (packet + *pointer);

    if (ip_header->ip_hl * 4 < MIN_HEADER_SIZE) {
        // Invalid header size
        return NULL;
    }

    // Don't care about options

    *pointer += ip_header->ip_hl * 4;
    return ip_header;
}

static const struct udphdr* check_udp(const struct pcap_pkthdr* header, const unsigned char* packet,
        unsigned int* pointer) {
    const unsigned int HEADER_SIZE = sizeof(struct udphdr);

    if (header->caplen < *pointer + HEADER_SIZE) {
        return NULL;
    }

    const struct udphdr* udp_header = (const struct udphdr*) (packet + *pointer);

    if (ntohs(udp_header->len) < HEADER_SIZE) {
        // Invalid datagram size
        return NULL;
    }

    *pointer += HEADER_SIZE;
    return udp_header;
}

static const NtpHeader* check_ntp(const struct pcap_pkthdr* header, const unsigned char* packet,
        unsigned int* pointer) {
    const unsigned int HEADER_SIZE = sizeof(NtpHeader);

    if (header->caplen < *pointer + HEADER_SIZE) {
        return NULL;
    }

    return (const NtpHeader*) (packet + *pointer);
}

static int get_ethernet_type(const struct ether_header* ethernet_header, uint16_t* ethernet_type) {
    const uint16_t type = ntohs(ethernet_header->ether_type);

    if (type >= 1536) {  // Ethernet II
        *ethernet_type = type;
    } else if (type <= 1500) {  // Ethernet 802.3
        *ethernet_type = 0;
        return -1;
    } else {  // Invalid
        return -1;
    }

    return 0;
}

void process_packet(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* packet) {
    CapSession* session = (CapSession*) user;
    unsigned int pointer = 0;  // Incremented every time a header is processed

    memset(&session->headers, 0, sizeof(CapPacketHeaders));

    session->headers.ethernet_header = check_ethernet(header, packet, &pointer);

    if (session->headers.ethernet_header == NULL) {
        LOG_IF_VERBOSE log_print("(No Ethernet)\n");
        goto stop_and_call;
    }

    uint16_t ethernet_type = 0;
    if (get_ethernet_type(session->headers.ethernet_header, &ethernet_type) < 0) {
        LOG_IF_VERBOSE log_print("(No Ethernet II\n");
        session->headers.ethernet_header = NULL;
        goto stop_and_call;
    }

    if (ethernet_type != ETHERTYPE_IP) {
        LOG_IF_VERBOSE log_print("(No IPv4; protocol is %u)\n", ethernet_type);
        goto stop_and_call;
    }

    session->headers.ipv4_header = check_ip(header, packet, &pointer);

    if (session->headers.ipv4_header == NULL) {
        LOG_IF_VERBOSE log_print("(No IP)\n");
        goto stop_and_call;
    }

    assert(session->headers.ipv4_header->ip_v == 4);  // IPv4 is checked above

    if (session->headers.ipv4_header->ip_p != 17) {
        LOG_IF_VERBOSE log_print("(No UDP; protocol is %u)\n", session->headers.ipv4_header->ip_p);
        goto stop_and_call;
    }

    session->headers.udp_header = check_udp(header, packet, &pointer);

    if (session->headers.udp_header == NULL) {
        LOG_IF_VERBOSE log_print("(No UDP)\n");
        goto stop_and_call;
    }

    if (ntohs(session->headers.udp_header->source) != 123 && ntohs(session->headers.udp_header->dest) != 123) {
        LOG_IF_VERBOSE log_print(
            "(No NTP; ports are %u -> %u)\n",
            ntohs(session->headers.udp_header->source),
            ntohs(session->headers.udp_header->dest)
        );
        goto stop_and_call;
    }

    session->headers.ntp_header = check_ntp(header, packet, &pointer);

    if (session->headers.ntp_header == NULL) {
        LOG_IF_VERBOSE log_print("(No NTP)\n");
        goto stop_and_call;
    }

stop_and_call:
    session->callback(&session->headers, session->user_data);
}
