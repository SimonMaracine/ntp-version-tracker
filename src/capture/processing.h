#ifndef PROCESSING_H
#define PROCESSING_H

#include <pcap/pcap.h>

void process_ether(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* packet);
void process_ether_ipv4(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* packet);
void process_ether_ipv4_udp(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* packet);
void process_ether_ipv4_udp_ntp(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* packet);

#endif
