#ifndef PROCESSING_H
#define PROCESSING_H

#include <pcap/pcap.h>

void process_packet(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* packet);

#endif
