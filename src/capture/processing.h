#ifndef PROCESSING_H
#define PROCESSING_H

#include <pcap/pcap.h>

/**
 * Callback function passed to pcap for packet processing.
*/
void process_packet(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* packet);

#endif
