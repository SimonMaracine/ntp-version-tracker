#ifndef CAPTURE_SESSION
#define CAPTURE_SESSION

#include <stdbool.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "ntp.h"

typedef struct {
    const struct ether_header* ethernet_header;
    const struct ip* ipv4_header;  // Without options
    const struct udphdr* udp_header;
    const NtpHeader* ntp_header;  // Without authentication (last field)
} CapPacketHeaders;

typedef void(*CapPacketCaptured)(const CapPacketHeaders* headers, void* user);

typedef enum {
    CapDevice,
    CapFile
} CapType;

typedef struct {
    void* handle;  // pcap_t

    const char* device_or_file;
    CapType type;
    bool verbose;

    CapPacketCaptured callback;
    void* user_data;

    CapPacketHeaders headers;
} CapSession;

int cap_initialize_session(CapSession* session, const char* device_or_file, CapType type,
    const char* filter, bool verbose);
void cap_uninitialize_session(CapSession* session);

int cap_start_capture(CapSession* session, CapPacketCaptured callback, void* user);

void cap_stop_signal();
const char* cap_get_pcap_version();

#endif
