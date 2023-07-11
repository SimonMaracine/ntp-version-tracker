#ifndef CAPTURE_SESSION
#define CAPTURE_SESSION

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

typedef void(*CapPacketCaptured)(const CapPacketHeaders* headers, unsigned int available, void* user);

typedef enum {
    CapDevice,
    CapFile
} CapType;

typedef enum {
    CapAvailableEthernet = 1 << 0,
    CapAvailableIpv4 = 1 << 1,
    CapAvailableUdp = 1 << 2,
    CapAvailableNtp = 1 << 3
} CapAvailableHeader;

typedef struct {
    void* handle;  // pcap_t handle
    const char* device_or_file;
    CapType type;

    CapPacketCaptured callback;
    void* user_data;

    CapPacketHeaders headers;
} CapSession;

int cap_initialize_session(CapSession* session, const char* device_or_file, CapType type);
void cap_uninitialize_session(CapSession* session);

int cap_start_capture(CapSession* session, CapPacketCaptured callback, void* user);

void cap_stop_signal();
const char* cap_get_pcap_version();

#endif
