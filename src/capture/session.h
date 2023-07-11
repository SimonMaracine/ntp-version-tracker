#ifndef CAPTURE_SESSION
#define CAPTURE_SESSION

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "ntp.h"

typedef void(*CapPacketCapturedEthernet)(const struct ether_header* header, void* user);
typedef void(*CapPacketCapturedIpv4)(const struct ip* header, void* user);  // Without options
typedef void(*CapPacketCapturedUdp)(const struct udphdr* header, void* user);
typedef void(*CapPacketCapturedNtp)(const NtpHeader* header, void* user);  // Without authentication

typedef enum {
    CapDevice,
    CapFile
} CapType;

typedef struct {
    void* handle;  // pcap_t handle
    const char* device_or_file;
    CapType type;

    CapPacketCapturedEthernet callback_ethernet;
    CapPacketCapturedIpv4 callback_ipv4;
    CapPacketCapturedUdp callback_udp;
    CapPacketCapturedNtp callback_ntp;
    void* user_data;
} CapSession;

int cap_initialize_session(CapSession* session, const char* device_or_file, CapType type);
void cap_uninitialize_session(CapSession* session);

void cap_want_ethernet(CapSession* session, CapPacketCapturedEthernet callback);
void cap_want_ipv4(CapSession* session, CapPacketCapturedIpv4 callback);
void cap_want_udp(CapSession* session, CapPacketCapturedUdp callback);
void cap_want_ntp(CapSession* session, CapPacketCapturedNtp callback);

int cap_start_capture(CapSession* session, void* user);

void cap_stop_signal();
const char* cap_get_pcap_version();

#endif
