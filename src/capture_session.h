#ifndef CAPTURE_SESSION
#define CAPTURE_SESSION

#include <net/ethernet.h>

struct pcap;
typedef struct pcap pcap_t;

typedef void(*CapPacketCaptured)(const struct ether_header* ethernet_header, void* user);

typedef enum {
    CapDevice,
    CapFile
} CapType;

typedef struct {
    pcap_t* handle;
    const char* device_or_file;
    CapType type;

    CapPacketCaptured callback;
    void* user_data;
} CapSession;


int cap_initialize_session(CapSession* session, const char* device_or_file, CapType type);
void cap_uninitialize_session(CapSession* session);

int cap_start_capture(CapSession* session, CapPacketCaptured callback, void* user);

void cap_stop_signal();
const char* cap_get_pcap_version();

#endif
