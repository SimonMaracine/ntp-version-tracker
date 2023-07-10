#ifndef CAPTURE_SESSION
#define CAPTURE_SESSION

#include <net/ethernet.h>

struct pcap;
typedef struct pcap pcap_t;

typedef void(*PacketCaped)(const struct ether_header* ethernet_header, void* user);

typedef struct {
    pcap_t* handle;
    const char* device_or_file;

    PacketCaped callback;
    void* user_data;
} CapSession;

typedef enum {
    CapDevice,
    CapFile,
} CapType;

int cap_initialize_session(CapSession* session, const char* device_or_file, CapType type);
void cap_uninitialize_session(CapSession* session);

int cap_capture(CapSession* session, PacketCaped callback, void* user);

void cap_stop_signal();
const char* cap_get_pcap_version();

#endif
