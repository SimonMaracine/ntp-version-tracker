#ifndef SNIFF_SESSION
#define SNIFF_SESSION

#include <net/ethernet.h>

struct pcap;
typedef struct pcap pcap_t;

typedef void(*PacketSniffed)(const struct ether_header* ethernet_header, void* user);

typedef struct {
    pcap_t* handle;
    const char* device_or_file;

    PacketSniffed callback;
    void* user_data;
} SniffSession;

typedef enum {
    SniffDevice,
    SniffFile,
} SniffType;

int sniff_initialize_session(SniffSession* session, const char* device_or_file, SniffType type);
void sniff_uninitialize_session(SniffSession* session);

int sniff(SniffSession* session, PacketSniffed callback, void* user);

void sniff_stop_signal();
const char* sniff_get_pcap_version();

#endif
