#ifndef SNIFF_SESSION
#define SNIFF_SESSION

#include <net/ethernet.h>

struct pcap;
typedef struct pcap pcap_t;

typedef void(*PacketSniffed)(const struct ether_header* ethernet_header, void* user);

typedef struct {
    pcap_t* handle;

    PacketSniffed callback;
    void* user_data;
} SniffSession;

int initialize_session(SniffSession* session, const char* device);
void deinitialize_session(SniffSession* session);

int sniff_blocking(SniffSession* session, int sniff_count, PacketSniffed callback, void* user);
int sniff_nonblocking(SniffSession* session, PacketSniffed callback, void* user);

#endif
