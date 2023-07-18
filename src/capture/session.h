#ifndef CAPTURE_SESSION
#define CAPTURE_SESSION

#include <stdbool.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "ntp.h"

/**
 * A struct holding pointers to the protocol headers. It is used by the callback function.
 * Check for NULL to see which protocols a packet contains.
*/
typedef struct {
    const struct ether_header* ethernet_header;
    const struct ip* ipv4_header;  // Without options
    const struct udphdr* udp_header;
    const NtpHeader* ntp_header;  // Without authentication (last field)
} CapPacketHeaders;

/**
 * Callback function prototype.
*/
typedef void(*CapPacketCaptured)(const CapPacketHeaders* headers, void* user);

/**
 * Constants indicating the session type.
*/
typedef enum {
    CapDevice,
    CapFile
} CapType;

/**
 * Struct holding the session context data. The allocated struct's lifetime must comprise both
 * cap_initialize_session and cap_uninitialize_session.
 *
 * @see CapType
 * @see CapPacketCaptured
 * @see CapPacketHeaders
*/
typedef struct {
    void* handle;  // pcap_t

    const char* device_or_file;
    CapType type;
    bool verbose;

    CapPacketCaptured callback;
    void* user_data;

    CapPacketHeaders headers;
} CapSession;

/**
 * Initialize the capture or reading session.
 *
 * @param session a pointer to a struct holding data related the the session
 * @param device_or_file a static string representing the device name or the save file path
 * @param type the session type
 * @param filter a string representing the filter used by pcap; can be NULL, which means no filter
 * @param verbose a flag indicating verbose output or not
 * @return 0 on success, -1 on error
 * @see CapSession
 * @see CapType
*/
int cap_initialize_session(CapSession* session, const char* device_or_file, CapType type,
    const char* filter, bool verbose);

/**
 * Uninitialize the capture or reading session.
 *
 * @param session a pointer to the struct previously initialized by cap_initialize_session
 * @see cap_initialize_session
*/
void cap_uninitialize_session(CapSession* session);

/**
 * Start the capture or reading session loop.
 *
 * @param session a pointer to the struct previously initialized by cap_initialize_session
 * @param callback a function called for every packet captured or read
 * @param user a pointer to arbitrary data, that is passed to the callback function
 * @return 0 on success, -1 on error
 * @see cap_initialize_session
 * @see CapSession
 * @see CapPacketCaptured
*/
int cap_start_capture(CapSession* session, CapPacketCaptured callback, void* user);

/**
 * Stop the capture or reading loop. It can be called from other threads or from interrupts.
*/
void cap_stop_signal(void);

/**
 * Get a string representing the pcap version.
 *
 * @return a version string
*/
const char* cap_get_pcap_version(void);

#endif
