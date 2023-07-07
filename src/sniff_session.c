#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <signal.h>
#include <sys/select.h>
#include <time.h>
#include <errno.h>

#include "sniff_session.h"
#include "logging.h"

// Flag indicating if to keep sniffing
static volatile sig_atomic_t running = 1;

static int set_options(pcap_t* handle) {
    if (pcap_set_snaplen(handle, 65535) == PCAP_ERROR_ACTIVATED) {
        log_print("Could not set snaplen\n");
        return -1;
    }

    if (pcap_set_promisc(handle, 1) == PCAP_ERROR_ACTIVATED) {
        log_print("Could not set promisc\n");
        return -1;
    }

    if (pcap_set_timeout(handle, 1000) == PCAP_ERROR_ACTIVATED) {
        log_print("Could not set timeout\n");
        return -1;
    }

    if (pcap_set_buffer_size(handle, 4096) == PCAP_ERROR_ACTIVATED) {
        log_print("Could not set buffer_size\n");
        return -1;
    }

    return 0;
}

static pcap_t* initialize_handle(const char* device) {
    char err_msg[PCAP_ERRBUF_SIZE];

    // Create a session for sniffing
    pcap_t* handle = pcap_create(device, err_msg);

    if (handle == NULL) {
        log_print("Could not open device `%s`: %s\n", device, err_msg);
        return NULL;
    }

    if (set_options(handle) < 0) {
        goto err_handle;
    }

    // After all options, activate the handle
    const int result = pcap_activate(handle);

    if (result > 0) {
        log_print("Warning on activating device `%s`: %d\n", device, result);
    } if (result < 0) {
        log_print("An error occurred activating device `%s`: %d\n", device, result);
        goto err_handle;
    }

    // Then check the type of data-link headers
    const int headers_type = pcap_datalink(handle);

    if (headers_type != DLT_EN10MB) {
        log_print("Device `%s` does not provide Ethernet headers\n", device);
        goto err_handle;
    }

    return handle;

err_handle:
    pcap_close(handle);
    return NULL;
}

static void packet_sniffed(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* packet) {
    (void) header;  // Ignore

    // https://en.wikipedia.org/wiki/Ethernet_frame

    const struct ether_header* ethernet_header = (const struct ether_header*) packet;

    SniffSession* session = (SniffSession*) user;
    session->callback(ethernet_header, session->user_data);
}

// Call this every time sniffing begins
static void reset_callback(SniffSession* session, PacketSniffed callback, void* user) {
    session->callback = callback;
    session->user_data = user;
}

int sniff_initialize_session(SniffSession* session, const char* device) {
    // Argument device must be a literal string
    // Logging must have been initialized already

    char err_msg[PCAP_ERRBUF_SIZE];

    if (pcap_init(PCAP_CHAR_ENC_UTF_8, err_msg) == PCAP_ERROR) {
        log_print("Could not initialize pcap: %s\n", err_msg);
        return -1;
    }

    // This function does all the cleaning, in case of error
    pcap_t* handle = initialize_handle(device);

    if (handle == NULL) {
        return -1;
    }

    session->handle = handle;
    session->device = device;

    return 0;
}

void sniff_uninitialize_session(SniffSession* session) {
    pcap_close(session->handle);
}

void sniff_stop_signal() {
    running = 0;
}

// https://www.tcpdump.org/manpages/libpcap-1.10.4/pcap_loop.3pcap.html

int sniff_blocking(SniffSession* session, int sniff_count, PacketSniffed callback, void* user) {
    reset_callback(session, callback, user);

    log_print("STARTING sniffing on device `%s`\n", session->device);

    const int result = pcap_loop(session->handle, sniff_count, packet_sniffed, (unsigned char*) session);

    switch (result) {
        case 0:
            log_print("Sniffed all packets\n");
            break;
        case PCAP_ERROR_BREAK:
        case PCAP_ERROR_NOT_ACTIVATED:
        case PCAP_ERROR:
            log_print("An error occurred\n");
            break;
    }

    log_print("STOPPED sniffing on device `%s`\n", session->device);

    return 0;
}

int sniff(SniffSession* session, PacketSniffed callback, void* user) {
    reset_callback(session, callback, user);

    log_print("STARTING sniffing on device `%s`\n", session->device);

    char err_msg[PCAP_ERRBUF_SIZE];

    if (pcap_setnonblock(session->handle, 1, err_msg) < 0) {
        log_print("Could not set session in non-blocking mode: %s\n", err_msg);
        return -1;
    }

    const int fd = pcap_get_selectable_fd(session->handle);

    if (fd < 0) {
        log_print("Could not retrieve file descriptor\n");
        return -1;
    }

    // Set a timeout of 1 second
    struct timespec ts = {0};
    ts.tv_sec = 1;

    // Used to unblock SIGINT during pselect
    sigset_t empty_set;
    sigemptyset(&empty_set);

    // Block SIGINT signals by default
    sigset_t block_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGINT);

    // Set the signal mask
    if (sigprocmask(SIG_BLOCK, &block_set, NULL) < 0) {
        log_print("Error blocking interrupt signal\n");
        return -1;
    }

    while (running) {
        fd_set files;
        FD_ZERO(&files);
        FD_SET(fd, &files);

        // Block at most 1 second
        const int result = pselect(fd + 1, &files, NULL, NULL, &ts, &empty_set);

        if (result < 0 && errno != EINTR) {
            log_print("An error occurred in pselect\n");
            continue;
        }

        // Check if there is anything to read
        if (FD_ISSET(fd, &files)) {
            const int result = pcap_dispatch(session->handle, 0, packet_sniffed, (unsigned char*) session);

            if (result < 0) {
                log_print("An error occurred sniffing packets\n");
                continue;
            }

            log_print("Sniffed %d packet(s)\n", result);
        }
    }

    log_print("STOPPED sniffing on device `%s`\n", session->device);

    return 0;
}
