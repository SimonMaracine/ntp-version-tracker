#include <pcap/pcap.h>
#include <signal.h>
#include <sys/select.h>
#include <time.h>
#include <errno.h>

#include "session.h"
#include "processing.h"
#include "../logging.h"

// Flag indicating if to keep capturing
static volatile sig_atomic_t running = 1;

static int set_options(pcap_t* handle) {
    // These options for capturing devices are hardcoded for now

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

static pcap_t* initialize_handle(const char* device_or_file, CapType type) {
    char err_msg[PCAP_ERRBUF_SIZE];

    // Create a session for capturing
    pcap_t* handle = NULL;

    switch (type) {
        case CapDevice:
            handle = pcap_create(device_or_file, err_msg);
            break;
        case CapFile:
            handle = pcap_open_offline(device_or_file, err_msg);
            break;
    }

    if (handle == NULL) {
        log_print("Could not open device `%s`: %s\n", device_or_file, err_msg);
        return NULL;
    }

    if (type == CapFile) {
        // Done with initialization for save file
        return handle;
    }

    if (set_options(handle) < 0) {
        goto err_handle;
    }

    // After all options, activate the handle
    const int result = pcap_activate(handle);

    if (result > 0) {
        log_print("Warning on activating device `%s`: %d\n", device_or_file, result);
    } if (result < 0) {
        log_print("An error occurred activating device `%s`: %d\n", device_or_file, result);
        goto err_handle;
    }

    // Then check the type of data-link headers
    const int headers_type = pcap_datalink(handle);

    if (headers_type != DLT_EN10MB) {
        log_print("Device `%s` does not provide Ethernet headers\n", device_or_file);
        goto err_handle;
    }

    return handle;

err_handle:
    pcap_close(handle);

    return NULL;
}

// https://www.tcpdump.org/manpages/libpcap-1.10.4/pcap_loop.3pcap.html

static int capture_device_loop(CapSession* session) {
    log_print("STARTING capturing on device `%s`\n", session->device_or_file);

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
            const int result = pcap_dispatch(
                session->handle, 0, captured_packet, (unsigned char*) session
            );

            if (result < 0) {
                log_print("An error occurred capturing packets\n");
                continue;
            }

            log_print("Captured %d packet(s)\n", result);
        }
    }

    log_print("STOPPED capturing on device `%s`\n", session->device_or_file);

    return 0;
}

static int capture_file_loop(CapSession* session) {
    log_print("STARTING reading save file `%s`\n", session->device_or_file);

    if (pcap_loop(session->handle, 0, captured_packet, (unsigned char*) session) < 0) {
        log_print("An error occurred reading packets from save file `%s`\n", session->device_or_file);
        return -1;
    }

    log_print("STOPPED reading save file `%s`\n", session->device_or_file);

    return 0;
}

int cap_initialize_session(CapSession* session, const char* device_or_file, CapType type) {
    // Argument device_or_file must be a literal string
    // Logging must have been initialized already

    char err_msg[PCAP_ERRBUF_SIZE];

    if (pcap_init(PCAP_CHAR_ENC_UTF_8, err_msg) == PCAP_ERROR) {
        log_print("Could not initialize pcap: %s\n", err_msg);
        return -1;
    }

    // This function does all the cleaning, in case of error
    pcap_t* handle = initialize_handle(device_or_file, type);

    if (handle == NULL) {
        return -1;
    }

    session->handle = handle;
    session->device_or_file = device_or_file;
    session->type = type;

    return 0;
}

void cap_uninitialize_session(CapSession* session) {
    pcap_close(session->handle);
}

void cap_want_ethernet(CapSession* session, CapPacketCapturedEthernet callback) {
    session->callback_ethernet = callback;
    session->want_protocol |= CapEthernet;
}

void cap_want_ipv4(CapSession* session, CapPacketCapturedIpv4 callback) {
    session->callback_ipv4 = callback;
    session->want_protocol |= CapIpv4;
}

void cap_want_udp(CapSession* session, CapPacketCapturedUdp callback) {
    session->callback_udp = callback;
    session->want_protocol |= CapUdp;
}

void cap_want_ntp(CapSession* session, CapPacketCapturedNtp callback) {
    session->callback_ntp = callback;
    session->want_protocol |= CapNtp;
}

int cap_start_capture(CapSession* session, void* user) {
    session->user_data = user;

    int result = 0;

    switch (session->type) {
        case CapDevice:
            result = capture_device_loop(session);
            break;
        case CapFile:
            result = capture_file_loop(session);
            break;
    }

    return result;
}

void cap_stop_signal() {
    running = 0;
}

const char* cap_get_pcap_version() {
    return pcap_lib_version();
}
