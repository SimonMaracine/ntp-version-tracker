#include <pcap/pcap.h>
#include <signal.h>
#include <sys/select.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#include "session.h"
#include "processing.h"
#include "../logging.h"

// Flag indicating if to keep capturing
static volatile sig_atomic_t g_running = 1;

// Global pointer used by interrupt
static CapSession* g_session = NULL;

static int set_options(pcap_t* handle) {
    // These options for capturing devices are hardcoded for now

    if (pcap_set_snaplen(handle, 65535) == PCAP_ERROR_ACTIVATED) {
        printf("Could not set snaplen\n");
        return -1;
    }

    if (pcap_set_promisc(handle, 1) == PCAP_ERROR_ACTIVATED) {
        printf("Could not set promisc\n");
        return -1;
    }

    if (pcap_set_timeout(handle, 1000) == PCAP_ERROR_ACTIVATED) {
        printf("Could not set timeout\n");
        return -1;
    }

    if (pcap_set_buffer_size(handle, 4096) == PCAP_ERROR_ACTIVATED) {
        printf("Could not set buffer_size\n");
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
        printf("Could not open device `%s`: %s\n", device_or_file, err_msg);
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
        printf("Warning on activating device `%s`: %d\n", device_or_file, result);
    } if (result < 0) {
        printf("An error occurred activating device `%s`: %d\n", device_or_file, result);
        goto err_handle;
    }

    // Then check the type of data-link headers
    const int headers_type = pcap_datalink(handle);

    if (headers_type != DLT_EN10MB) {
        printf("Device `%s` does not provide Ethernet headers\n", device_or_file);
        goto err_handle;
    }

    return handle;

err_handle:
    pcap_close(handle);

    return NULL;
}

static int apply_filter(pcap_t* handle, const char* filter) {
    struct bpf_program filter_program = {0};

    if (pcap_compile(handle, &filter_program, filter, 0, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {  // TODO
        printf("Could not compile filter program `%s`: %s\n", filter, pcap_geterr(handle));
        return -1;
    }

    if (pcap_setfilter(handle, &filter_program) == PCAP_ERROR) {
        printf("Could not set filter program `%s` on handle: %s\n", filter, pcap_geterr(handle));
        return -1;
    }

    pcap_freecode(&filter_program);

    return 0;
}

static int set_non_blocking(CapSession* session, int* fd, struct timespec* ts, sigset_t* empty_set) {
    char err_msg[PCAP_ERRBUF_SIZE];

    if (pcap_setnonblock(session->handle, 1, err_msg) < 0) {
        printf("Could not set session in non-blocking mode: %s\n", err_msg);
        return -1;
    }

    *fd = pcap_get_selectable_fd(session->handle);

    if (*fd < 0) {
        printf("Could not retrieve file descriptor\n");
        return -1;
    }

    // Set a timeout of 1 second
    memset(ts, 0, sizeof(struct timespec));
    ts->tv_sec = 1;

    // Used to unblock SIGINT during pselect
    sigemptyset(empty_set);

    // Block SIGINT signals by default
    sigset_t block_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGINT);

    // Set the signal mask
    if (sigprocmask(SIG_BLOCK, &block_set, NULL) < 0) {
        printf("Error blocking interrupt signal\n");
        return -1;
    }

    return 0;
}

// https://www.tcpdump.org/manpages/libpcap-1.10.4/pcap_loop.3pcap.html

static int loop_capture_device(CapSession* session) {
    int fd = 0;
    struct timespec ts = {0};
    sigset_t empty_set = {0};

    if (set_non_blocking(session, &fd, &ts, &empty_set) < 0) {
        return -1;
    }

    log_print("STARTING to capture on device `%s`\n", session->device_or_file);

    while (g_running) {
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
            const int result = pcap_dispatch(session->handle, 0, process_packet, (unsigned char*) session);

            if (result == PCAP_ERROR_BREAK) {
                continue;
            }

            if (result < 0) {
                log_print("An error occurred capturing packets from device: %d\n", result);
                continue;
            }

            LOG_IF_VERBOSE log_print("%d packet(s) captured\n", result);
        }
    }

    log_print("STOPPED capturing on device `%s`\n", session->device_or_file);

    return 0;
}

static int loop_capture_file(CapSession* session) {
    log_print("STARTING to read save file `%s`\n", session->device_or_file);

    const int result = pcap_loop(session->handle, 0, process_packet, (unsigned char*) session);

    if (result < 0 && result != PCAP_ERROR_BREAK) {
        log_print("An error occurred reading packets from save file: %d\n", result);
        return -1;
    }

    log_print("STOPPED reading save file `%s`\n", session->device_or_file);

    return 0;
}

int cap_initialize_session(CapSession* session, const char* device_or_file, CapType type,
        const char* filter, bool verbose) {
    // Argument device_or_file must be a literal string
    // Logging must have been initialized already

    char err_msg[PCAP_ERRBUF_SIZE];

    if (pcap_init(PCAP_CHAR_ENC_UTF_8, err_msg) == PCAP_ERROR) {
        printf("Could not initialize pcap: %s\n", err_msg);
        return -1;
    }

    pcap_t* handle = initialize_handle(device_or_file, type);

    if (handle == NULL) {
        // Handle has been already closed
        return -1;
    }

    // Apply filters, if available
    if (filter != NULL) {
        if (apply_filter(handle, filter) < 0) {
            pcap_close(handle);
            return -1;
        }
    }

    session->handle = handle;
    session->device_or_file = device_or_file;
    session->type = type;
    session->verbose = verbose;

    g_session = session;

    return 0;
}

void cap_uninitialize_session(CapSession* session) {
    pcap_close(session->handle);

    g_session = NULL;
}

int cap_start_capture(CapSession* session, CapPacketCaptured callback, void* user) {
    session->callback = callback;
    session->user_data = user;

    int result = 0;

    switch (session->type) {
        case CapDevice:
            result = loop_capture_device(session);
            break;
        case CapFile:
            result = loop_capture_file(session);
            break;
    }

    return result;
}

void cap_stop_signal() {
    g_running = 0;

    if (g_session != NULL) {
        pcap_breakloop(g_session->handle);
    }
}

const char* cap_get_pcap_version() {
    return pcap_lib_version();
}
