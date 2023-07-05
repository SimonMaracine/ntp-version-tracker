#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>

#include "sniff_session.h"

static int set_options(pcap_t* handle) {
    if (pcap_set_snaplen(handle, 65535) == PCAP_ERROR_ACTIVATED) {
        fprintf(stderr, "Could not set snaplen\n");
        return -1;
    }

    if (pcap_set_promisc(handle, 1) == PCAP_ERROR_ACTIVATED) {
        fprintf(stderr, "Could not set promisc\n");
        return -1;
    }

    if (pcap_set_timeout(handle, 1000) == PCAP_ERROR_ACTIVATED) {
        fprintf(stderr, "Could not set timeout\n");
        return -1;
    }

    if (pcap_set_buffer_size(handle, 4096) == PCAP_ERROR_ACTIVATED) {
        fprintf(stderr, "Could not set buffer_size\n");
        return -1;
    }

    return 0;
}

static pcap_t* initialize_handle(const char* device) {
    char err_msg[PCAP_ERRBUF_SIZE];

    // Create a session for sniffing
    pcap_t* handle = pcap_create(device, err_msg);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, err_msg);
        return NULL;
    }

    if (set_options(handle) < 0) {
        goto err_handle;
    }

    // After all options, activate the handle
    const int result = pcap_activate(handle);

    if (result > 0) {
        printf("Warning: %d\n", result);
    } if (result < 0) {
        fprintf(stderr, "An error occurred: %d\n", result);
        goto err_handle;
    }

    // Then check the type of data-link headers
    const int headers_type = pcap_datalink(handle);

    if (headers_type != DLT_EN10MB) {
        fprintf(stderr, "Device %s does not provide Ethernet headers\n", device);
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

static void interrupt_handler(int signal) {
    pcap_breakloop();
}

static int set_interrupt_signal_handler() {
    if (signal(SIGINT, interrupt_handler) == SIG_ERR) {  // TODO use sigaction instead
        fprintf(stderr, "Could not set interrupt handler\n");
        return -1;
    }

    return 0;
}

int initialize_session(SniffSession* session, const char* device) {
    char err_msg[PCAP_ERRBUF_SIZE];

    if (pcap_init(PCAP_CHAR_ENC_UTF_8, err_msg) == PCAP_ERROR) {
        fprintf(stderr, "Could not initialize pcap: %s\n", err_msg);
        return -1;
    }

    if (set_interrupt_signal_handler() < 0) {
        return -1;
    }

    pcap_t* handle = initialize_handle(device);

    if (handle == NULL) {
        return -1;
    }

    session->handle = handle;

    return 0;
}

void deinitialize_session(SniffSession* session) {
    pcap_close(session->handle);
}

// https://www.tcpdump.org/manpages/libpcap-1.10.4/pcap_loop.3pcap.html

int sniff_blocking(SniffSession* session, int sniff_count, PacketSniffed callback, void* user) {
    reset_callback(session, callback, user);

    printf("Starting sniffing...\n");

    const int result = pcap_loop(session->handle, sniff_count, packet_sniffed, (unsigned char*) session);

    switch (result) {
        case 0:
            printf("Sniffed all packets\n");
            break;
        case PCAP_ERROR_BREAK:
        case PCAP_ERROR_NOT_ACTIVATED:
        case PCAP_ERROR:
            printf("An error occurred\n");
            break;
    }

    return 0;
}

static void* sniff_thread(void* args) {
    const SniffSession* session = (const SniffSession*) args;

    // Loop forever
    const int result = pcap_dispatch(session->handle, 0, packet_sniffed, (unsigned char*) session);


}

int sniff_nonblocking(SniffSession* session, PacketSniffed callback, void* user) {
    reset_callback(session, callback, user);

    printf("Starting sniffing...\n");

    char err_msg[PCAP_ERRBUF_SIZE];

    // if (pcap_setnonblock(session->handle, 1, err_msg) < 0) {
    //     fprintf(stderr, "Could not set session in non-blocking mode: %s\n", err_msg);
    //     return -1;
    // }

    // const int result = pcap_dispatch(session->handle, 0, packet_sniffed, (unsigned char*) session);

    pthread_t thread;

    pthread_create(&thread, NULL, sniff_thread, session);

    void* ret;
    pthread_join(&thread, &ret);
}
