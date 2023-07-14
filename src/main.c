#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "capture/session.h"
#include "args.h"
#include "logging.h"
#include "helpers.h"

// User side callback for processing packets
static void packet_captured(const CapPacketHeaders* headers, void* user) {
    (void) user;

    char buffer[256];
    int pointer = 0;

    if (headers->ethernet_header == NULL) {
        return;
    }

    {
        char source[18];
        char destination[18];
        formatted_mac(headers->ethernet_header->ether_shost, source);
        formatted_mac(headers->ethernet_header->ether_dhost, destination);
        pointer += sprintf(buffer + pointer, "Ether %s --> %s (T %hu)", source, destination, headers->ethernet_header->ether_type);
    }

    if (headers->ipv4_header == NULL) {
        goto print;
    }

    pointer += sprintf(buffer + pointer, " IP proto %u", headers->ipv4_header->ip_p);

    {
        char source[16];
        char destination[16];
        formatted_ip(&headers->ipv4_header->ip_src, source);
        formatted_ip(&headers->ipv4_header->ip_dst, destination);
        pointer += sprintf(buffer + pointer, " IP %s --> %s", source, destination);
    }

    if (headers->udp_header == NULL) {
        goto print;
    }

    pointer += sprintf(
        buffer + pointer,
        " UDP %hu --> %hu",
        ntohs(headers->udp_header->source),
        ntohs(headers->udp_header->dest)
    );

    if (headers->ntp_header == NULL) {
        goto print;
    }

    pointer += sprintf(buffer + pointer, " NTP version %u", (headers->ntp_header->li_vn_mode & 0x38) >> 3);

print:
    log_print("%s\n", buffer);

    // Can do other stuff
}

static void interrupt_handler(int signal) {
    (void) signal;

    cap_stop_signal();
}

static void print_capture_status(const Args* args) {
    printf(
        "device: %s, log_target: %s, max_bytes: %lu",
        args->device_or_file,
        args_log_target_format(args->log_target_mask),
        args->max_bytes
    );

    if (args->log_target_mask & LogFile) {
        printf(", log_file: %s", args->log_file);
    }

    if (args->filter != NULL) {
        printf(", filter: %s", args->filter);
    }

    if (args->verbose) {
        printf(", verbose");
    }

    printf("\n");
}

// Main operation of the program
static int capture(const Args* args) {
    print_capture_status(args);

    if (set_interrupt_handler(interrupt_handler) < 0) {
        printf("Could not set interrupt handler\n");
        return 1;
    }

    if (log_initialize(args->log_file, args->log_target_mask, args->max_bytes) < 0) {
        return 1;
    }

    CapSession session = {0};

    const CapType type = args->command == CmdCaptureDevice ? CapDevice : CapFile;

    if (cap_initialize_session(&session, args->device_or_file, type, args->filter, args->verbose) < 0) {
        return 1;
    }

    if (cap_start_capture(&session, packet_captured, NULL) < 0) {
        cap_uninitialize_session(&session);
        return 1;
    }

    log_print("Quit\n");

    cap_uninitialize_session(&session);
    log_uninitialize();

    return 0;
}

int main(int argc, char** argv) {
    const Args* args = args_parse_arguments(argc, argv);

    if (args == NULL) {
        args_print_help();
        return 1;
    }

    int code = 0;

    switch (args->command) {
        case CmdCaptureDevice:
        case CmdCaptureFile:
            code = capture(args);
            break;
        case CmdHelp:
            args_print_help();
            break;
        case CmdVersion:
            args_print_version();
            break;
        case CmdNone:
            assert(0);
            break;
    }

    return code;
}
