#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <assert.h>

#include "sniff_session.h"
#include "args.h"
#include "logging.h"
#include "helpers.h"

static void packet_sniffed(const struct ether_header* ethernet_header, void* user) {
    (void) user;

    // Print MACs as they come
    char source[18];
    char destination[18];
    formatted_mac(ethernet_header->ether_shost, source);
    formatted_mac(ethernet_header->ether_dhost, destination);

    log_print("S %s --- D %s (T %hu)\n", source, destination, ethernet_header->ether_type);

    // Can do other stuff
}

static void interrupt_handler(int signal) {
    (void) signal;

    sniff_stop_signal();
}

static int capture(const Args* args) {
    printf(
        "device: %s, log_target: %u, log_file: %s\n",
        args->device_or_file,
        args->log_target_mask,
        args->log_file
    );

    if (set_interrupt_handler(interrupt_handler) < 0) {
        return 1;
    }

    if (log_initialize(args->log_file, args->log_target_mask) < 0) {
        return 1;
    }

    SniffSession session = {0};

    const SniffType type = args->command == CmdCaptureDevice ? SniffDevice : SniffFile;

    if (sniff_initialize_session(&session, args->device_or_file, type) < 0) {
        return 1;
    }

    if (sniff(&session, packet_sniffed, NULL) < 0) {
        sniff_uninitialize_session(&session);
        return 1;
    }

    log_print("Quit\n");

    sniff_uninitialize_session(&session);
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
