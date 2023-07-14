#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>

#include "args.h"
#include "logging.h"
#include "capture/session.h"

static int parse_log_target(const char* input, unsigned int* result_mask) {
    *result_mask = 0;

    size_t index = 0;
    char c = 0;

    while ((c = input[index]) != '\0') {
        switch (c) {
            case 'f':
            case 'F':
                *result_mask |= LogFile;
                break;
            case 'c':
            case 'C':
                *result_mask |= LogConsole;
                break;
            default:
                return -1;
        }

        index++;
    }

    return 0;
}

// https://www.gnu.org/software/libc/manual/html_node/Parsing-of-Integers.html

static int parse_max_bytes(const char* input, unsigned long* result_max_bytes) {
    errno = 0;

    char* end = NULL;

    const unsigned long result = strtoul(input, &end, 10);

    if (errno) {
        return -1;
    }

    if ((result == 0 && end == input) || *end != '\0') {
        return -1;
    }

    *result_max_bytes = result;

    return 0;
}

static ArgsCommand parse_capture_command(int option) {
    switch (option) {
        case 'd':
            return CmdCaptureDevice;
        case 'f':
            return CmdCaptureFile;
        default:
            assert(0);
            break;
    }
}

static ArgsCommand parse_miscellaneous_command(int option) {
    switch (option) {
        case 'h':
            return CmdHelp;
        case 'v':
            return CmdVersion;
        default:
            assert(0);
            break;
    }
}

const Args* args_parse_arguments(int argc, char** argv) {
    static Args args = {0};

    // Default arguments
    args.log_target_mask = LogConsole;
    args.max_bytes = 8388608;
    args.log_file = "capture.log";
    args.filter = NULL;
    args.verbose = false;

    // Don't print error messages from the library
    opterr = 0;

    int c = 0;

    while ((c = getopt(argc, argv, "d:f:t:m:l:F:Vhv")) != -1) {
        switch (c) {
            case 'd':
            case 'f':
                if (args.command != CmdNone) {
                    printf("Option -%c must not be used with other options, except -t and -l\n", c);
                    return NULL;
                }

                args.device_or_file = optarg;
                args.command = parse_capture_command(c);

                break;
            case 't':
                if (parse_log_target(optarg, &args.log_target_mask) < 0) {
                    printf("Invalid log target\n");
                    return NULL;
                }

                break;
            case 'm':
                if (parse_max_bytes(optarg, &args.max_bytes) < 0) {
                    printf("Invalid max bytes\n");
                    return NULL;
                }

                break;
            case 'l':
                args.log_file = optarg;

                break;
            case 'F':
                args.filter = optarg;

                break;
            case 'V':
                args.verbose = true;

                break;
            case 'h':
            case 'v':
                if (optind != 2) {
                    printf("Option -%c must be the only one\n", c);
                    return NULL;
                }

                args.command = parse_miscellaneous_command(c);

                break;
            case '?':
                switch (optopt) {
                    case 'd':
                    case 'f':
                    case 't':
                    case 'm':
                    case 'l':
                    case 'F':
                        printf("Option -%c requires an argument\n", optopt);
                        break;
                    default:
                        if (isprint(optopt)) {
                            printf("Unknown option `-%c`\n", optopt);
                        } else {
                            printf("Unknown option character `\\x%x`\n", optopt);
                        }
                }

                return NULL;

                break;
            default:
                abort();
        }
    }

    if (optind < argc) {
        printf("Invalid option(s)\n");
        return NULL;
    }

    if (args.command == CmdNone) {
        printf("No device provided\n");
        return NULL;
    }

    return &args;
}

void args_print_help() {
    printf(
        "usage:\n"
        "    ntp_version_tracker -d <device> [OPTIONS...]\n"
        "    ntp_version_tracker -f <file> [OPTIONS...]\n"
        "\n"
        "commands:\n"
        "    -d  Capture a device\n"
        "    -f  Read a save file\n"
        "    -h  Display this help\n"
        "    -v  Show version\n"
        "\n"
        "options:\n"
        "    -t  Set the log target\n"
        "        Possible values are [cCfF]+\n"
        "    -m  Set a soft limit of bytes logged\n"
        "    -l  Set the log file path, if even used\n"
        "    -F  Set the filter string\n"
        "        Possible values can be found in `man pcap-filter`\n"
        "    -V  Print additional information\n"
        "\n"
        "defaults:\n"
        "    log_target = c\n"
        "    max_bytes = 8388608 (8 MiB)\n"
        "    log_file = ./capture.log\n"
        "\n"
        "example:\n"
        "    ntp_version_tracker -d wlo1 -t cf -m 16777216 -l ~/capture.log -F 'udp port 123'\n"
        "\n"
        "    This captures packets on device `wlo1` and writes log messages in both the console and\n"
        "    the specified file. It automatically closes when 16 MiB have been written to logs.\n"
        "    It filters any packets that are not NTP. No verbose information is logged.\n"
    );
}

void args_print_version() {
    printf("ntp-version-tracker v0.1.0 | %s\n", cap_get_pcap_version());
}

const char* args_log_target_format(unsigned int log_target_mask) {
    switch (log_target_mask) {
        case LogFile:
            return "file";
        case LogConsole:
            return "console";
        case LogFile | LogConsole:
            return "file & console";
        default:
            assert(0);
            return NULL;
    }
}
