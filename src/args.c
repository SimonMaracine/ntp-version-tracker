#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>

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

Args* args_parse_arguments(int argc, char** argv) {
    static Args args = {0};

    // Default arguments
    args.log_target_mask = LogConsole;
    args.log_file = "capture.log";

    // Don't print error messages from the library
    opterr = 0;

    int c = 0;

    while ((c = getopt(argc, argv, "d:f:t:l:hv")) != -1) {
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
            case 'l':
                args.log_file = optarg;

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
                    case 'l':
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
        "    ntp_version_tracker -d <device> [-t <log_target> -l <log_file>]\n"
        "    ntp_version_tracker -f <file> [-t <log_target> -l <log_file>]\n"
        "\n"
        "commands:\n"
        "    -d Capture a device\n"
        "    -f Capture a save file\n"
        "    -t Set the log target (optional)\n"
        "       Possible values are [cCfF]+\n"
        "    -l Set the log file path, if even used (optional)\n"
        "    -h Display this help\n"
        "    -v Show version\n"
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
