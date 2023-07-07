#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "logging.h"

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

Args* args_parse_arguments(int argc, char** argv) {
    static Args args = {0};

    // Default arguments
    args.log_target_mask = LogConsole;
    args.log_file = "capture.log";

    switch (argc) {
        case 4: {
            args.device = argv[1];

            if (parse_log_target(argv[2], &args.log_target_mask) < 0) {
                printf("Invalid log target\n");
                return NULL;
            }

            args.log_file = argv[3];

            break;
        }
        case 3: {
            args.device = argv[1];

            if (parse_log_target(argv[2], &args.log_target_mask) < 0) {
                printf("Invalid log target\n");
                return NULL;
            }

            break;
        }
        case 2: {
            args.device = argv[1];

            break;
        }
        case 1: {
            printf("No device provided\n");
            return NULL;

            break;
        }
        default:
            printf("Invalid number of arguments\n");
            return NULL;
    }

    return &args;
}

void args_print_usage() {
    printf("sniffer: <device> [<log_target> <log_file>]\n");
}
