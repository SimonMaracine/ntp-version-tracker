#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "logging.h"

static int parse_positive_int(const char* integer) {
    char* end = NULL;
    const long result = strtol(integer, &end, 10);

    if (integer == end) {
        return -1;
    }

    return (int) result;
}

Args* args_parse_arguments(int argc, char** argv) {
    static Args args = {0};

    // Default arguments
    args.log_file = "capture.log";
    args.log_target = (int) LogConsole;

    switch (argc) {
        case 4: {
            args.device = argv[1];
            args.log_file = argv[2];

            const int result = parse_positive_int(argv[3]);

            if (result < 0 || !log_is_log_target(result)) {
                printf("Invalid log target\n");
                return NULL;
            }

            args.log_target = result;

            break;
        }
        case 3: {
            args.device = argv[1];
            args.log_file = argv[2];

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
    }

    return &args;
}

void args_print_usage() {
    printf("sniffer: <device> [<log_file> <log_target>]\n");
}
