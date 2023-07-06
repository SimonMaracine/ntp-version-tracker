#include <stdio.h>
#include <stdarg.h>

#include "logging.h"

int log_initialize() {
    return 0;
}

void log_uninitialize() {

}

void log_print(const char* format, ...) {
    va_list args;
    va_start(args, format);

    vprintf(format, args);

    va_end(args);
}
