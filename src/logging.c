#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

#include "logging.h"

// Logging is used everywhere, so use static memory

static LogTarget g_log_target = LogNone;
static FILE* g_log_file = NULL;  // TODO needs periodic flushing

static void get_current_time(char* out) {
    // Www Mmm dd hh:mm:ss yyyy\n => 25 + 1 bytes
    // Www Mmm dd hh:mm:ss yyyy => 24 + 1 bytes

    // out needs to be 24 + 1 bytes large

    time_t rawtime;
    time(&rawtime);

    struct tm* timeinfo = localtime(&rawtime);

    char* formatted_time = asctime(timeinfo);

    // Get rid of the new line
    char final_time[25];
    strncpy(final_time, formatted_time, 24);
    final_time[24] = '\0';

    sprintf(out, "%s", final_time);  // TODO
}

int log_initialize(const char* file_name, LogTarget target) {
    g_log_target = target;

    // Don't deal with files, if not necessary
    if (target == LogNone || target == LogConsole) {
        return 0;
    }

    g_log_file = fopen(file_name, "a");

    if (g_log_file == NULL) {
        printf("Could not open log file\n");
        return -1;
    }

    return 0;
}

void log_uninitialize() {
    if (g_log_file == NULL) {
        return;
    }

    fclose(g_log_file);
}

#define GET_CURRENT_TIME(out) \
    char out[25]; \
    get_current_time(out);

#define LOG(format, args, file, current_time) \
    fprintf(file, "[%s] ", current_time); \
    vfprintf(file, format, args);

void log_print(const char* format, ...) {
    va_list args;
    va_start(args, format);  // TODO can be put inside switch?

    switch (g_log_target) {
        case LogNone: {
            break;
        }
        case LogFile: {
            GET_CURRENT_TIME(current_time)
            LOG(format, args, g_log_file, current_time)

            break;
        }
        case LogConsole: {
            GET_CURRENT_TIME(current_time)
            LOG(format, args, stdout, current_time)

            break;
        }
        case LogFileConsole: {
            va_list args2;
            va_copy(args2, args);

            GET_CURRENT_TIME(current_time)
            LOG(format, args, g_log_file, current_time)
            LOG(format, args2, stdout, current_time)

            va_end(args2);

            break;
        }
    }

    va_end(args);
}

bool log_is_log_target(int value) {
    bool result = false;

    switch (value) {
        case LogNone:
        case LogFile:
        case LogConsole:
        case LogFileConsole:
            result = true;
            break;
    }

    return result;
}
