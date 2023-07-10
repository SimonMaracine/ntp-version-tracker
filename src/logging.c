#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <assert.h>

#include "logging.h"

// Logging could be used everywhere, so use static memory

static unsigned int g_log_target_mask = 0;  // Mask 0 is invalid
static FILE* g_log_file = NULL;  // Flushing is not controlled by this code

static void get_current_time(char* out) {
    // Www Mmm dd hh:mm:ss yyyy\n => 25 + 1 bytes
    // Www Mmm dd hh:mm:ss yyyy => 24 + 1 bytes

    // out needs to be 24 + 1 bytes large

    time_t rawtime;
    time(&rawtime);

    struct tm* timeinfo = localtime(&rawtime);

    char* formatted_time = asctime(timeinfo);

    // Get rid of the new line and write the result
    strncpy(out, formatted_time, 24);
    out[24] = '\0';
}

int log_initialize(const char* file_name, unsigned int target_mask) {
    assert(target_mask != 0);

    g_log_target_mask = target_mask;

    // Don't deal with files, if not necessary
    if (!(target_mask & LogFile)) {
        return 0;
    }

    g_log_file = fopen(file_name, "a");

    if (g_log_file == NULL) {
        printf("Could not open log file `%s`\n", file_name);
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

void log_print(const char* format, ...) {
    // Logging to at least one target is mandatory

    va_list args;
    va_start(args, format);

    char current_time[25];
    get_current_time(current_time);

    switch (g_log_target_mask) {
        case LogFile: {
            assert(g_log_file != NULL);

            fprintf(g_log_file, "[%s] ", current_time);
            vfprintf(g_log_file, format, args);

            break;
        }
        case LogConsole: {
            fprintf(stdout, "[%s] ", current_time);
            vfprintf(stdout, format, args);

            break;
        }
        case LogFile | LogConsole: {
            assert(g_log_file != NULL);

            va_list args2;
            va_copy(args2, args);

            fprintf(g_log_file, "[%s] ", current_time);
            vfprintf(g_log_file, format, args);
            fprintf(stdout, "[%s] ", current_time);
            vfprintf(stdout, format, args2);

            va_end(args2);

            break;
        }
        default:
            assert(0);
            break;
    }

    va_end(args);
}
