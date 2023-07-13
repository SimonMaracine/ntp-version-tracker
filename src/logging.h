#ifndef LOGGING_H
#define LOGGING_H

#define LOG_IF_VERBOSE if (session->verbose)

// Logging is used only by capture stuff

typedef enum {
    LogFile = 1 << 0,
    LogConsole = 1 << 1
} LogTarget;

int log_initialize(const char* file_name, unsigned int target_mask, unsigned long max_bytes);
void log_uninitialize();

void log_print(const char* format, ...);

#endif
