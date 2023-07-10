#ifndef LOGGING_H
#define LOGGING_H

// Logging is used only by capture stuff

typedef enum {
    LogFile = 1 << 0,
    LogConsole = 1 << 1
} LogTarget;

int log_initialize(const char* file_name, unsigned int target_mask);
void log_uninitialize();

void log_print(const char* format, ...);  // TODO rotating log files?

#endif
