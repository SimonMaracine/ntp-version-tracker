#ifndef LOGGING_H
#define LOGGING_H

#include <stdbool.h>

typedef enum {  // TODO maybe use bit masks
    LogNone,
    LogFile,
    LogConsole,
    LogFileConsole
} LogTarget;

int log_initialize(const char* file_name, LogTarget target);
void log_uninitialize();

void log_print(const char* format, ...);

bool log_is_log_target(int value);

#endif
