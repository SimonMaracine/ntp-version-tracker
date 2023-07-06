#ifndef LOGGING_H
#define LOGGING_H

typedef enum {
    LogNone,
    LogFile,
    LogConsole,
    LogFileConsole
} LogTarget;

int log_initialize(const char* file_name, LogTarget target);
void log_uninitialize();

void log_print(const char* format, ...);

#endif
