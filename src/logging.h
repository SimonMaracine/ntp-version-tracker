#ifndef LOGGING_H
#define LOGGING_H

int log_initialize();
void log_uninitialize();

void log_print(const char* format, ...);

#endif
