#ifndef LOGGING_H
#define LOGGING_H

#define LOG_IF_VERBOSE if (session->verbose)

// Logging is used only by capture stuff

/**
 * Constants used to specify the log target in log_initialize.
 *
 * @see log_initialize
*/
typedef enum {
    LogFile = 1 << 0,
    LogConsole = 1 << 1
} LogTarget;

/**
 * Initialize the logging system. Calls to log_print are only valid after this routine.
 *
 * @param file_name the path to the log file, if target includes logging to file
 * @param target_mask a bitmask of the logging target; use the LogTarget enum
 * @param max_bytes the maximum amount of bytes that can be written to the console and file
 * @return 0 on success, -1 on error
 * @see LogTarget
 * @see log_print
*/
int log_initialize(const char* file_name, unsigned int target_mask, unsigned long max_bytes);

/**
 * Uninitialize the logging system.
 *
 * @see log_initialize
*/
void log_uninitialize();

/**
 * Print a log message to the targets specified in log_initialize. It takes the same arguments as printf.
 *
 * @param format a string indicating the message format
 * @see log_initialize
*/
void log_print(const char* format, ...);

#endif
