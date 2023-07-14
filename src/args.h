#ifndef ARGS_H
#define ARGS_H

#include <stdbool.h>

/**
 * Constants used to specify the program command, i.e. what should it do.
*/
typedef enum {
    CmdNone,
    CmdCaptureDevice,
    CmdCaptureFile,
    CmdHelp,
    CmdVersion
} ArgsCommand;

/**
 * Struct holding various program flags and options.
 *
 * @see ArgsCommand
*/
typedef struct {
    ArgsCommand command;
    const char* device_or_file;
    unsigned int log_target_mask;
    unsigned long max_bytes;
    const char* log_file;
    const char* filter;
    bool verbose;
} Args;

/**
 * Parse the command line arguments and return a struct holding the default or specified values.
 *
 * @param argc same as in main
 * @param argv same as in main
 * @return a pointer to a struct with various program flags and options
 * @see Args
*/
Args* args_parse_arguments(int argc, char** argv);

/**
 * Print a help text message.
*/
void args_print_help();

/**
 * Print program and pcap versions.
*/
void args_print_version();

/**
 * Return a string representation of the log targets indicated by the bitmask.
 *
 * @param log_target_mask the bitmask of log targets to interpret
 * @return a static string representing the log targets
 * @see LogTarget
*/
const char* args_log_target_format(unsigned int log_target_mask);

#endif
