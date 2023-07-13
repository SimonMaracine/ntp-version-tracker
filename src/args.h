#ifndef ARGS_H
#define ARGS_H

typedef enum {
    CmdNone,
    CmdCaptureDevice,
    CmdCaptureFile,
    CmdHelp,
    CmdVersion
} ArgsCommand;

typedef struct {
    ArgsCommand command;
    const char* device_or_file;
    unsigned int log_target_mask;
    unsigned long max_bytes;
    const char* log_file;
} Args;

Args* args_parse_arguments(int argc, char** argv);
void args_print_help();
void args_print_version();
const char* args_log_target_format(unsigned int log_target_mask);

#endif
