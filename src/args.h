#ifndef ARGS_H
#define ARGS_H

typedef struct {
    const char* device;
    unsigned int log_target_mask;
    const char* log_file;
} Args;

Args* args_parse_arguments(int argc, char** argv);
void args_print_usage();

#endif
