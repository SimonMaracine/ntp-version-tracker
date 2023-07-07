#ifndef ARGS_H
#define ARGS_H

typedef struct {
    const char* device;
    const char* log_file;
    unsigned int log_target_mask;
} Args;

Args* args_parse_arguments(int argc, char** argv);
void args_print_usage();

#endif
