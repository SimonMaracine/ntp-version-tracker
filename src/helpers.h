#ifndef HELPERS_C
#define HELPERS_C

#include <stdint.h>

int is_little_endian();
void formatted_mac(const uint8_t* mac, char* out);
void print_mac(const uint8_t* mac, const char* end);

#endif
