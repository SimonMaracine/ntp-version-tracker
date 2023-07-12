#ifndef HELPERS_C
#define HELPERS_C

#include <stdint.h>
#include <stdbool.h>

bool is_little_endian();
void formatted_mac(const uint8_t* mac, char* out);
void formatted_ip(const void* ip, char* out);
int set_interrupt_handler(void(*interrupt_handler)(int));

#endif
