#ifndef HELPERS_C
#define HELPERS_C

#include <stdint.h>
#include <stdbool.h>

/**
 * Check the machine endianess.
 *
 * @return true, if the machine has a little endian processor, false otherwise
*/
bool is_little_endian();

/**
 * Get a string representation of the MAC address. The buffer must be 18 bytes in size.
 *
 * @param mac a pointer to the MAC address
 * @param out a pointer to a buffer large enough to contain the resulting string
*/
void formatted_mac(const uint8_t* mac, char* out);

/**
 * Get a string representation of the IP address. The buffer must be 16 bytes in size.
 *
 * @param mac a pointer to the IP address
 * @param out a pointer to a buffer large enough to contain the resulting string
*/
void formatted_ip(const void* ip, char* out);

/**
 * Overwrite the SIGINT interrupt with a callback function.
 *
 * @param interrupt_handler the callback function
 * @return 0 on success, -1 on error
*/
int set_interrupt_handler(void(*interrupt_handler)(int));

#endif
