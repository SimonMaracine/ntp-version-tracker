#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "helpers.h"

bool is_little_endian() {
    const volatile uint32_t whatever = 0x0001;
    return ((const volatile uint8_t*) &whatever)[0] == 1;
}

void formatted_mac(const uint8_t* mac, char* out) {
    // FF:FF:FF:FF:FF:FF
    // out needs to be 17 + 1 bytes large

    sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void formatted_ip(const void* ip, char* out) {
    // out needs to be 16 bytes large

    inet_ntop(AF_INET, ip, out, INET_ADDRSTRLEN);
}

int set_interrupt_handler(void(*interrupt_handler)(int)) {
    struct sigaction sa = {0};
    sa.sa_handler = interrupt_handler;

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        printf("Could not set interrupt handler\n");
        return -1;
    }

    return 0;
}
