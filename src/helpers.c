#include <stdio.h>
#include <stdint.h>
#include <signal.h>

#include "helpers.h"
#include "logging.h"

int is_little_endian() {
    const volatile uint32_t whatever = 0x0001;
    return ((const volatile uint8_t*) &whatever)[0] == 1;
}

void formatted_mac(const uint8_t* mac, char* out) {
    // FF:FF:FF:FF:FF:FF
    // out needs to be 17 + 1 bytes large

    // TODO this is dangerous
    sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int set_interrupt_handler(void(*interrupt_handler)(int)) {
    struct sigaction sa = {0};
    sa.sa_handler = interrupt_handler;

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        log_print("Could not set interrupt handler\n");
        return -1;
    }

    return 0;
}
