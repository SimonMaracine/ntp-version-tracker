#ifndef NTP_H
#define NTP_H

#include <stdint.h>

typedef struct {
    uint8_t li_vn_mode;  // 2-3-3 bits respectively
    uint8_t stratum;
    int8_t poll;
    int8_t precision;

    uint32_t root_delay;  // These should be fixed-point numbers
    uint32_t root_dispersion;

    uint32_t reference_identifier;
    uint64_t reference_timestamp;
    uint64_t originate_timestamp;
    uint64_t receive_timestamp;
    uint64_t transmit_timestamp;

    // Field authentication is ignored
} NtpHeader;

#endif
