#pragma once

#include "sha256.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h> // IWYU pragma: keep

typedef unsigned int uint;
typedef unsigned char char_u;

#define NUL 0

#ifndef MIN
#    define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#    define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define STRINGIFY_DIRECT(x) #x
#define STRINGIFY(x) STRINGIFY_DIRECT(x)

#define ARRAY_SIZE(arr) ((uint)(sizeof(arr) / sizeof(*arr)))

#define STRLEN(s) ((uint32_t)strlen(s))

#define FLAG_ON(flags, f)                                                      \
    do                                                                         \
    {                                                                          \
        flags |= f;                                                            \
    } while (false)

#define FLAG_OFF(flags, f)                                                     \
    do                                                                         \
    {                                                                          \
        flags &= ~(uint32_t)f;                                                 \
    } while (false)

#ifdef __GNUC__
#    define UNUSED __attribute__((__unused__))
#else
#    define UNUSED
#endif

#define wlip_log(fmt, ...)                                                     \
    wlip_log_raw(false, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define wlip_debug(fmt, ...)                                                   \
    wlip_log_raw(true, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

void wlip_set_debug(bool state);
void
wlip_log_raw(bool debug, const char *file, int lnum, const char *format, ...);

int64_t get_realtime_us(void);

void sha256_hex2digest(const char *str, char_u buf[SHA256_BLOCK_SIZE]);

// vim: ts=4 sw=4 sts=4 et
