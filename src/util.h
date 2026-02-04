#pragma once

#include "sha256.h"
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>  // IWYU pragma: keep
#include <string.h> // IWYU pragma: keep

#define NUL 0

#ifndef MIN
#    define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#    define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define STRINGIFY_DIRECT(x) #x
#define STRINGIFY(x) STRINGIFY_DIRECT(x)

#define ARRAY_SIZE(arr) ((int)(sizeof(arr) / sizeof(*arr)))

#define wlip_snprintf(b, s, f, ...)                                            \
    do                                                                         \
    {                                                                          \
        if (snprintf(b, s, f, ##__VA_ARGS__) < 0)                              \
        {                                                                      \
            wlip_error("snprintf(...) failed: %s", strerror(errno));      \
            abort();                                                           \
        }                                                                      \
    } while (false)

#define STRLEN(s) ((uint32_t)strlen(s))

#ifdef __GNUC__
#    define likely(x) __builtin_expect(!!(x), 1)
#    define unlikely(x) __builtin_expect(!!(x), 0)
#else
#    define likely(x) (x)
#    define unlikely(x) (x)
#endif

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
#    define PRINTFLIKE(n, m) __attribute__((format(printf, n, m)))
#else
#    define UNUSED
#    define PRINTFLIKE(n, m)
#endif

#define OK 0
#define FAIL -1
#define NOERROR -2

#define wlip_log(fmt, ...)                                                     \
    wlip_log_raw(false, "", __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define wlip_debug(fmt, ...)                                                   \
    wlip_log_raw(true, "DEBUG ", __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define wlip_warn(fmt, ...)                                                    \
    wlip_log_raw(false, "WARN ", __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define wlip_error(fmt, ...)                                                   \
    wlip_log_raw(false, "ERROR ", __FILE__, __LINE__, fmt, ##__VA_ARGS__)

void wlip_set_debug(bool state);
void wlip_log_raw(
    bool debug, const char *prefix, const char *file, int lnum,
    const char *format, ...
) PRINTFLIKE(5, 6);

int64_t get_realtime_us(void);
int64_t get_montonictime_us(void);
struct timespec timespec_subtract(struct timespec start, struct timespec end);
int timespec_compare(struct timespec a, struct timespec b);

const uint8_t *
sha256_hex2digest(const char *str, uint8_t buf[SHA256_BLOCK_SIZE]);
const char *
sha256_digest2hex(const uint8_t hash[SHA256_BLOCK_SIZE], char buf[65]);

int wlip_mkdir(const char *path);

// vim: ts=4 sw=4 sts=4 et
