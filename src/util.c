#include "util.h"
#include "sha256.h"
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// If debug messages should be outputted
static bool DEBUG_ON = false;

void
wlip_set_debug(bool state)
{
    DEBUG_ON = state;
}

/*
 * Log a message to stderr.
 */
void
wlip_log_raw(bool debug, const char *file, int lnum, const char *format, ...)
{
    assert(format != NULL);

    if (debug && !DEBUG_ON)
        return;

    va_list ap;

    va_start(ap, format);
    fprintf(stderr, "%s:%d: ", file, lnum);
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

/*
 * Get time in microseconds since epoch.
 */
int64_t
get_realtime_us(void)
{
    struct timespec ts;

    assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);

    return ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/*
 * Get monotonic time in microseconds
 */
int64_t
get_montonictime_us(void)
{
    struct timespec ts;

    assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);

    return ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static inline char_u
hex2byte(char c)
{
    if ('0' <= c && c <= '9')
        return c - '0';
    if ('a' <= c && c <= 'f')
        return c - 'a' + 10;
    if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    abort();
}

/*
 * Convert a SHA-256 sum in hexadecimal form (64 bytes) into a binary digest (32
 * bytes)
 */
void
sha256_hex2digest(const char *str, char_u buf[SHA256_BLOCK_SIZE])
{
    assert(STRLEN(str) == 64);

    for (char_u i = 0; i < 32; i++)
    {
        char_u hi = hex2byte(str[2 * i]);
        char_u lo = hex2byte(str[2 * i + 1]);

        buf[i] = (char_u)((hi << 4) | lo);
    }
}
