#include "util.h"
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
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
