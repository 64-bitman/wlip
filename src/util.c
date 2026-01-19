#include "util.h"
#include "sha256.h"
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
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
wlip_log_raw(
    bool debug, const char *prefix, const char *file, int lnum,
    const char *format, ...
)
{
    assert(format != NULL);

    if (debug && !DEBUG_ON)
        return;

    va_list ap;

    va_start(ap, format);
    fprintf(stderr, "%s%s:%d: ", prefix, file, lnum);
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

    if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
    {
        wlip_log(
            "clock_gettime(CLOCK_MONOTONIC, ...) error: %s", strerror(errno)
        );
        return 0;
    }

    return ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/*
 * Get monotonic time in microseconds
 */
int64_t
get_montonictime_us(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
    {
        wlip_log(
            "clock_gettime(CLOCK_MONOTONIC, ...) error: %s", strerror(errno)
        );
        return 0;
    }

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
 * bytes) into "buf". If "buf" is NULL, then a static memory buffer is used, and
 * it is assumed to be invalid on the next function call.
 */
void
sha256_hex2digest(const char *str, char_u buf[SHA256_BLOCK_SIZE])
{
    assert(STRLEN(str) == 64);

    static char_u sbuf[SHA256_BLOCK_SIZE];

    if (buf == NULL)
        buf = sbuf;

    for (int i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        char_u hi = hex2byte(str[2 * i]);
        char_u lo = hex2byte(str[2 * i + 1]);

        buf[i] = (char_u)((hi << 4) | lo);
    }
}

/*
 * Convert a SHA-256 digest into hexadecimal form (64 bytes). If "buf" is NULL,
 * then a static memory buffer is used, and it is assumed to be invalid on the
 * next function call.
 */
const char *
sha256_digest2hex(const char_u hash[SHA256_BLOCK_SIZE], char buf[65])
{
    assert(hash != NULL);

    static char sbuf[65];

    if (buf == NULL)
        buf = sbuf;
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++)
        sprintf(buf + (i * 2), "%02x", hash[i]);
    buf[64] = NUL;
    return buf;
}

/*
 * Create a directory, and create any parent directories as well. Taken from
 * https://gist.github.com/JonathonReinhart/8c0d90191c38af2dcadb102c4e202950
 * because of my lazy ass.
 */
static int
maybe_mkdir(const char *path, mode_t mode)
{
    struct stat st;
    errno = 0;

    /* Try to make the directory */
    if (mkdir(path, mode) == 0)
        return 0;

    /* If it fails for any reason but EEXIST, fail */
    if (errno != EEXIST)
        return -1;

    /* Check if the existing path is a directory */
    if (stat(path, &st) != 0)
        return -1;

    /* If not, fail with ENOTDIR */
    if (!S_ISDIR(st.st_mode))
    {
        errno = ENOTDIR;
        return -1;
    }

    errno = 0;
    return 0;
}

int
wlip_mkdir(const char *path)
{
    /* Adapted from http://stackoverflow.com/a/2336245/119527 */
    char *_path = NULL;
    char *p;
    int result = -1;
    mode_t mode = 0777;

    errno = 0;

    /* Copy string so it's mutable */
    _path = strdup(path);
    if (_path == NULL)
        goto out;

    /* Iterate the string */
    for (p = _path + 1; *p; p++)
    {
        if (*p == '/')
        {
            /* Temporarily truncate */
            *p = '\0';

            if (maybe_mkdir(_path, mode) != 0)
                goto out;

            *p = '/';
        }
    }

    if (maybe_mkdir(_path, mode) != 0)
        goto out;

    result = 0;

out:
    free(_path);
    return result;
}
