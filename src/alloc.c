#include "alloc.h"
#include "util.h"
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Same as malloc(), but aborts on failure
 */
void *
wlip_malloc(size_t sz)
{
    void *ptr = malloc(sz);

    if (unlikely(ptr == NULL))
    {
        fprintf(stderr, "malloc(%zu) fail: %s\n", sz, strerror(errno));
        abort();
    }

    return ptr;
}

/*
 * Same as calloc(), but aborts on failure
 */
void *
wlip_calloc(size_t n, size_t n_size)
{
    void *ptr = calloc(n, n_size);

    if (unlikely(ptr == NULL))
    {
        fprintf(
            stderr, "calloc(%zu, %zu) fail: %s\n", n, n_size, strerror(errno)
        );
        abort();
    }

    return ptr;
}

/*
 * Same as free(), here for consistency.
 */
void
wlip_free(void *ptr)
{
    free(ptr);
}

/*
 * Same as realloc() but aborts on failure
 */
void *
wlip_realloc(void *ptr, size_t new_size)
{
    void *new = realloc(ptr, new_size);

    if (unlikely(new == NULL))
    {
        fprintf(
            stderr, "realloc(..., %zu) fail: %s\n", new_size, strerror(errno)
        );
        abort();
    }

    return new;
}

/*
 * Same as strdup() but aborts on failure
 */
char *
wlip_strdup(const char *str)
{
    assert(str != NULL);

    char *ptr = strdup(str);

    if (unlikely(ptr == NULL))
    {
        fprintf(stderr, "strdup(\"%s\") fail: %s\n", str, strerror(errno));
        abort();
    }

    return ptr;
}

/*
 * Same as strdup() but formats the resulting string.
 */
char *
wlip_strdup_printf(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    size_t sz = (size_t)vsnprintf(NULL, 0, fmt, ap) + 1;
    va_end(ap);

    va_start(ap, fmt);
    char *new = wlip_malloc((size_t)sz);
    vsnprintf(new, (size_t)sz, fmt, ap);
    va_end(ap);

    return new;
}

// vim: ts=4 sw=4 sts=4 et
