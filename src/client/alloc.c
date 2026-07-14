#include "alloc.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>

void *
do_malloc(size_t sz)
{
    void *ptr = malloc(sz);

    if (ptr == NULL)
        log_errabort("malloc(%zu) fail", sz);
    return ptr;
}

void *
do_calloc(size_t n, size_t sz)
{
    void *ptr = calloc(n, sz);

    if (ptr == NULL)
        log_errabort("calloc(%zu, %zu) fail", n, sz);
    return ptr;
}

void *
do_realloc(void *ptr, size_t sz)
{
    ptr = realloc(ptr, sz);

    if (ptr == NULL)
        log_errabort("realloc(%p, %zu) fail", ptr, sz);
    return ptr;
}

void
do_free(void *ptr)
{
    free(ptr);
}

char *
do_strdup(const char *str)
{
    char *s = strdup(str);

    if (s == NULL)
        log_errabort("strdup(\"%s\") fail", str);
    return s;
}
