#include "util.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

char *
wlip_strdup_printf(const char *fmt, ...)
{
    char *str;
    va_list ap;
    int len;

    va_start(ap, fmt);
    len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    str = malloc(len + 1);
    if (str == NULL)
        return NULL;

    va_start(ap, fmt);
    vsnprintf(str, len + 1, fmt, ap);
    va_end(ap);

    return str;
}
