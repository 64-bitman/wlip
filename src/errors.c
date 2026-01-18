#include "errors.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

/*
 * Set the error to the given code and error message. If "error" is NULL, then
 * this is a no-op. The error must have not been set before.
 */
void
error_set(error_T *error, errorcode_T code, const char *fmt, ...)
{
    assert(code >= 0);
    assert(fmt != NULL);

    if (error == NULL)
        return;

    assert(error->code == ERROR_NONE);

    va_list ap;

    va_start(ap, fmt);
    vsnprintf(error->msg, ERRMSG_SIZE, fmt, ap);
    va_end(ap);
    error->code = code;
}
