#include "array.h"
#include "alloc.h"
#include "util.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/*
 * Initialize the array struct with the given item size. "grow_len" is the
 * number of items that should be allocated for when growing the array. If more
 * items are needed than "grow_len", then "grow_len" is ignored. No memory will
 * be allocated.
 */
void
array_init(array_T *self, uint32_t item_size, uint32_t grow_len)
{
    assert(self != NULL);

    self->data = NULL;

    self->item_sz = item_size;
    self->len = 0;
    self->alloc_len = 0;
    self->grow_len = grow_len;
}

/*
 * Free the resources for the given array. Note that this does not free the
 * array structure itself.
 */
void
array_clear(array_T *self)
{
    assert(self != NULL);

    wlip_free(self->data);
}

/*
 * Same as array_clear(), but frees an array of strings.
 */
void
array_clear_all(array_T *self)
{
    assert(self != NULL);

    if (self->data == NULL)
        return;

    for (uint32_t i = 0; i < self->len; i++)
        wlip_free(((char **)self->data)[i]);
    array_clear(self);
}

/*
 * Same as array_clear(), but calls func on each item
 */
void
array_clear_func(array_T *self, array_freefunc_T func)
{
    assert(self != NULL);

    if (self->data == NULL)
        return;

    for (uint32_t i = 0; i < self->len; i++)
        func(((char *)self->data) + (i * self->item_sz));
    array_clear(self);
}

/*
 * Grow the array by "n_items". If the array is already big enough, then nothing
 * is done. Otherwise the required extra number of items to grow by is
 * calculated, and the array is grown by that amount or by "grow_len" (if it is
 * bigger). Returns false if array did not grow because the size would overflow.
 */
bool
array_grow(array_T *self, uint32_t n_items)
{
    assert(self != NULL);

    if ((uint64_t)self->len + (uint64_t)n_items > UINT32_MAX)
        return false;

    if (self->len + n_items > self->alloc_len)
    {
        // Need to grow array

        // Grow by factor of 1.5 (if n_items is smaller than the 1.5x growth)
        if (n_items < (self->len / 2))
            n_items = self->len / 2;

        uint32_t extra_len = (self->len + n_items) - self->alloc_len;
        uint32_t new_len = self->len + MAX(self->grow_len, extra_len);
        void *new;

        if ((uint64_t)new_len * (uint64_t)self->item_sz > UINT32_MAX)
            return false;

        new = wlip_realloc(self->data, (size_t)new_len * (size_t)self->item_sz);

        self->alloc_len = new_len;
        self->data = new;
    }
    return true;
}

/*
 * Append the given string to the end of the array, growing as needed.
 */
void
array_append(array_T *self, const char *fmt, ...)
{
    assert(self != NULL);

    va_list ap;

    va_start(ap, fmt);
    int len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    assert(len >= 0);
    // If array size is zero, then we must add the null terminator as well.
    array_grow(self, self->len > 0 ? (uint32_t)len : (uint32_t)len + 1);

    char *data = (char *)self->data + MIN(self->len, self->len - 1);

    va_start(ap, fmt);
    vsprintf(data, fmt, ap);
    va_end(ap);

    self->len += self->len > 0 ? (uint32_t)len : (uint32_t)len + 1;
}

/*
 * Like array_append(), but appends a single character.
 */
void
array_appendc(array_T *self, char c)
{
    assert(self != NULL);

    array_grow(self, self->len == 0 ? 2 : 1);
    ((char *)self->data)[self->len++ - 1] = c;
    ((char *)self->data)[self->len - 1] = 0;
}

/*
 * Append the given chunk of memory to the end of the array, growing as needed.
 */
void
array_add(array_T *self, const void *data, uint32_t len)
{
    assert(self != NULL);
    assert(data != NULL);

    if (len == 0)
        return;

    array_grow(self, len);

    memcpy(self->data + self->len, data, len);
    self->len += len;
}

/*
 * Set the contents of the array to "data". Array must not be allocated.
 */
void
array_take(array_T *self, void *data, uint32_t len)
{
    assert(self != NULL);
    assert(self->data == NULL);
    assert(data != NULL);

    self->data = data;
    self->alloc_len = len;
    self->len = len;
}

// vim: ts=4 sw=4 sts=4 et
