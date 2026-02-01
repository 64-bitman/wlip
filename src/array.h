#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef void (*array_freefunc_T)(void *item);

// A simple dynamic array implementation
typedef struct
{
    void *data; // Memory block

    uint32_t item_sz;   // Size of each item
    uint32_t len;       // Number of items
    uint32_t alloc_len; // Number of items allocated for
    uint32_t grow_len;  // Number of items to grow each time
} array_T;

void array_init(array_T *self, uint32_t item_size, uint32_t grow_len);
void array_clear(array_T *self);
void array_clear_all(array_T *self);
void array_clear_func(array_T *self, array_freefunc_T func);
bool array_grow(array_T *self, uint32_t n_items);
void array_append(array_T *self, const char *fmt, ...);
void array_appendc(array_T *self, char c);
void array_add(array_T *self, const void *data, uint32_t len);
void array_take(array_T *self, void *data, uint32_t len);

// vim: ts=4 sw=4 sts=4 et
