#pragma once

#include <stddef.h>

void *wlip_malloc(size_t sz);
void *wlip_calloc(size_t n, size_t n_size);
void  wlip_free(void *ptr);
void *wlip_realloc(void *ptr, size_t new_size);

char *wlip_strdup_printf(const char *fmt, ...);

// vim: ts=4 sw=4 sts=4 et
