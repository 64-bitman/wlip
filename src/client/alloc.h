#pragma once

#include <stdlib.h>

// clang-format off
void *do_malloc(size_t sz);
void *do_calloc(size_t n, size_t sz);
void *do_realloc(void *ptr, size_t sz);
void  do_free(void *ptr);
char *do_strdup(const char *str);
// clang-format on
