#pragma once

#include "util.h"

// Ring buffer implementation
typedef struct
{
    char_u *buf;
    char_u *head;
    char_u *tail;

    uint32_t size;
    uint32_t len;
} ringbuffer_T;

void ringbuffer_init(ringbuffer_T *rb, char_u *buf, uint32_t size);
ssize_t ringbuffer_read(ringbuffer_T *rb, int fd);
void ringbuffer_get(
    ringbuffer_T *rb, const char_u **region1, uint32_t *len1,
    const char_u **region2, uint32_t *len2
);
void ringbuffer_consume(ringbuffer_T *rb, uint32_t n);

// vim: ts=4 sw=4 sts=4 et
