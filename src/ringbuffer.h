#pragma once

#include "util.h"

// Ring buffer implementation
typedef struct
{
    uint8_t *buf;
    uint8_t *head;
    uint8_t *tail;

    uint32_t size;
    uint32_t len;
} ringbuffer_T;

void ringbuffer_init(ringbuffer_T *rb, uint8_t *buf, uint32_t size);
ssize_t ringbuffer_read(ringbuffer_T *rb, int fd);
void ringbuffer_get(
    ringbuffer_T *rb, const uint8_t **region1, uint32_t *len1,
    const uint8_t **region2, uint32_t *len2
);
void ringbuffer_consume(ringbuffer_T *rb, uint32_t n);

// vim: ts=4 sw=4 sts=4 et
