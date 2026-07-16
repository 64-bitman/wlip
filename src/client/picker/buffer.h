#pragma once

#include <cairo.h>
#include <stdbool.h>
#include <wayland-client.h>

struct buffer
{
    struct wl_buffer *buffer;
    cairo_surface_t  *csurf;
    cairo_t          *cr;

    bool busy;
};

struct buffer_pool
{
    void  *data;
    size_t sz;

    uint32_t width;
    uint32_t height;

    struct buffer  buffers[2];
    struct buffer *cur;
};

// clang-format off
int buffer_pool_init(struct buffer_pool *pool, uint32_t w, uint32_t h, struct wl_shm *shm);
void buffer_pool_uninit(struct buffer_pool *pool);
// clang-format on
