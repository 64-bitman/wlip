#pragma once

#include <cairo.h>
#include <pango/pangocairo.h>
#include <stdbool.h>
#include <wayland-client.h>

struct buffer
{
    struct wl_buffer *buffer; // NULL if not initialized
    cairo_surface_t  *csurf;
    cairo_t          *cr;
    PangoContext     *pango;

    void  *data;
    size_t sz;

    // In physical pixels
    uint32_t width;
    uint32_t height;

    bool busy;
};

// clang-format off
int buffer_init(struct buffer *buffer, uint32_t w, uint32_t h, struct wl_shm *shm);
void buffer_uninit(struct buffer *buffer);
struct buffer *buffer_get_next(struct buffer buffers[2], struct wl_shm *shm, uint32_t w, uint32_t h);
// clang-format on
