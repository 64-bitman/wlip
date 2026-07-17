#pragma once

#include "buffer.h"
#include "fractional-scale-v1.h"
#include "viewporter.h"
#include "wlr-layer-shell-unstable-v1.h"
#include <wayland-client.h>

struct wayland;

struct surface
{
    struct wayland *wayland;

    struct wl_surface            *surf; // NULL if closed
    struct zwlr_layer_surface_v1 *lsurf;
    // If NULL, then use "preferred_buffer_scale" event to get scale.
    struct wp_fractional_scale_v1 *frac;
    struct wp_viewport            *vport;

    double scale;
    // In logical pixels
    uint32_t width;
    uint32_t height;

    // Note that buffer cairo_t will already be scaled properly.
    struct buffer  buffers[2];
    struct buffer *cur_buffer;

    // If true, then current buffer should be changed and committed always.
    bool dirty;
};

// clang-format off
int surface_init(struct surface *surf, struct wayland *wayland, uint32_t w, uint32_t h, const char *output_name);
void surface_uninit(struct surface *surf);
// clang-format on
