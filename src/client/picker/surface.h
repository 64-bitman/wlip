#pragma once

#include "buffer.h"
#include "fractional-scale-v1.h"
#include "viewporter.h"
#include "wayland.h"
#include "wlr-layer-shell-unstable-v1.h"
#include <wayland-client.h>

struct surface
{
    struct wl_surface            *surf;
    struct zwlr_layer_surface_v1 *lsurf;
    // If NULL, then use "preferred_buffer_scale" event to get scale.
    struct wp_fractional_scale_v1 *frac;
    struct wp_viewport            *vport;

    double scale;

    struct buffer_pool pool;
};

// clang-format off
int surface_init(struct surface *surf, struct wayland *wayland, const char *output);
// clang-format on
