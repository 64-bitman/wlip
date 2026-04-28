#pragma once

#include "wayland_base.h"
#include "wlr-layer-shell-unstable-v1.h"
#include "xdg-shell.h"
#include <wayland-client.h>

struct wayland
{
    struct wayland_base base;

    struct wl_compositor         *compositor;
    struct zwlr_layer_surface_v1 *layer_surface;
};
