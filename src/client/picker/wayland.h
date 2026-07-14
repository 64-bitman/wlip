#pragma once

#include "event.h"
#include "fractional-scale-v1.h"
#include "wayland_base.h"
#include "wlr-layer-shell-unstable-v1.h"
#include <cairo.h>
#include <wayland-client.h>

struct wayland_seat
{
    struct wayland *wayland;

    struct wl_seat *proxy;
    char           *name; // May be NULL if seat has not been started yet.
    uint32_t        id;   // Used to match with global_remove event

    // Any of these may be NULL
    struct wl_keyboard *keyboard;
    struct wl_pointer  *pointer;
    struct wl_touch    *touch;

    struct wl_list link;
};

struct wayland
{
    struct wayland_base base;

    struct wl_compositor *compositor;
    struct wl_shm        *shm;
    struct wl_list        seats;

    struct zwlr_layer_shell_v1            *layer_shell;
    struct wp_fractional_scale_manager_v1 *frac_mgr;

    double                         scale;
    struct wl_surface             *surf;
    struct zwlr_layer_surface_v1  *lsurf;
    struct wp_fractional_scale_v1 *frac;

    int              buffd;
    cairo_surface_t *csurf;
    cairo_t         *cr;
};

// clang-format off
int wayland_init(struct wayland *wayland, struct eventloop *loop);
void wayland_uninit(struct wayland *wayland);
// clang-format on
