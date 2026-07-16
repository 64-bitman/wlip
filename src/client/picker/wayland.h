#pragma once

#include "event.h"
#include "fractional-scale-v1.h"
#include "viewporter.h"
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

struct wayland_output
{
    struct wayland *wayland;

    struct wl_output *proxy;
    char             *name; // May be NULL
    uint32_t          id;

    enum wl_output_subpixel subpixel;

    struct wl_list link;
};

struct wayland
{
    struct wayland_base base;

    struct wl_compositor *compositor;
    struct wl_shm        *shm;
    struct wl_list        seats;
    struct wl_list        outputs;

    struct zwlr_layer_shell_v1            *layer_shell;
    struct wp_fractional_scale_manager_v1 *frac_mgr;
    struct wp_viewporter                  *vporter;
};

// clang-format off
int wayland_init(struct wayland *wayland, struct eventloop *loop);
void wayland_uninit(struct wayland *wayland);
struct wayland_output *wayland_find_output(struct wayland *wayland, const char *name);
// clang-format on
