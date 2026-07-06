#pragma once

#include "event.h"
#include <stdbool.h>

struct wayland_base
{
    struct eventsource  source;
    struct eventprepare prepare;

    bool                reading;
    struct wl_display  *display;
    struct wl_registry *registry;
    int                 fd;

    struct eventloop *loop;
};

// clang-format off
int wayland_base_init(struct wayland_base *wbase, const char *display, struct eventloop *loop);
void wayland_base_uninit(struct wayland_base *wbase);
// clang-format on
