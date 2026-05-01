#pragma once

#include "config.h"
#include "ipc.h"
#include <gtk-4.0/gtk/gtk.h>
#include <gtk4-layer-shell.h>

struct wlipgtk
{
    GMainLoop *loop;
    GtkWindow *window;

    struct config config;
    struct ipc    ipc;
};

// clang-format off
int wlipgtk_init(struct wlipgtk *wlipgtk, GMainLoop *loop);
void wlipgtk_uninit(struct wlipgtk *wlipgtk);
// clang-format on
