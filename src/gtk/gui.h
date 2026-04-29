#pragma once

#include "config.h"
#include "ipc.h"
#include <gtk-4.0/gtk/gtk.h>

struct gui
{
    GMainLoop   *loop;
    GtkWindow   *window;
    GtkBuilder  *builder;
    GtkListView *list_view;

    struct config config;
    struct ipc    ipc;
};

// clang-format off
int gui_init(struct gui *gui, GMainLoop *loop);
void gui_uninit(struct gui *gui);
// clang-format on
