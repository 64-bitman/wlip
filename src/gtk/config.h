#pragma once

#include <gtk-4.0/gtk/gtk.h>
#include <gtk4-layer-shell.h>

struct config
{
    int width;
    int height;

    GtkLayerShellKeyboardMode keyboard_mode;
    GtkLayerShellLayer        layer_mode;

    GtkEventController *global_shortcuts;
};
