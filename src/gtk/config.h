#pragma once

#include <gtk-4.0/gtk/gtk.h>
#include <gtk4-layer-shell.h>

struct shortcut_handler
{
    GtkShortcutFunc callback;
    void           *udata;
};

struct shortcut_handlers
{
    struct shortcut_handler quit;
};

struct config
{
    int width;
    int height;

    GtkLayerShellKeyboardMode keyboard_mode;
    GtkLayerShellLayer        layer_mode;

    GtkEventController *global_shortcuts;
};

// clang-format off
int config_init(struct config *config, const char *cfgdir, struct shortcut_handlers *handlers);
void config_uninit(struct config *config);
// clang-format on
