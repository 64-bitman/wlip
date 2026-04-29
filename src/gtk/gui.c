#include "gui.h"
#include "util.h"
#include <gtk-4.0/gtk/gtk.h>
#include <gtk4-layer-shell.h>

/*
 * Initialize GTK and application window. Returns OK on success and FAIL on
 * failure.
 */
int
gui_init(struct gui *gui, GMainLoop *loop)
{
    gtk_init();

    gui->loop = loop;
    gui->builder =
        gtk_builder_new_from_resource("/com/github/wlipgtk/wlipgtk.ui");

    gui->window = GTK_WINDOW(gtk_builder_get_object(gui->builder, "win"));

    gtk_layer_init_for_window(gui->window);
    gtk_layer_set_keyboard_mode(
        gui->window, GTK_LAYER_SHELL_KEYBOARD_MODE_EXCLUSIVE
    );
    gtk_layer_auto_exclusive_zone_enable(gui->window);

    gtk_window_set_auto_startup_notification(FALSE);
    gtk_window_set_default_size(gui->window, 800, 600);

    gtk_window_present(gui->window);

    return OK;
}

void
gui_uninit(struct gui *gui)
{
    gtk_window_destroy(gui->window);
    g_object_unref(gui->builder);
}
