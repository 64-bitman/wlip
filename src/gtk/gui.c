#include "gui.h"
#include "config.h"
#include "ipc.h"
#include "util.h"
#include <gtk-4.0/gtk/gtk.h>
#include <gtk4-layer-shell.h>

// clang-format off
static gboolean shortcut_quit(GtkWidget *widget, GVariant *args, struct gui *gui);
// clang-format on

/*
 * Initialize GTK and application window. Returns OK on success and FAIL on
 * failure.
 */
int
gui_init(struct gui *gui, GMainLoop *loop)
{
    gtk_init();

    // clang-format off
    struct shortcut_handlers global = {
        .quit = {
            .callback = (GtkShortcutFunc)shortcut_quit,
            .udata = gui
        }
    };
    // clang-format on

    if (config_init(&gui->config, NULL, &global) == FAIL)
        return FAIL;
    if (ipc_init(&gui->ipc, gui) == FAIL)
    {
        config_uninit(&gui->config);
        return FAIL;
    }

    gui->loop = loop;
    gui->window = GTK_WINDOW(gtk_window_new());

    gtk_layer_init_for_window(gui->window);
    gtk_layer_set_keyboard_mode(
        gui->window, GTK_LAYER_SHELL_KEYBOARD_MODE_EXCLUSIVE
    );
    gtk_layer_auto_exclusive_zone_enable(gui->window);

    gtk_window_set_auto_startup_notification(FALSE);
    gtk_window_set_default_size(
        gui->window, gui->config.width, gui->config.height
    );

    gtk_widget_add_controller(
        GTK_WIDGET(gui->window), g_object_ref(gui->config.global_shortcuts)
    );

    GtkListItemFactory *factory = gtk_signal_list_item_factory_new();

    gtk_window_present(gui->window);

    return OK;
}

void
gui_uninit(struct gui *gui)
{
    ipc_uninit(&gui->ipc);
    config_uninit(&gui->config);
    gtk_window_destroy(gui->window);
}

static gboolean
shortcut_quit(GtkWidget *widget UNUSED, GVariant *args UNUSED, struct gui *gui)
{
    g_main_loop_quit(gui->loop);
    return TRUE;
}
