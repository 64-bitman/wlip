#include "wlipgtk.h"
#include "ipc.h"
#include "util.h"
#include <gtk-4.0/gtk/gtk.h>
#include <gtk4-layer-shell.h>

// clang-format off
static gboolean shortcut_quit(GtkWidget *widget UNUSED, GVariant *args UNUSED, GMainLoop *loop);

static void event_handler(struct json_object *event, void *udata);
// clang-format on

int
wlipgtk_init(struct wlipgtk *wlipgtk, GMainLoop *loop)
{
    gtk_init();

    // clang-format off
    struct shortcut_handlers global = {
        .quit = {
            .callback = (GtkShortcutFunc)shortcut_quit,
            .udata = loop
        }
    };
    // clang-format on

    if (config_init(&wlipgtk->config, NULL, &global) == FAIL)
        return FAIL;
    if (ipc_init(&wlipgtk->ipc, event_handler, wlipgtk) == FAIL)
        return FAIL;

    wlipgtk->loop = loop;
    wlipgtk->window = GTK_WINDOW(gtk_window_new());

    gtk_layer_init_for_window(wlipgtk->window);
    gtk_layer_set_keyboard_mode(wlipgtk->window, wlipgtk->config.keyboard_mode);
    gtk_layer_set_layer(wlipgtk->window, wlipgtk->config.layer_mode);
    gtk_layer_auto_exclusive_zone_enable(wlipgtk->window);

    gtk_window_set_default_size(
        wlipgtk->window, wlipgtk->config.width, wlipgtk->config.height
    );

    gtk_widget_add_controller(
        GTK_WIDGET(wlipgtk->window),
        g_object_ref(wlipgtk->config.global_shortcuts)
    );

    gtk_window_present(wlipgtk->window);

    return OK;
}

void
wlipgtk_uninit(struct wlipgtk *wlipgtk)
{
    gtk_window_destroy(wlipgtk->window);
    config_uninit(&wlipgtk->config);
    ipc_uninit(&wlipgtk->ipc);
}

static void
event_handler(struct json_object *event, void *udata)
{
    struct wlipgtk *wlipgtk = udata;

    json_object_put(event);
}

static gboolean
shortcut_quit(GtkWidget *widget UNUSED, GVariant *args UNUSED, GMainLoop *loop)
{
    g_main_loop_quit(loop);
    return TRUE;
}
