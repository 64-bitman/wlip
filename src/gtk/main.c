#include "log.h"
#include "util.h"
#include <glib-unix.h>
#include <glib.h>
#include <gtk-4.0/gtk/gtk.h>
#include <gtk4-layer-shell/gtk4-layer-shell.h>

static gboolean
signal_handler(void *data)
{
    g_main_loop_quit(data);

    // We will remove the source after the main loop quits
    return G_SOURCE_CONTINUE;
}

int
main(int argc, char **argv)
{
    static const GOptionEntry options[] = {G_OPTION_ENTRY_NULL};

    g_autoptr(GError) error = NULL;
    g_autoptr(GOptionContext) context = g_option_context_new("");

    log_init(NULL);
    log_set_level(LOG_DEBUG); // Temporary

    g_option_context_add_main_entries(context, options, NULL);
    if (!g_option_context_parse(context, &argc, &argv, &error))
    {
        log_error("%s", error->message);
        return EXIT_FAILURE;
    }

    g_autoptr(GMainLoop) loop = g_main_loop_new(NULL, FALSE);
    uint signals[2];

    signals[0] = g_unix_signal_add(SIGINT, signal_handler, loop);
    signals[1] = g_unix_signal_add(SIGTERM, signal_handler, loop);

    gtk_init();

    GtkWindow *win = GTK_WINDOW(gtk_window_new());

    gtk_layer_init_for_window(win);
    gtk_layer_set_exclusive_zone(win, TRUE);
    gtk_layer_set_keyboard_mode(win, GTK_LAYER_SHELL_KEYBOARD_MODE_NONE);
    gtk_layer_set_layer(win, GTK_LAYER_SHELL_LAYER_OVERLAY);

    gtk_window_set_default_size(win, 500, 600);
    gtk_window_present(win);

    g_main_loop_run(loop);

    log_info("Exiting...");

    gtk_window_destroy(win);

    for (uint i = 0; i < N_ELEMENTS(signals); i++)
        g_source_remove(signals[i]);

    return EXIT_SUCCESS;
}
