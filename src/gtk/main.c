#include "wlipdaemon.h"
#include "wliplist.h"
#include <glib-unix.h>
#include <glib.h>

static gboolean
signal_handler(GMainLoop *loop)
{
    g_main_loop_quit(loop);
    return G_SOURCE_CONTINUE;
}

int
main(int argc G_GNUC_UNUSED, char **argv G_GNUC_UNUSED)
{
    static const GOptionEntry entries[] = {G_OPTION_ENTRY_NULL};

    g_autoptr(GError) error = NULL;
    g_autoptr(GOptionContext) context = g_option_context_new("");

    g_option_context_add_main_entries(context, entries, NULL);

    if (!g_option_context_parse(context, &argc, &argv, &error))
    {
        g_printerr("Error parsing options: %s\n", error->message);
        return EXIT_FAILURE;
    }

    // Temporary
    g_log_set_debug_enabled(TRUE);

    g_autoptr(GMainLoop) loop = g_main_loop_new(NULL, FALSE);

    guint signal_handlers[2] = {
        g_unix_signal_add(SIGTERM, (GSourceFunc)signal_handler, loop),
        g_unix_signal_add(SIGINT, (GSourceFunc)signal_handler, loop),
    };

    g_autoptr(WlipDaemon) daemon = wlip_daemon_new(NULL, NULL);
    g_autoptr(WlipList) list = wlip_list_new(daemon);

    g_main_loop_run(loop);

    for (guint i = 0; i < G_N_ELEMENTS(signal_handlers); i++)
        g_source_remove(signal_handlers[i]);

    g_debug("Exiting...");

    return EXIT_SUCCESS;
}
