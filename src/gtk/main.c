#include "clipboard-entry.h"
#include "clipboard-list.h"
#include "entry-box.h"
#include "log.h"
#include "util.h"
#include <glib-unix.h>
#include <glib.h>
#include <gtk-4.0/gtk/gtk.h>
#include <gtk4-layer-shell/gtk4-layer-shell.h>

// clang-format off
static void setup_cb(GtkSignalListItemFactory *self, GtkListItem *listitem, gpointer udata UNUSED);
static void bind_cb(GtkSignalListItemFactory *self, GtkListItem *listitem, gpointer udata UNUSED);
static void unbind_cb(GtkSignalListItemFactory *self, GtkListItem *listitem, gpointer udata UNUSED);
// clang-format on

static gboolean
signal_handler(void *data)
{
    g_main_loop_quit(data);

    // We will remove the source after the main loop quits
    return G_SOURCE_CONTINUE;
}

static gboolean
close_handler(GtkWindow *win UNUSED, GMainLoop *loop)
{
    g_main_loop_quit(loop);
    return FALSE;
}

int
main(int argc, char **argv)
{
    static bool opt_window = false;

    static const GOptionEntry options[] = {
        {"window",
         'w',
         0,
         G_OPTION_ARG_NONE,
         &opt_window,
         "Open in normal window",
         ""},
        G_OPTION_ENTRY_NULL
    };

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

    GdkDisplay     *display = gdk_display_get_default();
    GtkCssProvider *default_style = gtk_css_provider_new();

    gtk_css_provider_load_from_resource(
        default_style, "/com/github/wlipgtk/style.css"
    );

    gtk_style_context_add_provider_for_display(
        display,
        GTK_STYLE_PROVIDER(default_style),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION
    );

    GtkWindow *win = GTK_WINDOW(gtk_window_new());
    gtk_widget_add_css_class(GTK_WIDGET(win), "window");

    g_signal_connect(win, "close-request", G_CALLBACK(close_handler), loop);

    g_autoptr(IPCHandle) ipc_handle = ipc_handle_new();

    if (!opt_window)
    {
        gtk_layer_init_for_window(win);
        gtk_layer_set_keyboard_mode(win, GTK_LAYER_SHELL_KEYBOARD_MODE_NONE);
        gtk_layer_set_layer(win, GTK_LAYER_SHELL_LAYER_OVERLAY);
    }

    gtk_window_set_default_size(win, 500, 600);

    ClipboardList      *list = clipboard_list_new(ipc_handle);
    GtkListItemFactory *factory = gtk_signal_list_item_factory_new();

    g_signal_connect(factory, "setup", G_CALLBACK(setup_cb), NULL);
    g_signal_connect(factory, "bind", G_CALLBACK(bind_cb), NULL);
    /* The following two lines can be left out. The handlers do nothing. */
    g_signal_connect(factory, "unbind", G_CALLBACK(unbind_cb), NULL);
    // "teardown" signal is not needed

    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_add_css_class(main_box, "container");

    GtkWidget *view = gtk_list_view_new(
        GTK_SELECTION_MODEL(gtk_single_selection_new(G_LIST_MODEL(list))),
        factory
    );
    gtk_widget_add_css_class(view, "list");

    GtkWidget *scr = gtk_scrolled_window_new();
    gtk_widget_add_css_class(scr, "scroll_win");

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scr), view);
    gtk_scrolled_window_set_policy(
        GTK_SCROLLED_WINDOW(scr), GTK_POLICY_NEVER, GTK_POLICY_ALWAYS
    );
    gtk_box_append(GTK_BOX(main_box), scr);
    gtk_widget_set_vexpand(scr, TRUE);

    gtk_window_set_child(GTK_WINDOW(win), main_box);
    gtk_window_present(win);

    g_main_loop_run(loop);

    log_info("Exiting...");

    gtk_window_destroy(win);

    for (uint i = 0; i < N_ELEMENTS(signals); i++)
        g_source_remove(signals[i]);

    return EXIT_SUCCESS;
}

static void
setup_cb(
    GtkSignalListItemFactory *self UNUSED,
    GtkListItem                   *item,
    gpointer udata                 UNUSED
)
{
    GtkWidget *ebox = entry_box_new();

    gtk_list_item_set_child(item, ebox);
}

static void
bind_cb(
    GtkSignalListItemFactory *self UNUSED,
    GtkListItem                   *item,
    gpointer udata                 UNUSED
)
{
    GtkWidget      *ebox = gtk_list_item_get_child(item);
    ClipboardEntry *entry = gtk_list_item_get_item(item);
    uint            pos = gtk_list_item_get_position(item);

    entry_box_set(ENTRY_BOX(ebox), entry, item, pos);
}

static void
unbind_cb(
    GtkSignalListItemFactory *self UNUSED,
    GtkListItem                   *item,
    gpointer udata                 UNUSED
)
{
    GtkWidget *ebox = gtk_list_item_get_child(item);

    entry_box_set(ENTRY_BOX(ebox), NULL, NULL, 0);
}
