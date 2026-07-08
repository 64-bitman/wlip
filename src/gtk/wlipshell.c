#include "wlipshell.h"
#include "wlipdaemon.h"
#include "wliplist.h"
#include <gtk/gtk.h>
#include <gtk4-layer-shell.h>

struct _WlipShell
{
    GObject parent;

    WlipDaemon *daemon;
    WlipList   *list;
    GtkWidget  *win;

    GtkWidget *vbox;    // Vertical box that holds everything
    GtkWidget *menubar; // Popover menu bar
    GtkWidget *search;  // Search entry
    GtkWidget *view;    // Entry list view
};

G_DEFINE_TYPE(WlipShell, wlip_shell, G_TYPE_OBJECT)

static void
wlip_shell_dispose(GObject *obj)
{
    WlipShell *self = WLIP_SHELL(obj);

    g_clear_object(&self->daemon);
    g_clear_object(&self->list);
    g_clear_pointer((GtkWindow **)&self->win, gtk_window_destroy);

    G_OBJECT_CLASS(wlip_shell_parent_class)->dispose(obj);
}

static void
wlip_shell_class_init(WlipShellClass *class)
{
    GObjectClass *obj_class = G_OBJECT_CLASS(class);

    obj_class->dispose = wlip_shell_dispose;
}

static void
wlip_shell_init(WlipShell *self)
{
    self->win = gtk_window_new();

    // TODO
    gtk_window_set_default_size(GTK_WINDOW(self->win), 500, 600);

    gtk_layer_init_for_window(GTK_WINDOW(self->win));
    gtk_layer_set_keyboard_mode(
        GTK_WINDOW(self->win), GTK_LAYER_SHELL_KEYBOARD_MODE_ON_DEMAND
    );
    gtk_layer_set_layer(GTK_WINDOW(self->win), GTK_LAYER_SHELL_LAYER_OVERLAY);

    self->vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    // TODO
    self->menubar = gtk_popover_menu_bar_new_from_model(NULL);
    gtk_box_append(GTK_BOX(self->vbox), self->menubar);

    self->search = gtk_search_entry_new();
    gtk_box_append(GTK_BOX(self->vbox), self->search);
}

/*
 * Create a new shell and start presenting it
 */
WlipShell *
wlip_shell_new(WlipDaemon *daemon, WlipList *list)
{
    WlipShell *shell = g_object_new(WLIP_TYPE_SHELL, NULL);

    shell->daemon = g_object_ref(daemon);
    shell->list = g_object_ref(list);

    gtk_window_present(GTK_WINDOW(shell->win));

    return shell;
}
