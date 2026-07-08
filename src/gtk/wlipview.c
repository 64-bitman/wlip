#include "wlipview.h"
#include "wliplist.h"

struct _WlipViewItem
{
    GtkWidget parent;

    // Contains header and main content
    GtkWidget *vbox;

    GtkWidget *header;
};

G_DEFINE_TYPE(WlipViewItem, wlip_view_item, GTK_TYPE_WIDGET)

static void
wlip_view_item_dispose(GObject *obj)
{
    WlipViewItem *self = WLIP_VIEW_ITEM(obj);

    G_OBJECT_CLASS(wlip_view_item_parent_class)->dispose(obj);
}

static void
wlip_view_item_class_init(WlipViewItemClass *class)
{
    GObjectClass *obj_class = G_OBJECT_CLASS(class);

    obj_class->dispose = wlip_view_item_dispose;
}

static void
wlip_view_item_init(WlipViewItem *self)
{
}

struct _WlipView
{
    GtkWidget parent;

    WlipDaemon *daemon;
    WlipList   *list;
    GtkWidget  *scr; // Scrolled window

    GtkSelectionModel  *sel;
    GtkListItemFactory *factory;
    GtkWidget          *listview;
};

G_DEFINE_TYPE(WlipView, wlip_view, GTK_TYPE_WIDGET)

static void
wlip_view_dispose(GObject *obj)
{
    WlipView *self = WLIP_VIEW(obj);

    g_clear_object(&self->daemon);
    g_clear_object(&self->list);
    g_clear_pointer(&self->scr, gtk_widget_unparent);

    G_OBJECT_CLASS(wlip_view_parent_class)->dispose(obj);
}

static void
wlip_view_class_init(WlipViewClass *class)
{
    GObjectClass *obj_class = G_OBJECT_CLASS(class);

    obj_class->dispose = wlip_view_dispose;
}

static void
wlip_view_init(WlipView *self)
{
    self->scr = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(
        GTK_SCROLLED_WINDOW(self->scr), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC
    );
    gtk_widget_set_parent(self->scr, GTK_WIDGET(self));

    self->sel = GTK_SELECTION_MODEL(gtk_single_selection_new(NULL));
    self->factory = gtk_signal_list_item_factory_new();

    self->listview = gtk_list_view_new(self->sel, self->factory);
    gtk_scrolled_window_set_child(
        GTK_SCROLLED_WINDOW(self->scr), self->listview
    );
}

GtkWidget *
wlip_view_new(WlipDaemon *daemon, WlipList *list)
{
    WlipView *view = g_object_new(WLIP_TYPE_VIEW, NULL);

    view->daemon = g_object_ref(daemon);
    view->list = g_object_ref(list);

    gtk_single_selection_set_model(
        GTK_SINGLE_SELECTION(view->sel), G_LIST_MODEL(list)
    );

    return GTK_WIDGET(view);
}
