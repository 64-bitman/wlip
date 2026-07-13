#include "wliplist.h"
#include "wlipdaemon.h"
#include <gio/gio.h>
#include <glib.h>
#include <json-glib/json-glib.h>

struct _WlipList
{
    GObject parent;

    WlipDaemon *daemon;

    GTree *entries;
};

static void *
wlip_list_get_item(GListModel *list, guint position)
{
    return NULL;
}

static GType
wlip_list_get_item_type(GListModel *list G_GNUC_UNUSED)
{
    return WLIP_TYPE_ENTRY;
}

static guint
wlip_list_get_n_items(GListModel *list)
{
    WlipList *self = WLIP_LIST(list);

    return wlip_daemon_get_history_size(self->daemon);
}

static void
wlip_list_model_init(GListModelInterface *iface)
{
    iface->get_item = wlip_list_get_item;
    iface->get_item_type = wlip_list_get_item_type;
    iface->get_n_items = wlip_list_get_n_items;
}

G_DEFINE_TYPE_WITH_CODE(
    WlipList,
    wlip_list,
    G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE(G_TYPE_LIST_MODEL, wlip_list_model_init)
)

static void
wlip_list_finalize(GObject *obj)
{
    WlipList *self = WLIP_LIST(obj);

    g_tree_unref(self->entries);

    G_OBJECT_CLASS(wlip_list_parent_class)->finalize(obj);
}

static void
wlip_list_dispose(GObject *obj)
{
    WlipList *self = WLIP_LIST(obj);

    g_clear_object(&self->daemon);

    G_OBJECT_CLASS(wlip_list_parent_class)->dispose(obj);
}

static void
wlip_list_class_init(WlipListClass *class)
{
    GObjectClass *obj_class = G_OBJECT_CLASS(class);

    obj_class->finalize = wlip_list_finalize;
    obj_class->dispose = wlip_list_dispose;
}

static int
key_compare_func(const void *a, const void *b)
{
    guint ia = GPOINTER_TO_UINT(a);
    guint ib = GPOINTER_TO_UINT(b);

    if (ia == ib)
        return 0;
}

static void
wlip_list_init(WlipList *self)
{
    self->entries = g_tree_new(NULL);
}

WlipList *
wlip_list_new(WlipDaemon *daemon)
{
    g_assert(WLIP_IS_DAEMON(daemon));

    WlipList *list = g_object_new(WLIP_TYPE_LIST, NULL);

    list->daemon = g_object_ref(daemon);
    return list;
}
