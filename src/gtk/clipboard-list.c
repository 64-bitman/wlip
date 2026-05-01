#include "clipboard-list.h"
#include "ipc.h"
#include <gio/gio.h>
#include <glib-object.h>

struct _ClipboardList
{
    GObject parent;

    GHashTable *cache;

    struct ipc *ipc;
};

// clang-format off
static void clipboard_list_model_init(GListModelInterface *iface);
// clang-format on

G_DEFINE_TYPE_WITH_CODE(
    ClipboardList,
    clipboard_list,
    G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE(G_TYPE_LIST_MODEL, clipboard_list_model_init)
)

static void
clipboard_list_finalize(GObject *object)
{
    ClipboardList *self = CLIPBOARD_LIST(object);

    g_hash_table_unref(self->cache);

    G_OBJECT_CLASS(clipboard_list_parent_class)->finalize(object);
}

static void
clipboard_list_class_init(ClipboardListClass *class)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS(class);

    gobject_class->finalize = clipboard_list_finalize;
}

static void
clipboard_list_init(ClipboardList *self)
{
    self->cache = g_hash_table_new_full(
        g_direct_hash, g_direct_equal, NULL, g_object_unref
    );
}

ClipboardList *
clipboard_list_new(struct ipc *ipc)
{
    ClipboardList *list = g_object_new(CLIPBOARD_TYPE_LIST, NULL);

    list->ipc = ipc;
    return list;
}

static void
clipboard_list_model_init(GListModelInterface *iface)
{
}
