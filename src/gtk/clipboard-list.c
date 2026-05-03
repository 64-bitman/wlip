#include "clipboard-list.h"
#include "clipboard-entry.h"
#include "ipc-handle.h"
#include "ipc_client.h"
#include "log.h"
#include <gio/gio.h>

struct _ClipboardList
{
    GObject parent;

    // Number of entries that list model currently represents. It is
    // incrementally increased to "actual_size".
    //
    // This is done so that the list view/signal factory doesnt just do all the
    // bind requests in one go, freezing the ui temporarily.
    int64_t size;
    uint    timer_id;

    // Total number of entries from daemon (not size of cache)
    int64_t actual_size;

    // Mapping of positions to entries. Index of entry in array is its position.
    // Note that some elements may be NULL, if get_item() was called beyond the
    // current length of the array.
    GArray *cache;

    IPCHandle *ipc_handle;
};

static void clipboard_list_model_init(GListModelInterface *iface);
G_DEFINE_TYPE_WITH_CODE(
    ClipboardList,
    clipboard_list,
    G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE(G_TYPE_LIST_MODEL, clipboard_list_model_init)
)

// clang-format off
static void history_size_callback(IPCHandle *ipc_handle, GAsyncResult *result, ClipboardList *list);

static GType clipboard_list_model_get_item_type(GListModel *list);
static uint clipboard_list_model_get_n_items(GListModel *list);
static void *clipboard_list_model_get_item(GListModel *list, uint pos);
// clang-format on

static void
clipboard_list_model_init(GListModelInterface *iface)
{
    iface->get_item_type = clipboard_list_model_get_item_type;
    iface->get_n_items = clipboard_list_model_get_n_items;
    iface->get_item = clipboard_list_model_get_item;
}

static void
clipboard_list_finalize(GObject *object)
{
    ClipboardList *list = CLIPBOARD_LIST(object);

    g_assert(list->timer_id == 0);
    g_array_unref(list->cache);

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
    self->size = 0;
    self->cache = g_array_new(FALSE, TRUE, sizeof(ClipboardEntry *));
    g_array_set_clear_func(self->cache, g_object_unref);
}

ClipboardList *
clipboard_list_new(IPCHandle *ipc_handle)
{
    g_assert(IPC_IS_HANDLE(ipc_handle));

    ClipboardList *list = g_object_new(CLIPBOARD_TYPE_LIST, NULL);

    list->ipc_handle = ipc_handle;

    ipc_handle_request_async(
        ipc_handle,
        IPC_REQUEST_TYPE_HISTORY_SIZE,
        NULL,
        (GAsyncReadyCallback)history_size_callback,
        g_object_ref(list)
    );

    return list;
}

static gboolean
increment_size_callback(ClipboardList *list)
{
    int64_t  old = list->size;
    int64_t  change = 10;
    gboolean ret = G_SOURCE_CONTINUE;

    if (list->size + change > list->actual_size)
    {
        change = list->actual_size - list->size;
        list->timer_id = 0;
        ret = G_SOURCE_REMOVE;
    }
    list->size += change;

    g_list_model_items_changed(G_LIST_MODEL(list), old, 0, change);

    return ret;
}

static void
history_size_callback(
    IPCHandle *ipc_handle, GAsyncResult *result, ClipboardList *list
)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(JsonObj) resp =
        ipc_handle_request_finish(ipc_handle, result, &error);

    if (resp == NULL)
    {
        log_warn("Error sending history_size request: %s", error->message);
        return;
    }
    if (ipc_is_error(resp))
    {
        log_warn("Error getting history size: %s", ipc_get_error_desc(resp));
        return;
    }

    int64_t size;

    if (get_json_integer(resp, "size", &size) == FAIL)
        return;

    list->actual_size = size;
    if (list->timer_id == 0)
        list->timer_id = g_timeout_add_full(
            G_PRIORITY_LOW,
            100,
            (GSourceFunc)increment_size_callback,
            g_object_ref(list),
            g_object_unref
        );
}

static GType
clipboard_list_model_get_item_type(GListModel *self UNUSED)
{
    return CLIPBOARD_TYPE_ENTRY;
}

static uint
clipboard_list_model_get_n_items(GListModel *self)
{
    // This might overflow since a 64 bit integer is used for the history size,
    // but I highly doubt that will be an actual problem.
    return CLIPBOARD_LIST(self)->size;
}

static int
clipboard_list_get_entry(ClipboardList *list, uint pos, ClipboardEntry **entry)
{
    ClipboardEntry **arr = (void *)list->cache->data;

    if (pos >= list->size)
        return FAIL;
    if (pos >= list->cache->len)
        *entry = NULL;
    else
        *entry = arr[pos];
    return OK;
}

static void *
clipboard_list_model_get_item(GListModel *self, uint pos)
{
    ClipboardList  *list = CLIPBOARD_LIST(self);
    ClipboardEntry *entry;

    if (clipboard_list_get_entry(list, pos, &entry) == FAIL)
        return NULL;

    if (entry == NULL)
    {
        entry = clipboard_entry_new(list->ipc_handle);
        g_array_insert_vals(list->cache, pos, &entry, 1);
    }

    return g_object_ref(entry);
}
