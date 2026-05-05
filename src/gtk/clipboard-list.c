#include "clipboard-list.h"
#include "clipboard-entry.h"
#include "ipc-handle.h"
#include "ipc_client.h"
#include "log.h"
#include <gio/gio.h>

struct _ClipboardList
{
    GObject parent;

    // Total number of entries from daemon (not size of cache)
    int64_t       size;
    GCancellable *cancel; // Used to cancel "history_size" request, when we
                          // received a "change" event before we received the
                          // response.

    // Mapping of positions to entries. Index of entry in array is its position.
    // Note that some elements may be NULL, if get_item() was called beyond the
    // current length of the array.
    GPtrArray *cache;

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
static void ipc_change_event_callback(IPCHandle *ipc_handle, struct json_object *event, ClipboardList *list);

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

    g_ptr_array_unref(list->cache);

    G_OBJECT_CLASS(clipboard_list_parent_class)->finalize(object);
}

static void
clipboard_list_class_init(ClipboardListClass *class)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS(class);

    gobject_class->finalize = clipboard_list_finalize;
}

static void
object_unref(void *obj)
{
    if (obj != NULL)
        g_object_unref(obj);
}

static void
clipboard_list_init(ClipboardList *self)
{
    self->size = 0;
    self->cache = g_ptr_array_new_with_free_func(object_unref);
}

static void
send_history_size_req(ClipboardList *list)
{
    g_assert(CLIPBOARD_IS_LIST(list));

    list->cancel = g_cancellable_new();
    ipc_handle_request_async(
        list->ipc_handle,
        IPC_REQUEST_TYPE_HISTORY_SIZE,
        list->cancel,
        (GAsyncReadyCallback)history_size_callback,
        g_object_ref(list)
    );
}

ClipboardList *
clipboard_list_new(IPCHandle *ipc_handle)
{
    g_assert(IPC_IS_HANDLE(ipc_handle));

    ClipboardList *list = g_object_new(CLIPBOARD_TYPE_LIST, NULL);

    list->ipc_handle = ipc_handle;

    send_history_size_req(list);
    ipc_handle_request_async(
        ipc_handle, IPC_REQUEST_TYPE_SUBSCRIBE, NULL, NULL, NULL, "change", NULL
    );
    g_signal_connect_object(
        ipc_handle,
        "event::change",
        G_CALLBACK(ipc_change_event_callback),
        list,
        G_CONNECT_DEFAULT
    );

    return list;
}

/*
 * Send a request to the daemon to set the selection to the given entry at
 * position "pos".
 */
void
clipboard_list_copy(ClipboardList *self, uint pos)
{
    g_assert(CLIPBOARD_IS_LIST(self));
    g_assert(pos < self->size);

    ClipboardEntry **arr = (ClipboardEntry **)self->cache->pdata;

    if (pos >= self->cache->len)
    {
        log_warn("Position %u is larger than cache size?", pos);
        return;
    }

    ClipboardEntry *entry = arr[pos];

    if (entry == NULL)
    {
        log_warn("Position %u is NULL?", pos);
        return;
    }

    int64_t id;

    if (clipboard_entry_get_id(entry, &id) == FAIL)
        // Entry not loaded, just become a no op
        return;

    ipc_handle_request_async(
        self->ipc_handle, IPC_REQUEST_TYPE_SET, NULL, NULL, NULL, id
    );
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
        if (error->code != G_IO_ERROR_CANCELLED)
            log_warn("Error sending history_size request: %s", error->message);
        goto exit;
    }
    if (ipc_is_error(resp))
    {
        log_warn("Error getting history size: %s", ipc_get_error_desc(resp));
        goto exit;
    }

    int64_t size;

    if (get_json_integer(resp, "size", &size) == FAIL)
        goto exit;

    list->size = size;
    g_list_model_items_changed(G_LIST_MODEL(list), 0, 0, size);
exit:
    g_clear_object(&list->cancel);
    g_object_unref(list);
}

static void
ipc_change_event_callback(
    IPCHandle *ipc_handle UNUSED, struct json_object *event, ClipboardList *list
)
{
    const char *change = get_json_string(event, "change");
    int64_t     id, index;

    if (list->cancel != NULL)
    {
        // Resend the request again
        log_debug(
            "Received change event before history_size response, resending"
        );
        g_cancellable_cancel(list->cancel);
        g_object_unref(list->cancel);
        send_history_size_req(list);
        return;
    }

    if (change == NULL || get_json_integer(event, "id", &id) == FAIL ||
        get_json_integer(event, "index", &index) == FAIL)
        return;

    if (index < 0)
        return;

    if (strcmp(change, "new") == 0)
    {
        int64_t i = list->size - index;

        if (i >= 0)
        {
            if (i <= list->cache->len)
            {
                g_ptr_array_insert(list->cache, i, NULL);
                g_list_model_items_changed(G_LIST_MODEL(list), i, 0, 1);
            }
            list->size++;
        }
    }
    else if (strcmp(change, "delete") == 0)
    {
        int64_t i = --list->size - index;

        if (i >= 0 && i < list->cache->len)
            g_ptr_array_remove_index(list->cache, i);
        g_list_model_items_changed(G_LIST_MODEL(list), i, 1, 0);
    }
    else if (strcmp(change, "update") == 0)
    {
        // Refresh entry, if it is loaded.
        if (index < list->cache->len)
        {
            ClipboardEntry *entry = list->cache->pdata[index];

            if (entry != NULL)
                clipboard_entry_refresh(entry, index, NULL);
        }
    }
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
    ClipboardEntry **arr = (ClipboardEntry **)list->cache->pdata;

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
        g_ptr_array_insert(list->cache, pos, entry);
    }

    return g_object_ref(entry);
}
