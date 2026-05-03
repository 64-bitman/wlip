#include "clipboard-entry.h"
#include "ipc-handle.h"
#include "ipc_client.h"
#include "log.h"
#include <glib-object.h>
#include <glib.h>
#include <stdbool.h>
#include <stdio.h>

struct _ClipboardEntry
{
    GObject parent;

    int64_t id;

    int64_t creation_time;
    int64_t update_time;
    bool    starred;

    // Map of mime type (string) to GBytes containg the data. Note that value
    // may be NULL, if mime type data is not loaded.
    GHashTable *mime_types;
    const char *display_mime_type; // Mime type that should be displayed to the
                                   // user. NULL if there are none (binary data)

    // If false, then entry has not beem loaded yet, still waiting for a
    // response.
    bool       loaded;
    IPCHandle *ipc_handle;
};

G_DEFINE_TYPE(ClipboardEntry, clipboard_entry, G_TYPE_OBJECT)

typedef enum
{
    SIGNAL_REFRESH,
    N_SIGNALS
} ClipboardEntrySignal;

static uint obj_signals[N_SIGNALS] = {0};

static void
clipboard_entry_finalize(GObject *object)
{
    ClipboardEntry *entry = CLIPBOARD_ENTRY(object);

    g_hash_table_unref(entry->mime_types);

    G_OBJECT_CLASS(clipboard_entry_parent_class)->finalize(object);
}

static void
clipboard_entry_class_init(ClipboardEntryClass *class)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS(class);

    gobject_class->finalize = clipboard_entry_finalize;

    obj_signals[SIGNAL_REFRESH] = g_signal_new(
        "refresh",
        G_TYPE_FROM_CLASS(class),
        G_SIGNAL_NO_HOOKS | G_SIGNAL_NO_RECURSE,
        0,
        NULL,
        NULL,
        NULL,
        G_TYPE_NONE,
        0
    );
}

static void
clipboard_entry_init(ClipboardEntry *self)
{
    self->mime_types = g_hash_table_new_full(
        g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_bytes_unref
    );
    self->loaded = false;
}

ClipboardEntry *
clipboard_entry_new(IPCHandle *ipc_handle)
{
    g_assert(IPC_IS_HANDLE(ipc_handle));

    ClipboardEntry *entry = g_object_new(CLIPBOARD_TYPE_ENTRY, NULL);

    entry->ipc_handle = ipc_handle;
    return entry;
}

static void
entry_callback(
    IPCHandle *ipc_handle, GAsyncResult *result, ClipboardEntry *entry
)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(JsonObj) resp =
        ipc_handle_request_finish(ipc_handle, result, &error);

    if (resp == NULL)
    {
        log_warn("Error refreshing entry");
        return;
    }
    if (ipc_is_error(resp))
    {
        log_warn("Error refreshing entry: %s", ipc_get_error_desc(resp));
        return;
    }

    if (get_json_integer(resp, "id", &entry->id) == FAIL)
        return;
    if (get_json_integer(resp, "creation_time", &entry->creation_time) == FAIL)
        return;
    if (get_json_integer(resp, "update_time", &entry->update_time) == FAIL)
        return;
    if (get_json_boolean(resp, "starred", &entry->starred) == FAIL)
        return;

    struct json_object *arr;

    if (!json_object_object_get_ex(resp, "mime_types", &arr))
        return;
    if (!json_object_is_type(arr, json_type_array))
        return;

    size_t len = json_object_array_length(arr);

    g_hash_table_remove_all(entry->mime_types);
    for (size_t i = 0; i < len; i++)
    {
        const char *mime_type = get_json_arr_string(arr, i);

        if (mime_type == NULL)
            continue;
        g_hash_table_insert(entry->mime_types, g_strdup(mime_type), NULL);
    }

    if (g_hash_table_contains(entry->mime_types, "image/png") == 0)
        entry->display_mime_type = "image/png";
    else if (g_hash_table_contains(entry->mime_types, "image/jpeg") == 0)
        entry->display_mime_type = "image/jpeg";
    else if (g_hash_table_contains(
                 entry->mime_types, "text/plain;charset=utf-8"
             ) == 0)
        entry->display_mime_type = "text/plain;charset=utf-8";
    else if (g_hash_table_contains(entry->mime_types, "text/plain") == 0)
        entry->display_mime_type = "text/plain;charset=utf-8";
    else
        entry->display_mime_type = NULL;

    entry->loaded = true;
    g_signal_emit(entry, obj_signals[SIGNAL_REFRESH], 0);
}

/*
 * If entry is not loaded, then retrieve info about it using the given index. If
 * entry is already loaded, then "index" is ignored, and info is refreshed from
 * the daemon. This is done asynchronously, and emits "refresh" signal when
 * entry has been refreshed.
 */
void
clipboard_entry_refresh(ClipboardEntry *self, uint index)
{
    g_assert(CLIPBOARD_IS_ENTRY(self));

    if (self->loaded)
        ipc_handle_request_async(
            self->ipc_handle,
            IPC_REQUEST_TYPE_ENTRY,
            NULL,
            (GAsyncReadyCallback)entry_callback,
            g_object_ref(self),
            -1,
            self->id
        );
    else
        ipc_handle_request_async(
            self->ipc_handle,
            IPC_REQUEST_TYPE_ENTRY,
            NULL,
            (GAsyncReadyCallback)entry_callback,
            g_object_ref(self),
            index
        );
}

struct mimetype_udata
{
    ClipboardEntry *entry;
    char            mime_type[1]; // Actually longer
};

static void
mimetype_udata_free(struct mimetype_udata *udata)
{
    g_object_unref(udata->entry);
    g_free(udata);
}

static void
mimetype_callback(IPCHandle *ipc_handle, GAsyncResult *result, GTask *task)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(JsonObj) resp =
        ipc_handle_request_finish(ipc_handle, result, &error);

    if (resp == NULL)
    {
        g_task_return_new_error_literal(
            task, G_IO_ERROR, G_IO_ERROR_FAILED, "Response is NULL"
        );
        goto exit;
    }
    if (ipc_is_error(resp))
    {
        g_task_return_new_error(
            task, G_IO_ERROR, G_IO_ERROR_FAILED, "%s", ipc_get_error_desc(resp)
        );
        goto exit;
    }

    const char *b64_data = get_json_string(resp, "data");

    if (b64_data == NULL)
        goto exit;

    size_t                 len;
    uint8_t               *data = g_base64_decode(b64_data, &len);
    GBytes                *bytes = g_bytes_new_take(data, len);
    struct mimetype_udata *udata = g_task_get_task_data(task);

    g_hash_table_replace(
        udata->entry->mime_types, g_strdup(udata->mime_type), g_bytes_ref(bytes)
    );

    g_task_return_pointer(task, bytes, (GDestroyNotify)g_bytes_unref);

exit:
    g_object_unref(task);
}

/*
 * Load the specified mime type for the given entry asynchronously. Note that
 * entry must already be loaded.
 */
void
clipboard_load_mime_type_async(
    ClipboardEntry     *self,
    const char         *mime_type,
    GCancellable       *cancellable,
    GAsyncReadyCallback callback,
    void               *udata
)
{
    g_assert(CLIPBOARD_IS_ENTRY(self));
    g_assert(mime_type != NULL);
    g_assert(cancellable == NULL || G_IS_CANCELLABLE(cancellable));

    if (!self->loaded)
    {
        log_warn("Cannot get mime type data for unloaded entry");
        return;
    }

    GTask *task = g_task_new(self, cancellable, callback, udata);
    struct mimetype_udata *tdata = g_malloc(sizeof(*tdata) + strlen(mime_type));

    tdata->entry = g_object_ref(self);
    sprintf(tdata->mime_type, "%s", mime_type);

    g_task_set_source_tag(task, clipboard_load_mime_type_async);
    g_task_set_task_data(task, tdata, (GDestroyNotify)mimetype_udata_free);

    ipc_handle_request_async(
        self->ipc_handle,
        IPC_REQUEST_TYPE_MIMETYPE,
        NULL,
        (GAsyncReadyCallback)mimetype_callback,
        task,
        self->id,
        mime_type
    );
}

GBytes *
clipboard_load_mime_type_finish(
    ClipboardEntry *self, GAsyncResult *result, GError **error
)
{
    g_assert(IPC_IS_HANDLE(self));
    g_assert(G_IS_ASYNC_RESULT(result));
    g_assert(g_async_result_is_tagged(result, clipboard_load_mime_type_async));
    g_assert(error == NULL || *error == NULL);

    return g_task_propagate_pointer(G_TASK(result), error);
}
