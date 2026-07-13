#include "wlipdaemon.h"
#include <gio/gio.h>
#include <glib.h>
#include <json-glib/json-glib.h>

G_DEFINE_ENUM_TYPE(
    WlipContent,
    wlip_content,
    G_DEFINE_ENUM_VALUE(WLIP_CONTENT_IMAGE, "image"),
    G_DEFINE_ENUM_VALUE(WLIP_CONTENT_TEXT, "text"),
    G_DEFINE_ENUM_VALUE(WLIP_CONTENT_BINARY, "binary"),
    G_DEFINE_ENUM_VALUE(WLIP_CONTENT_UNKNOWN, "unknown")
)

struct _WlipEntry
{
    GObject parent;

    int64_t id; // -1 if entry is not loaded

    int64_t creation_time;
    int64_t update_time;

    gboolean starred;
    gboolean current;

    // Content that represents this clipboard entry.
    WlipContent content;
    GBytes     *content_data; // NULL if binary or unknown
    WlipContent pending_content;

    // Maps mime type to GBytes object (or NULL if not loaded).
    GHashTable *mime_types;
};

G_DEFINE_TYPE(WlipEntry, wlip_entry, G_TYPE_OBJECT)

typedef enum
{
    ENTRY_PROP_CREATION_TIME = 1,
    ENTRY_PROP_UPDATE_TIME,
    ENTRY_PROP_STARRED,
    ENTRY_PROP_CURRENT,
    ENTRY_PROP_CONTENT,
    N_ENTRY_PROPS
} WlipEntryProperty;

static GParamSpec *entry_props[N_ENTRY_PROPS] = {NULL};

typedef enum
{
    ENTRY_SIGNAL_READY,
    N_ENTRY_SIGNALS
} WlipEntrySignal;

static guint entry_signals[N_ENTRY_SIGNALS] = {0};

static const char *content_map[] = {
    [WLIP_CONTENT_IMAGE] = "image/*",
    [WLIP_CONTENT_TEXT] = "text/*",
    [WLIP_CONTENT_BINARY] = "*"
};

static void
wlip_entry_finalize(GObject *obj)
{
    WlipEntry *self = WLIP_ENTRY(obj);

    g_hash_table_unref(self->mime_types);
    g_bytes_unref(self->content_data);

    G_OBJECT_CLASS(wlip_entry_parent_class)->finalize(obj);
}

static void
wlip_entry_class_init(WlipEntryClass *class)
{
    GObjectClass *obj_class = G_OBJECT_CLASS(class);

    obj_class->finalize = wlip_entry_finalize;

    entry_props[ENTRY_PROP_CREATION_TIME] = g_param_spec_int64(
        "creation-time",
        NULL,
        NULL,
        0,
        G_MAXINT64,
        0,
        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS
    );
    entry_props[ENTRY_PROP_UPDATE_TIME] = g_param_spec_int64(
        "update-time",
        NULL,
        NULL,
        0,
        G_MAXINT64,
        0,
        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS
    );
    entry_props[ENTRY_PROP_STARRED] = g_param_spec_boolean(
        "starred", NULL, NULL, FALSE, G_PARAM_READABLE | G_PARAM_STATIC_STRINGS
    );
    entry_props[ENTRY_PROP_CURRENT] = g_param_spec_boolean(
        "current", NULL, NULL, FALSE, G_PARAM_READABLE | G_PARAM_STATIC_STRINGS
    );
    entry_props[ENTRY_PROP_CONTENT] = g_param_spec_enum(
        "current",
        NULL,
        NULL,
        WLIP_TYPE_CONTENT,
        WLIP_CONTENT_UNKNOWN,
        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS
    );

    entry_signals[ENTRY_SIGNAL_READY] = g_signal_new(
        "ready",
        G_TYPE_FROM_CLASS(class),
        G_SIGNAL_NO_RECURSE | G_SIGNAL_NO_HOOKS,
        0,
        NULL,
        NULL,
        NULL,
        G_TYPE_NONE,
        0
    );
}

static void
wlip_entry_init(WlipEntry *self)
{
    self->id = -1;
    self->content = WLIP_CONTENT_UNKNOWN;
    self->mime_types = g_hash_table_new_full(
        g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_bytes_unref
    );
}

static WlipEntry *
wlip_entry_new(void)
{
    return g_object_new(WLIP_TYPE_ENTRY, NULL);
}

#define REQUEST_LISTEN_EVENT_STREAM "listen_event_stream"
#define REQUEST_GET_ENTRY "get_entry"
#define REQUEST_LOAD_MIMETYPE_DATA "load_mimetype_data"
#define REQUEST_GET_HISTORY_SIZE "get_history_size"

#define EVENT_ENTRY_ADDED "entry_added"
#define EVENT_ENTRY_DELETED "entry_deleted"
#define EVENT_CURRENT_STATE_UPDATED "current_state_updated"
#define EVENT_ENTRY_UPDATED "entry_updated"

/*
 * Object that represents the connection to the wlip daemon. IPC stuff runs on a
 * separate thread.
 */
struct _WlipDaemon
{
    GObject parent;

    char *socket_path;

    guint serial;

    // Used to wakeup IPC thread when reading or writing. Accessed by main
    // thread and worker thread.
    GCancellable *cancel;

    GThread *ipc_thread;

    // Maps serial to GTask
    GHashTable *pending;

    // Queue of GBytes to write
    GAsyncQueue *write_queue;

    // Queue of JsonNode objects
    GAsyncQueue *event_queue;
    guint        event_idle;

    // If > 0, then exit IPC thread
    int stop;

    guint n_entries;
    // Maps entry ID to WlipEntry object. Note that a weak reference is held on
    // the object. Modified and accessed only by main thread.
    GHashTable *entries;
};

// clang-format off
static void *wlip_daemon_thread_cb(WlipDaemon *self);
// clang-format on

G_DEFINE_TYPE(WlipDaemon, wlip_daemon, G_TYPE_OBJECT)

typedef enum
{
    DAEMON_SIGNAL_READY,  // When daemon is ready to be used
    DAEMON_SIGNAL_ADD,    // "add" event
    DAEMON_SIGNAL_DELETE, // "delete" event, has one argument which is the
                          // position that was deleted.
    N_DAEMON_SIGNALS
} WlipDaemonSignal;

static guint daemon_signals[N_DAEMON_SIGNALS] = {0};

static void
wlip_daemon_finalize(GObject *obj)
{
    WlipDaemon *self = WLIP_DAEMON(obj);

    g_free(self->socket_path);
    g_hash_table_unref(self->pending);
    g_async_queue_unref(self->write_queue);
    g_async_queue_unref(self->event_queue);
    g_hash_table_unref(self->entries);

    G_OBJECT_CLASS(wlip_daemon_parent_class)->finalize(obj);
}

static void
wlip_daemon_dispose(GObject *obj)
{
    WlipDaemon *self = WLIP_DAEMON(obj);

    // Stop the IPC thread
    if (self->ipc_thread != NULL)
    {
        g_atomic_int_inc(&self->stop);
        g_cancellable_cancel(self->cancel);
        (void)g_thread_join(self->ipc_thread);
        self->ipc_thread = NULL;
    }

    g_clear_object(&self->cancel);

    G_OBJECT_CLASS(wlip_daemon_parent_class)->dispose(obj);
}

static void
wlip_daemon_class_init(WlipDaemonClass *class)
{
    GObjectClass *obj_class = G_OBJECT_CLASS(class);

    obj_class->finalize = wlip_daemon_finalize;
    obj_class->dispose = wlip_daemon_dispose;

    daemon_signals[DAEMON_SIGNAL_READY] = g_signal_new(
        "ready",
        G_TYPE_FROM_CLASS(class),
        G_SIGNAL_NO_RECURSE | G_SIGNAL_NO_HOOKS,
        0,
        NULL,
        NULL,
        NULL,
        G_TYPE_NONE,
        0
    );
    daemon_signals[DAEMON_SIGNAL_ADD] = g_signal_new(
        "add",
        G_TYPE_FROM_CLASS(class),
        G_SIGNAL_NO_RECURSE | G_SIGNAL_NO_HOOKS,
        0,
        NULL,
        NULL,
        NULL,
        G_TYPE_NONE,
        0
    );
    daemon_signals[DAEMON_SIGNAL_DELETE] = g_signal_new(
        "delete",
        G_TYPE_FROM_CLASS(class),
        G_SIGNAL_NO_RECURSE | G_SIGNAL_NO_HOOKS,
        0,
        NULL,
        NULL,
        NULL,
        G_TYPE_NONE,
        1,
        G_TYPE_UINT
    );
}

static void
wlip_daemon_init(WlipDaemon *self)
{
    self->cancel = g_cancellable_new();

    self->pending =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

    self->write_queue = g_async_queue_new_full((GDestroyNotify)g_bytes_unref);
    self->event_queue = g_async_queue_new_full((GDestroyNotify)json_node_unref);

    self->entries =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
}

/*
 * Start a connection to the daemon. This will return immediately. If
 * "socket_path" is NULL, then get the socket path using the $WAYLAND_DISPLAY
 * env var. Returns NULL on failure.
 */
WlipDaemon *
wlip_daemon_new(const char *socket_path, GError **error)
{
    g_assert(error == NULL || *error == NULL);

    WlipDaemon *daemon = g_object_new(WLIP_TYPE_DAEMON, NULL);

    if (socket_path == NULL)
    {
        const char *display = g_getenv("WAYLAND_DISPLAY");

        if (display == NULL)
        {
            g_set_error_literal(
                error,
                G_IO_ERROR,
                G_IO_ERROR_CONNECTION_REFUSED,
                "$WAYLAND_DISPLAY not set in environment"
            );
            g_object_unref(daemon);
            return NULL;
        }
        daemon->socket_path =
            g_build_filename(g_get_user_runtime_dir(), "wlip", display, NULL);
    }
    else
        daemon->socket_path = g_strdup(socket_path);

    daemon->ipc_thread =
        g_thread_new("IPC worker", (GThreadFunc)wlip_daemon_thread_cb, daemon);

    return daemon;
}

/*
 * Return number of entries in history. If daemon is not ready yet, then zero is
 * returned.
 */
guint
wlip_daemon_get_history_size(WlipDaemon *self)
{
    g_assert(WLIP_IS_DAEMON(self));

    return self->n_entries;
}

/*
 * Generic function to send a request to the daemon, creating a new GTask. The
 * variadic arguments are in the format of <member name>, <value>. "fmt" is a
 * string of types that each <value> represents:
 *
 * "s": const char * (note that no escaping is done for the JSON string!!)
 * "i": int64_t
 * "b": gboolean
 *
 * If "fmt" is NULL, then no arguments are expected.
 */
static void
wlip_daemon_send_request_async(
    WlipDaemon         *self,
    const char         *type,
    const char         *fmt,
    GAsyncReadyCallback callback,
    void               *udata,
    ...
)
{
    guint    serial = self->serial++;
    GString *msg = g_string_new(NULL);

    g_string_append_printf(msg, "{\"type\":\"%s\",\"serial\":%u", type, serial);

    if (fmt != NULL)
    {
        va_list ap;

        va_start(ap, udata);
        for (const char *c = fmt; *c != 0; c++)
        {
            const char *name = va_arg(ap, const char *);

            g_string_append_printf(msg, ",\"%s\":", name);
            switch (*c)
            {
            case 's':
                g_string_append_printf(msg, "\"%s\"", va_arg(ap, const char *));
                break;
            case 'i':
                g_string_append_printf(
                    msg, "%" G_GINT64_FORMAT, va_arg(ap, int64_t)
                );
                break;
            case 'b':
                g_string_append_printf(
                    msg, "%s", va_arg(ap, int) ? "true" : "false"
                );
                break;
            default:
                g_assert_not_reached();
            }
        }
        va_end(ap);
    }
    g_string_append(msg, "}\n");

    GBytes *bytes = g_string_free_to_bytes(msg);
    GTask  *task = g_task_new(self, NULL, callback, udata);

    g_task_set_source_tag(task, wlip_daemon_send_request_async);
    g_task_set_priority(task, G_PRIORITY_LOW);

    g_hash_table_insert(self->pending, GUINT_TO_POINTER(serial), task);
    g_async_queue_push(self->write_queue, bytes);
    g_cancellable_cancel(self->cancel);
}

static JsonObject *
wlip_daemon_send_request_finish(
    WlipDaemon *self, GAsyncResult *result, GError **error
)
{
    g_assert(WLIP_IS_DAEMON(self));
    g_assert(G_IS_TASK(result));
    g_assert(error == NULL || *error == NULL);

    g_autoptr(JsonNode) node = g_task_propagate_pointer(G_TASK(result), error);

    if (node == NULL)
        return NULL;

    return json_object_ref(json_node_get_object(node));
}

static void
entry_weak_cb(WlipDaemon *daemon, WlipEntry *entry)
{
    WlipEntry *existing = g_hash_table_lookup(daemon->entries, &entry->id);

    // May happen if entry is still referenced after being removed from table.
    if (existing == entry)
        g_hash_table_remove(daemon->entries, &entry->id);
    g_object_unref(daemon);
}

static void
mimetype_cb(WlipDaemon *daemon, GAsyncResult *result, GWeakRef *ref)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(JsonObject) resp =
        wlip_daemon_send_request_finish(daemon, result, &error);
    g_autoptr(WlipEntry) entry = g_weak_ref_get(ref);

    g_weak_ref_clear(ref);
    g_free(ref);

    if (resp == NULL)
    {
        g_warning("Error loading mime type: %s", error->message);
        return;
    }
    if (entry == NULL)
        return;

    const char *b64 =
        json_object_get_string_member_with_default(resp, "data", "");

    size_t   datasz;
    uint8_t *data = g_base64_decode(b64, &datasz);
    GBytes  *bytes = g_bytes_new_take(data, datasz);

    entry->content = entry->pending_content;
    entry->content_data = bytes;

    g_object_notify_by_pspec(G_OBJECT(entry), entry_props[ENTRY_PROP_CONTENT]);
}

static void
entry_cb(WlipDaemon *daemon, GAsyncResult *result, GWeakRef *ref)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(JsonObject) resp =
        wlip_daemon_send_request_finish(daemon, result, &error);
    g_autoptr(WlipEntry) entry = g_weak_ref_get(ref);
    gboolean need_ref = FALSE;

    if (resp == NULL)
    {
        g_warning("Error loading entry: %s", error->message);
        goto exit;
    }
    if (entry == NULL)
        goto exit;

    entry->id = json_object_get_int_member_with_default(resp, "id", -1);
    if (entry->id == -1)
        goto exit;
    entry->creation_time =
        json_object_get_int_member_with_default(resp, "creation_time", -1);
    if (entry->creation_time == -1)
        goto exit;
    entry->update_time =
        json_object_get_int_member_with_default(resp, "update_time", -1);
    if (entry->update_time == -1)
        goto exit;

    entry->starred =
        json_object_get_boolean_member_with_default(resp, "starred", FALSE);
    entry->current =
        json_object_get_boolean_member_with_default(resp, "current", FALSE);

    if (json_object_has_member(resp, "mime_types") &&
        JSON_NODE_HOLDS_ARRAY(json_object_get_member(resp, "mime_types")))
    {
        JsonArray *mime_types =
            json_object_get_array_member(resp, "mime_types");
        WlipContent content = WLIP_CONTENT_BINARY;
        const char *content_mime_type = NULL;

        // Add mime types to table. Also find the representing content, and send
        // a request to load the data for it. Only emit the notify signal for
        // "content" property when we receive the content data.
        for (guint i = 0; i < json_array_get_length(mime_types); i++)
        {
            const char *mime_type =
                json_array_get_string_element(mime_types, i);

            if (mime_type == NULL)
                continue;

            g_hash_table_insert(entry->mime_types, g_strdup(mime_type), NULL);

            for (WlipContent t = 0; t < content; t++)
                if (g_content_type_is_a(mime_type, content_map[t]))
                {
                    content = t;
                    content_mime_type = mime_type;
                    break;
                }
        }

        if (content == WLIP_CONTENT_BINARY)
        {
            entry->content = WLIP_CONTENT_BINARY;
            g_object_notify_by_pspec(
                G_OBJECT(entry), entry_props[ENTRY_PROP_CONTENT]
            );
        }
        else
        {
            g_assert(content_mime_type != NULL);
            entry->pending_content = content;
            need_ref = TRUE;
            wlip_daemon_send_request_async(
                daemon,
                REQUEST_LOAD_MIMETYPE_DATA,
                "is",
                (GAsyncReadyCallback)mimetype_cb,
                ref,
                "id",
                entry->id,
                "mime_type",
                content_mime_type
            );
        }
    }

    int64_t *idvar = g_new(int64_t, 1);

    *idvar = entry->id;

    g_object_weak_ref(
        G_OBJECT(entry), (GWeakNotify)entry_weak_cb, g_object_ref(daemon)
    );
    g_hash_table_insert(daemon->entries, idvar, entry);

    for (int i = ENTRY_PROP_CREATION_TIME; i < ENTRY_PROP_CONTENT; i++)
        g_object_notify_by_pspec(G_OBJECT(entry), entry_props[i]);

    g_signal_emit(entry, entry_signals[ENTRY_SIGNAL_READY], 0);
exit:
    if (!need_ref)
    {
        g_weak_ref_clear(ref);
        g_free(ref);
    }
}

/*
 * Return an entry at the given position, that is initially unloaded.
 */
WlipEntry *
wlip_daemon_get_entry(WlipDaemon *self, guint pos)
{
    g_assert(WLIP_IS_DAEMON(self));

    WlipEntry *entry = wlip_entry_new();
    GWeakRef  *ref = g_new(GWeakRef, 1);

    // Use a weak ref in case entry is disposed
    g_weak_ref_init(ref, entry);
    wlip_daemon_send_request_async(
        self,
        REQUEST_GET_ENTRY,
        "i",
        (GAsyncReadyCallback)entry_cb,
        ref,
        "pos",
        pos
    );

    return entry;
}

static void
wlip_daemon_process_event(WlipDaemon *self, JsonObject *event)
{
    const char *eventtype =
        json_object_get_string_member_with_default(event, "event", NULL);

    if (eventtype == NULL)
        return;

    if (strcmp(eventtype, EVENT_ENTRY_ADDED) == 0)
    {
        g_signal_emit(self, daemon_signals[DAEMON_SIGNAL_ADD], 0);
    }
    else if (strcmp(eventtype, EVENT_ENTRY_DELETED) == 0)
    {
        int64_t id = json_object_get_int_member_with_default(event, "id", 0);
        guint   pos = json_object_get_int_member_with_default(event, "pos", 0);

        g_hash_table_remove(self->entries, &id);
        g_signal_emit(self, daemon_signals[DAEMON_SIGNAL_DELETE], 0, pos);
    }
    else if (strcmp(eventtype, EVENT_CURRENT_STATE_UPDATED) == 0)
    {
    }
    else if (strcmp(eventtype, EVENT_ENTRY_UPDATED) == 0)
    {
    }
}

static gboolean
process_events_cb(WlipDaemon *daemon)
{
    while (TRUE)
    {
        g_autoptr(JsonNode) node = g_async_queue_try_pop(daemon->event_queue);

        if (node == NULL)
            break;

        wlip_daemon_process_event(daemon, json_node_get_object(node));
    }

    daemon->event_idle = 0;
    g_object_unref(daemon);
    return G_SOURCE_REMOVE;
}

/*
 * Handle an IPC message from the daemon. Takes ownership of "node" (which
 * should always be a JSON object and not be referenced anywhere else other than
 * the caller once).
 */
static void
wlip_daemon_handle_message(WlipDaemon *self, JsonNode *node)
{
    JsonObject *msg = json_node_get_object(node);
    const char *type;

    type = json_object_get_string_member_with_default(msg, "type", NULL);
    if (type == NULL)
        goto fail;

    if (strcmp(type, "event") == 0)
    {
        g_async_queue_push(self->event_queue, node);
        if (self->event_idle == 0)
            g_idle_add((GSourceFunc)process_events_cb, g_object_ref(self));
        return;
    }

    guint serial = json_object_get_int_member_with_default(msg, "serial", 0);

    GTask *task = g_hash_table_lookup(self->pending, GUINT_TO_POINTER(serial));

    g_hash_table_steal(self->pending, GUINT_TO_POINTER(serial));

    if (task == NULL)
    {
        g_warning("Unknown response with serial %u", serial);
        goto fail;
    }

    // We have to to transfer full ownership of the JSON node, because JsonNode
    // is not thread safe (including reference counting).
    if (strcmp(type, "response") == 0)
    {
        g_task_return_pointer(task, node, (GDestroyNotify)json_node_unref);
    }
    else if (strcmp(type, "error") == 0)
    {
        const char *desc = json_object_get_string_member_with_default(
            msg, "desc", "(unknown)"
        );

        g_task_return_new_error(
            task, G_IO_ERROR, G_IO_ERROR_FAILED_HANDLED, "%s", desc
        );
    }
    else
        g_task_return_new_error(
            task,
            G_IO_ERROR,
            G_IO_ERROR_UNKNOWN,
            "Unknown message type \"%s\"",
            type
        );

    g_object_unref(task);

    return;
fail:
    json_node_unref(node);
}

static void
history_size_cb(
    WlipDaemon *daemon, GAsyncResult *result, void *udata G_GNUC_UNUSED
)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(JsonObject) resp =
        wlip_daemon_send_request_finish(daemon, result, &error);

    if (resp == NULL)
    {
        g_warning("Error getting history size: %s", error->message);
        return;
    }

    int64_t size = json_object_get_int_member_with_default(resp, "size", -1);

    size = MIN(size, G_MAXUINT);

    if (size >= 0)
    {
        // Start receiving events
        wlip_daemon_send_request_async(
            daemon, REQUEST_LISTEN_EVENT_STREAM, "b", NULL, NULL, "enable", TRUE
        );

        daemon->n_entries = (guint)size;

        g_signal_emit(daemon, daemon_signals[DAEMON_SIGNAL_READY], 0);
    }
}

static void *
wlip_daemon_thread_cb(WlipDaemon *self)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GSocketClient) client = g_socket_client_new();
    g_autoptr(GSocketAddress) addr =
        g_unix_socket_address_new(self->socket_path);
    g_autoptr(GSocketConnection) ct = g_socket_client_connect(
        client, G_SOCKET_CONNECTABLE(addr), NULL, &error
    );

    if (ct == NULL)
    {
        g_critical("Error connecting to daemon: %s", error->message);
        g_object_unref(self);
        return NULL;
    }

    g_autoptr(GDataInputStream) in_stream = NULL;
    GOutputStream *out_stream;

    in_stream =
        g_data_input_stream_new(g_io_stream_get_input_stream(G_IO_STREAM(ct)));
    out_stream = g_io_stream_get_output_stream(G_IO_STREAM(ct));

    g_data_input_stream_set_byte_order(
        in_stream, G_DATA_STREAM_BYTE_ORDER_HOST_ENDIAN
    );
    g_data_input_stream_set_newline_type(
        in_stream, G_DATA_STREAM_NEWLINE_TYPE_LF
    );

    // Get initial history size, when that is received, then the daemon object
    // is considered ready.
    wlip_daemon_send_request_async(
        self,
        REQUEST_GET_HISTORY_SIZE,
        NULL,
        (GAsyncReadyCallback)history_size_cb,
        NULL
    );

    g_autoptr(JsonParser) parser = json_parser_new_immutable();

    // Main blocking object is the input stream. When the write buffer is
    // updated, the GCancellable is cancelled, making the input stream read
    // stop.
    while (TRUE)
    {
        if (g_atomic_int_get(&self->stop) > 0)
            break;

        while (TRUE)
        {
            g_autoptr(GBytes) bytes = g_async_queue_try_pop(self->write_queue);

            if (bytes == NULL)
                break;

            gboolean       ret;
            size_t         sz;
            const uint8_t *data = g_bytes_get_data(bytes, &sz);

            ret = g_output_stream_write_all(
                out_stream, data, sz, NULL, self->cancel, NULL
            );

            if (!ret)
            {
                g_cancellable_reset(self->cancel);
                continue;
            }
        }

        size_t len;

        while (TRUE)
        {
            g_autofree char *str = g_data_input_stream_read_line_utf8(
                in_stream, &len, self->cancel, NULL
            );

            if (str == NULL)
            {
                g_cancellable_reset(self->cancel);
                break;
            }

            // Ignore message if larger than 16 MB
            if (len > 16000000)
                continue;

            if (json_parser_load_from_data(parser, str, len, NULL))
            {
                JsonNode *msg = json_parser_steal_root(parser);

                if (JSON_NODE_HOLDS_OBJECT(msg))
                    wlip_daemon_handle_message(self, msg);
                else
                    json_node_unref(msg);
            }
        }
    }

    return NULL;
}
