#include "wlipdaemon.h"
#include <gio/gio.h>
#include <glib.h>
#include <json-glib/json-glib.h>

/*
 * Object that represents the connection to the wlip daemon. IPC stuff runs on a
 * separate thread.
 */
struct _WlipDaemon
{
    GObject parent;

    char         *socket_path;
    GCancellable *cancel; // Used to stop IPC thread
    GThread      *ipc_thread;

    GAsyncQueue *write_queue; // Queue of GBytes to send

    // Table of pending requests that have been sent. Maps request serial to the
    // GTask object.
    GHashTable *pending;
    int64_t     serial_gen;

    // Used to signal write thread to stop
    GBytes *sentinel;
};

// clang-format off
static void *wlip_daemon_thread_cb(WlipDaemon *self);
// clang-format on

G_DEFINE_TYPE(WlipDaemon, wlip_daemon, G_TYPE_OBJECT)

typedef enum
{
    SIGNAL_EVENT,
    N_SIGNALS
} WlipDaemonSignals;

static guint SIGNALS[N_SIGNALS] = {0};

static const char *REQUEST_NAMES[N_WLIP_DAEMON_REQUESTS] = {
    [WLIP_DAEMON_REQUEST_ENTRY] = "entry",
    [WLIP_DAEMON_REQUEST_SUBSCRIBE] = "subscribe",
    [WLIP_DAEMON_REQUEST_HISTORY_SIZE] = "history_size"
};

static void
wlip_daemon_finalize(GObject *obj)
{
    WlipDaemon *self = WLIP_DAEMON(obj);

    g_free(self->socket_path);
    g_async_queue_unref(self->write_queue);
    g_hash_table_unref(self->pending);
    g_bytes_unref(self->sentinel);

    G_OBJECT_CLASS(wlip_daemon_parent_class)->finalize(obj);
}

static void
wlip_daemon_dispose(GObject *obj)
{
    WlipDaemon *self = WLIP_DAEMON(obj);

    wlip_daemon_stop(self);
    g_clear_object(&self->cancel);

    G_OBJECT_CLASS(wlip_daemon_parent_class)->dispose(obj);
}

static void
wlip_daemon_class_init(WlipDaemonClass *class)
{
    GObjectClass *obj_class = G_OBJECT_CLASS(class);

    obj_class->finalize = wlip_daemon_finalize;
    obj_class->dispose = wlip_daemon_dispose;

    SIGNALS[SIGNAL_EVENT] = g_signal_new(
        "event",
        G_TYPE_FROM_CLASS(class),
        G_SIGNAL_NO_RECURSE | G_SIGNAL_NO_HOOKS,
        0,
        NULL,
        NULL,
        NULL,
        G_TYPE_NONE,
        1,
        JSON_TYPE_OBJECT
    );
}

static void
wlip_daemon_init(WlipDaemon *self)
{
    self->cancel = g_cancellable_new();
    self->pending = g_hash_table_new_full(
        g_int64_hash, g_int64_equal, g_free, g_object_unref
    );
    self->write_queue = g_async_queue_new_full((GDestroyNotify)g_bytes_unref);

    char c = 1;
    self->sentinel = g_bytes_new(&c, sizeof(c));
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
 * Stop the IPC thread for this object. Should always be called before the
 * object is not needed anymore (or else object will leak).
 */
void
wlip_daemon_stop(WlipDaemon *self)
{
    if (self->ipc_thread == NULL)
        return;

    if (self->cancel != NULL)
        g_cancellable_cancel(self->cancel);

    g_debug("Closing IPC connection");
    g_thread_join(self->ipc_thread);
    self->ipc_thread = NULL;
}

/*
 * Send a request to the daemon asynchronously. The variadic arguments depend on
 * "req":
 *
 * WLIP_DAEMON_REQUEST_ENTRY: "int64_t index, int64_t id"
 * If "index" is -1, then "id" is used, otherwise "id" is ignored (and is not
 * required).
 *
 * WLIP_DAEMON_REQUEST_SUBSCRIBE: "const char * event, ..., NULL"
 *
 * WLIP_DAEMON_REQUEST_HISTORY_SIZE: no args
 */
void
wlip_daemon_request_async(
    WlipDaemon         *self,
    WlipDaemonRequest   req,
    int                 io_priority,
    GCancellable       *cancellable,
    GAsyncReadyCallback callback,
    void               *udata,
    ...
)
{
    g_assert(WLIP_IS_DAEMON(self));
    g_assert(cancellable == NULL || G_IS_CANCELLABLE(cancellable));

    int64_t  serial = self->serial_gen++;
    GString *str = g_string_new(NULL);
    va_list  ap;

    g_string_append_printf(
        str,
        "{\"type\":\"%s\",\"serial\":%" G_GINT64_FORMAT,
        REQUEST_NAMES[req],
        serial
    );

    va_start(ap, udata);

    switch (req)
    {
    case WLIP_DAEMON_REQUEST_ENTRY:
    {
        int64_t index = va_arg(ap, int64_t);

        if (index == -1)
            g_string_append_printf(
                str, ",\"id\":%" G_GINT64_FORMAT, va_arg(ap, int64_t)
            );
        else
            g_string_append_printf(str, ",\"index\":%" G_GINT64_FORMAT, index);
        break;
    }
    case WLIP_DAEMON_REQUEST_SUBSCRIBE:
    {
        gboolean first = TRUE;

        g_string_append_printf(str, ",\"events\":[");
        while (TRUE)
        {
            const char *event = va_arg(ap, const char *);

            if (event == NULL)
                break;
            if (!first)
                g_string_append_c(str, ',');

            g_string_append_printf(str, "\"%s\"", event);
            first = FALSE;
        }
        g_string_append_printf(str, "]");
        break;
    }
    case WLIP_DAEMON_REQUEST_HISTORY_SIZE:
        break;
    default:
        g_assert_not_reached();
    }

    va_end(ap);
    g_string_append(str, "}\n");
    g_async_queue_push(self->write_queue, g_string_free_to_bytes(str));

    GTask *task = g_task_new(self, cancellable, callback, udata);

    g_task_set_priority(task, io_priority);
    g_task_set_source_tag(task, wlip_daemon_request_async);

    int64_t *serial_buf = g_new(int64_t, 1);
    *serial_buf = serial;

    g_hash_table_insert(self->pending, serial_buf, task);
}

JsonObject *
wlip_daemon_request_finish(
    WlipDaemon *self, GAsyncResult *result, GError **error
)
{
    g_assert(WLIP_IS_DAEMON(self));
    g_assert(G_IS_TASK(result));
    g_assert(error == NULL || *error == NULL);
    return g_task_propagate_pointer(G_TASK(result), error);
}

typedef struct
{
    GOutputStream *stream;
    GCancellable  *cancel;
    GAsyncQueue   *queue;
    GBytes        *sentinel;
} WriteThreadData;

static void *
wlip_daemon_write_thread_cb(WriteThreadData *data)
{
    GOutputStream *stream = data->stream;
    GCancellable  *cancel = data->cancel;
    GAsyncQueue   *queue = data->queue;
    GBytes        *sentinel = data->sentinel;

    g_free(data);

    while (TRUE)
    {
        g_autoptr(GError) error = NULL;
        g_autoptr(GBytes) bytes = g_async_queue_pop(queue);

        if (bytes == sentinel)
            // Stop thread
            break;

        size_t         sz;
        const uint8_t *stuff = g_bytes_get_data(bytes, &sz);

        if (sz < G_MAXINT)
            // Don't include newline
            g_debug("Sending request to daemon: \"%.*s\"", (int)sz - 1, stuff);

        if (!g_output_stream_write_all(stream, stuff, sz, NULL, cancel, &error))
        {
            if (error->code != G_IO_ERROR_CANCELLED)
                g_critical(
                    "Error writing to daemon socket: %s", error->message
                );
            break;
        }
    }

    return NULL;
}

typedef struct
{
    WlipDaemon *daemon;
    JsonNode   *msg;
} ReadThreadData;

static void
read_thread_data_free(ReadThreadData *data)
{
    g_object_unref(data->daemon);
    json_node_unref(data->msg);
    g_free(data);
}

/*
 * Called when a message has been read from the daemon. Technically we can
 * finish the task in the worker thread instead of using an idle callback, but
 * we need an idle callback for events (to emit signals).
 */
static gboolean
wlip_daemon_received_cb(ReadThreadData *data)
{
    WlipDaemon *self = data->daemon;
    JsonNode   *msg = data->msg;
    JsonObject *obj;
    const char *type;
    int64_t     serial;

    if (!JSON_NODE_HOLDS_OBJECT(msg))
        goto exit;
    obj = json_node_get_object(msg);

    type = json_object_get_string_member_with_default(obj, "type", NULL);
    if (type == NULL)
        goto exit;

    if (strcmp(type, "event") == 0)
    {
        g_signal_emit(self, SIGNALS[SIGNAL_EVENT], 0, obj);
        goto exit;
    }

    serial = json_object_get_int_member_with_default(obj, "serial", -1);
    if (serial == -1)
        goto exit;

    // Find GTask and finish it
    int64_t *serial_buf = NULL;
    GTask   *task = NULL;

    g_hash_table_steal_extended(
        self->pending, &serial, (void **)&serial_buf, (void **)&task
    );
    g_free(serial_buf);

    if (task == NULL)
    {
        g_warning(
            "Pending message with serial %" G_GINT64_FORMAT " does not exist",
            serial
        );
        goto exit;
    }

    if (g_task_return_error_if_cancelled(task))
    {
    }
    else if (strcmp(type, "response") == 0 || strcmp(type, "success") == 0)
    {
        g_task_return_pointer(
            task, json_object_ref(obj), (GDestroyNotify)json_object_unref
        );
    }
    else if (strcmp(type, "error") == 0)
    {
        const char *err = json_object_get_string_member_with_default(
            obj, "desc", "(Unknown)"
        );
        g_task_return_new_error(
            task, G_IO_ERROR, G_IO_ERROR_FAILED_HANDLED, "%s", err
        );
    }
    else
        g_task_return_new_error_literal(
            task, G_IO_ERROR, G_IO_ERROR_UNKNOWN, "Unknown message type"
        );

    g_object_unref(task);

exit:
    // GSource destroy func will free "data"
    return G_SOURCE_REMOVE;
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

    WriteThreadData *write_data = g_new(WriteThreadData, 1);

    write_data->stream = g_io_stream_get_output_stream(G_IO_STREAM(ct));
    write_data->cancel = self->cancel;
    write_data->queue = self->write_queue;
    write_data->sentinel = self->sentinel;

    // Start write thread
    GThread *write_thread = g_thread_new(
        "IPC write worker", (GThreadFunc)wlip_daemon_write_thread_cb, write_data
    );

    // Synchronously read from the input socket
    g_autoptr(JsonParser) parser = json_parser_new_immutable();
    g_autoptr(GByteArray) arr = g_byte_array_new();

    GInputStream *stream = g_io_stream_get_input_stream(G_IO_STREAM(ct));
    uint8_t       buf[4096];

    while (TRUE)
    {
        ssize_t r =
            g_input_stream_read(stream, buf, sizeof(buf), self->cancel, &error);

        if (r == -1)
        {
            if (error->code != G_IO_ERROR_CANCELLED)
                g_critical("Error reading daemon socket: %s", error->message);
            break;
        }
        else if (r == 0)
            // EOF, just stop the loop
            break;

        // Check if there is a newline in "buf", if there is, then calculate the
        // offset of the newline + the current length of the array to get the
        // total length to parse. Do this until there are no more newlines
        // found.
        const uint8_t *ptr = buf;

        while (TRUE)
        {
            const uint8_t *nl = memchr(ptr, '\n', r);

            if (nl == NULL)
                // Wait for more data
                break;

            size_t off = nl - ptr;
            size_t total_len = (size_t)arr->len + off;

            g_byte_array_append(arr, ptr, off);

            if (total_len < G_MAXINT)
                g_debug(
                    "Received message: \"%.*s\"", (int)total_len, arr->data
                );

            // If an error occurs parsing, then just ignore the parsed data.
            if (json_parser_load_from_data(
                    parser, (char *)arr->data, total_len, &error
                ))
            {
                ReadThreadData *data = g_new(ReadThreadData, 1);

                data->daemon = g_object_ref(self);
                data->msg = json_parser_steal_root(parser);

                g_main_context_invoke_full(
                    NULL,
                    G_PRIORITY_LOW,
                    (GSourceFunc)wlip_daemon_received_cb,
                    data,
                    (GDestroyNotify)read_thread_data_free
                );
            }
            g_clear_error(&error);

            g_byte_array_set_size(arr, 0);
            ptr = nl + 1;
            r -= off + 1;
        }

        // Append rest into buffer
        if (r > 0)
        {
            // If array size is over 64 MiB, abandon everything
            if (arr->len + r > 64 * 1024 * 1024)
            {
                g_warning("Read buffer has grown too large!");
                g_byte_array_set_size(arr, 0);
            }
            else
                g_byte_array_append(arr, ptr, r);
        }
    }

    g_async_queue_push(self->write_queue, g_bytes_ref(self->sentinel));
    g_thread_join(write_thread);
    return NULL;
}
