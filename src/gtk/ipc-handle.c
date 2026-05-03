#include "ipc-handle.h"
#include "ipc_client.h"
#include "log.h"
#include "util.h"
#include <assert.h>
#include <gio/gio.h>
#include <glib.h>
#include <json.h>
#include <poll.h>
#include <sys/eventfd.h>

struct ipc_request_data
{
    struct json_object *obj;
    request_callback    callback;
    void               *udata;
};

struct _IPCHandle
{
    GObject parent;

    GAsyncQueue *request_queue;
    GThread     *thread;

    int efd; // Used to wakeup IPC thread
    int run; // Used by main and IPC thread
};
G_DEFINE_TYPE(IPCHandle, ipc_handle, G_TYPE_OBJECT);

typedef enum
{
    SIGNAL_EVENT,
    N_SIGNALS
} IPCHandleSignal;

static uint obj_signals[N_SIGNALS] = {0};

// clang-format off
static void *ipc_handle_thread(IPCHandle *handle);
static void ipc_handle_thread_wakeup(IPCHandle *self);

static void put_json_object(struct json_object *obj);
// clang-format on

typedef struct json_object JsonObj;
#define JSON_TYPE_OBJ (json_obj_get_type())
G_DEFINE_BOXED_TYPE(JsonObj, json_obj, json_object_get, put_json_object);

static void
ipc_handle_finalize(GObject *object)
{
    IPCHandle *handle = IPC_HANDLE(object);

    g_atomic_int_set(&handle->run, 0);
    ipc_handle_thread_wakeup(handle);
    g_thread_join(handle->thread);
    g_thread_unref(handle->thread);

    g_async_queue_unref(handle->request_queue);
    close(handle->efd);

    G_OBJECT_CLASS(ipc_handle_parent_class)->finalize(object);
}

static void
ipc_handle_class_init(IPCHandleClass *class)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS(class);

    gobject_class->finalize = ipc_handle_finalize;

    obj_signals[SIGNAL_EVENT] = g_signal_new(
        "event",
        G_TYPE_FROM_CLASS(class),
        G_SIGNAL_NO_HOOKS | G_SIGNAL_NO_RECURSE | G_SIGNAL_DETAILED,
        0,
        NULL,
        NULL,
        NULL,
        G_TYPE_NONE,
        1,
        JSON_TYPE_OBJ
    );
}

static void
ipc_handle_init(IPCHandle *self)
{
    self->request_queue = g_async_queue_new_full(g_object_unref);
}

IPCHandle *
ipc_handle_new(void)
{
    IPCHandle *handle = g_object_new(IPC_TYPE_HANDLE, NULL);

    handle->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

    if (handle->efd == -1)
        log_errabort("Error creating eventfd");

    g_atomic_int_set(&handle->run, 1);
    handle->thread =
        g_thread_new("IPCHandle", (GThreadFunc)ipc_handle_thread, handle);

    return handle;
}

struct ipc_event_udata
{
    struct json_object *obj;
    IPCHandle          *handle;
};

static void
ipc_event_udata_free(struct ipc_event_udata *udata)
{
    json_object_put(udata->obj);
    g_free(udata);
}

static gboolean
ipc_event_invoke(struct ipc_event_udata *udata)
{
    const char *type = get_json_string(udata->obj, "event");
    if (type != NULL)
    {
        GQuark detail = g_quark_from_string(type);
        g_signal_emit(
            udata->handle, obj_signals[SIGNAL_EVENT], detail, udata->obj
        );
    }
    // No need to free "udata", that is handled by the source
    return G_SOURCE_REMOVE;
}

static void
ipc_event_handler(struct json_object *event, IPCHandle *handle)
{
    // Emit signal in global context, not IPC thread.
    struct ipc_event_udata *udata = g_new(struct ipc_event_udata, 1);

    udata->obj = event;
    udata->handle = handle;

    g_main_context_invoke_full(
        NULL,
        G_PRIORITY_DEFAULT,
        (GSourceFunc)ipc_event_invoke,
        udata,
        (GDestroyNotify)ipc_event_udata_free
    );
}

static void
ipc_response_handler(struct json_object *resp, GTask *task)
{
    g_task_return_pointer(task, resp, (GDestroyNotify)put_json_object);
    g_object_unref(task);
}

static void *
ipc_handle_thread(IPCHandle *handle)
{
    struct ipc_client client;

    if (ipc_client_init(&client) == FAIL)
        exit(EXIT_FAILURE);

    g_autoptr(GMainContext) context = g_main_context_new();

    g_main_context_push_thread_default(context);

    client.event_callback = (event_callback)ipc_event_handler;
    client.event_udata = handle;

    struct pollfd pfds[2];

    pfds[0].fd = client.fd;
    pfds[1].fd = handle->efd;
    pfds[1].events = POLLIN;

    while (true)
    {
        ipc_client_prepare(&client, &pfds[0]);

        int ret = poll(pfds, 2, -1);

        if (ret == -1)
        {
            if (errno == EINTR)
                continue;
            log_errerror("Error polling IPC connection");
            exit(EXIT_FAILURE);
        }

        int64_t a = 0;
        if (pfds[1].revents & POLLIN)
            read(pfds[1].fd, &a, sizeof(a));

        // Check if we have been signalled to stop
        if (g_atomic_int_get(&handle->run) == 0)
            break;

        if (pfds[0].revents != 0)
            if (ipc_client_check(&client, pfds[0].revents) == FAIL)
                exit(EXIT_FAILURE);

        // Flush any pending requests to the client
        GTask *task;

        while ((task = g_async_queue_try_pop(handle->request_queue)) != NULL)
        {
            struct json_object *obj = g_task_get_task_data(task);

            ipc_client_queue_request(
                &client,
                obj,
                (request_callback)ipc_response_handler,
                task,
                g_object_unref
            );
        }
    }

    ipc_client_uninit(&client);
    g_main_context_pop_thread_default(context);

    return NULL;
}

static void
ipc_handle_thread_wakeup(IPCHandle *self)
{
    g_assert(IPC_IS_HANDLE(self));
    int64_t x = 1;
    write(self->efd, &x, sizeof(x));
}

static void
put_json_object(struct json_object *obj)
{
    json_object_put(obj);
}

/*
 * Send a request to the daemon. The variadic arguments depend on "type":
 *
 * "entry": int64_t index
 * "mimetype": int64_t id, const char *mimetype
 * "set": int64_t id
 * "delete": int64_t id,
 * "subscribe": const char *first_event, ..., NULL
 * "history_size": void
 */
void
ipc_handle_request_async(
    IPCHandle          *self,
    IPCRequestType      type,
    GCancellable       *cancellable,
    GAsyncReadyCallback callback,
    void               *udata,
    ...
)
{
    g_assert(IPC_IS_HANDLE(self));
    g_assert(cancellable == NULL || G_IS_CANCELLABLE(cancellable));

    GTask *task = g_task_new(self, cancellable, callback, udata);

    struct json_object *req = json_object_new_object();

    if (req == NULL)
        log_errabort("Error allocating JSON object");

    va_list ap;
    va_start(ap, udata);

    switch (type)
    {
    case IPC_REQUEST_TYPE_ENTRY:
        add_json_string(req, "type", "entry", true);
        add_json_integer(req, "index", va_arg(ap, int64_t), true);
        break;
    case IPC_REQUEST_TYPE_MIMETYPE:
        add_json_string(req, "type", "mimetype", true);
        add_json_integer(req, "id", va_arg(ap, int64_t), true);
        add_json_string(req, "mimetype", va_arg(ap, const char *), true);
        break;
    case IPC_REQUEST_TYPE_SET:
        add_json_string(req, "type", "set", true);
        add_json_integer(req, "id", va_arg(ap, int64_t), true);
        break;
    case IPC_REQUEST_TYPE_DELETE:
        add_json_string(req, "type", "delete", true);
        add_json_integer(req, "id", va_arg(ap, int64_t), true);
        break;
    case IPC_REQUEST_TYPE_SUBSCRIBE:
        add_json_string(req, "type", "subscribe", true);

        struct json_object *arr = json_object_new_array();

        if (arr == NULL)
            log_errabort("Error allocating JSON array");

        while (true)
        {
            const char *event = va_arg(ap, const char *);

            if (event == NULL)
                break;
            add_json_arr_string(arr, event);
        }
        json_object_object_add(req, "events", arr);
        break;
    case IPC_REQUEST_TYPE_HISTORY_SIZE:
        break;
    default:
        log_abort("Unknown request type %d", type);
    }
    va_end(ap);

    g_task_set_source_tag(task, ipc_handle_request_async);
    g_task_set_task_data(task, req, (GDestroyNotify)put_json_object);

    g_async_queue_push(self->request_queue, task);
    ipc_handle_thread_wakeup(self);
}

struct json_object *
ipc_handle_request_finish(IPCHandle *self, GAsyncResult *result, GError **error)
{
    g_assert(IPC_IS_HANDLE(self));
    g_assert(G_IS_ASYNC_RESULT(result));
    g_assert(g_async_result_is_tagged(result, ipc_handle_request_async));
    g_assert(error == NULL || *error == NULL);

    return g_task_propagate_pointer(G_TASK(result), error);
}
