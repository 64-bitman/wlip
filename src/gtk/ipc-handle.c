#include "ipc-handle.h"
#include "ipc_client.h"
#include "log.h"
#include "util.h"
#include <assert.h>
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
static void ipc_handle_signal_event(IPCHandle *self, IPCEvent *event, void *udata);

static void *ipc_handle_thread(IPCHandle *handle);
static void ipc_handle_thread_wakeup(IPCHandle *self);

static void ipc_request_data_free(struct ipc_request_data *data);

static IPCEvent *ipc_event_ref(IPCEvent *event);
static void ipc_event_unref(IPCEvent *event);
// clang-format on

#define IPC_TYPE_EVENT (ipc_event_get_type())
G_DEFINE_BOXED_TYPE(IPCEvent, ipc_event, ipc_event_ref, ipc_event_unref);

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

    obj_signals[SIGNAL_EVENT] = g_signal_new_class_handler(
        "event",
        G_TYPE_FROM_CLASS(class),
        G_SIGNAL_NO_HOOKS | G_SIGNAL_NO_RECURSE,
        G_CALLBACK(ipc_handle_signal_event),
        NULL,
        NULL,
        NULL,
        G_TYPE_NONE,
        1,
        IPC_TYPE_EVENT
    );
}

static void
ipc_handle_init(IPCHandle *self)
{
    self->request_queue =
        g_async_queue_new_full((GDestroyNotify)ipc_request_data_free);
}

IPCHandle *
ipc_handle_new(void)
{
    IPCHandle *handle = g_object_new(IPC_TYPE_HANDLE, NULL);

    handle->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

    if (handle->efd == -1)
        log_errabort("Error creating eventfd:%s");

    g_atomic_int_set(&handle->run, 1);
    handle->thread =
        g_thread_new("IPCHandle", (GThreadFunc)ipc_handle_thread, handle);

    return handle;
}

static gboolean
ipc_invoke_handler(struct ipc_request_data *data)
{
    data->callback(data->obj, data->udata);
    data->obj = NULL;
    return G_SOURCE_REMOVE;
}

static void
ipc_response_handler(struct json_object *resp, void *udata)
{
    struct ipc_request_data *data = udata;

    assert(data->obj == NULL);
    if (data->callback == NULL)
    {
        json_object_put(resp);
        ipc_request_data_free(data);
        return;
    }

    data->obj = resp;

    // Invoke callback in global main context
    g_main_context_invoke_full(
        NULL,
        G_PRIORITY_DEFAULT,
        (GSourceFunc)ipc_invoke_handler,
        data,
        (GDestroyNotify)ipc_request_data_free
    );
}

static gboolean
ipc_event_invoke_handler(IPCEvent *event)
{
    IPCHandle *handle = event->ptr;

    g_signal_emit(handle, obj_signals[SIGNAL_EVENT], 0, event);
    return G_SOURCE_REMOVE;
}

static void
ipc_event_handler(struct json_object *event_obj, IPCHandle *handle)
{
    const char *event_type = get_json_string(event_obj, "event");

    if (event_type == NULL)
    {
        json_object_put(event_obj);
        return;
    }

    IPCEvent *event = g_new(IPCEvent, 1);

    event->event = event_obj;
    event->event_type = event_type;
    event->ptr = handle;

    g_main_context_invoke_full(
        NULL,
        G_PRIORITY_DEFAULT,
        (GSourceFunc)ipc_event_invoke_handler,
        event,
        (GDestroyNotify)ipc_event_unref
    );
}

static void
ipc_handle_signal_event(
    IPCHandle *self UNUSED, IPCEvent *event, void *udata UNUSED
)
{
    ipc_event_unref(event);
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
        struct ipc_request_data *data;

        while ((data = g_async_queue_try_pop(handle->request_queue)) != NULL)
        {
            ipc_client_queue_request(
                &client, data->obj, ipc_response_handler, data
            );
            data->obj = NULL;
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
ipc_request_data_free(struct ipc_request_data *data)
{
    if (data->obj != NULL)
        json_object_put(data->obj);
    g_free(data);
}

/*
 * Queue a request to be sent to the daemon, taking ownershio of "req". If
 * "callback" is NULL, then any responses are ignored. If "req" is NULL, then a
 * new JSON empty json object is created.
 */
void
ipc_handle_queue_request(
    IPCHandle          *self,
    const char         *type,
    struct json_object *req,
    request_callback    callback,
    void               *udata
)
{
    g_assert(IPC_IS_HANDLE(self));
    g_assert(type != NULL);

    struct ipc_request_data *data = g_new(struct ipc_request_data, 1);

    if (req == NULL)
        req = json_object_new_object();
    if (req == NULL)
        log_abort("Error allocating JSON object");
    add_json_string(req, "type", type, true);

    data->obj = req;
    data->callback = callback;
    data->udata = udata;

    g_async_queue_push(self->request_queue, data);
    ipc_handle_thread_wakeup(self);
}

void
ipc_handle_subscribe(IPCHandle *self, const char *event)
{
    g_assert(IPC_IS_HANDLE(self));
    g_assert(event != NULL);

    struct json_object *obj = json_object_new_object();

    if (obj == NULL)
        log_abort("Error allocating JSON object");

    add_json_string(obj, "event", event, true);
    ipc_handle_queue_request(self, "subscribe", obj, NULL, NULL);
}

static IPCEvent *
ipc_event_ref(IPCEvent *event)
{
    json_object_get(event->event);
    return event;
}

static void
ipc_event_unref(IPCEvent *event)
{
    if (json_object_put(event->event))
        g_free(event);
}
