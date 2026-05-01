#include "ipc.h"
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

struct ipc_event_data
{
    struct ipc         *ipc;
    struct json_object *obj;
};

// clang-format off
static void *ipc_thread(struct ipc *ipc);
static void ipc_thread_wakeup(struct ipc *ipc);

static void ipc_request_data_free(struct ipc_request_data *data);
static void ipc_event_data_free(struct ipc_event_data *data);
// clang-format on

/*
 * Start IPC thread and connect to daemon. If connecting fails, then the IPC
 * thread will call exit(). Returns OK on success and FAIL on failure.
 */
int
ipc_init(struct ipc *ipc, event_callback event_cb, void *udata)
{
    ipc->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

    if (ipc->efd == -1)
    {
        log_errerror("Error creating eventfd");
        return FAIL;
    }
    g_atomic_int_set(&ipc->run, 1);
    ipc->request_queue =
        g_async_queue_new_full((GDestroyNotify)ipc_request_data_free);
    ipc->event_cb = event_cb;
    ipc->event_udata = udata;
    ipc->thread = g_thread_new("IPC", (GThreadFunc)ipc_thread, ipc);

    return OK;
};

void
ipc_uninit(struct ipc *ipc)
{
    g_atomic_int_set(&ipc->run, 0);
    ipc_thread_wakeup(ipc);
    g_thread_join(ipc->thread);
    g_thread_unref(ipc->thread);

    g_async_queue_unref(ipc->request_queue);
    close(ipc->efd);
}

static gboolean
ipc_invoke_handler(struct ipc_request_data *data)
{
    data->callback(data->obj, data->udata);
    g_free(data);
    return G_SOURCE_REMOVE;
}

static void
ipc_response_handler(struct json_object *resp, void *udata)
{
    struct ipc_request_data *data = udata;

    assert(data->obj == NULL);
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
ipc_event_invoke_handler(struct ipc_event_data *data)
{
    data->ipc->event_cb(data->obj, data->ipc->event_udata);
    g_free(data);
    return G_SOURCE_REMOVE;
}

static void
ipc_event_handler(struct json_object *event, void *udata)
{
    struct ipc            *ipc = udata;
    struct ipc_event_data *data = g_new(struct ipc_event_data, 1);

    data->ipc = ipc;
    data->obj = event;
    g_main_context_invoke_full(
        NULL,
        G_PRIORITY_DEFAULT,
        (GSourceFunc)ipc_event_invoke_handler,
        data,
        (GDestroyNotify)ipc_event_data_free
    );
}

static void *
ipc_thread(struct ipc *ipc)
{
    struct ipc_client client;

    if (ipc_client_init(&client) == FAIL)
        exit(EXIT_FAILURE);

    client.event_callback = ipc_event_handler;
    client.event_udata = ipc;

    struct pollfd pfds[2];

    pfds[0].fd = client.fd;
    pfds[1].fd = ipc->efd;
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
        if (g_atomic_int_get(&ipc->run) == 0)
            break;

        if (ipc_client_check(&client, pfds[0].revents) == FAIL)
            exit(EXIT_FAILURE);

        // Flush any pending requests to the client
        struct ipc_request_data *data;

        while ((data = g_async_queue_try_pop(ipc->request_queue)) != NULL)
        {
            ipc_client_queue_request(
                &client, data->obj, ipc_response_handler, data
            );
            data->obj = NULL;
        }
    }

    ipc_client_uninit(&client);

    return NULL;
}

static void
ipc_thread_wakeup(struct ipc *ipc)
{
    int64_t x = 1;
    write(ipc->efd, &x, sizeof(x));
}

static void
ipc_request_data_free(struct ipc_request_data *data)
{
    json_object_put(data->obj);
    g_free(data);
}

static void
ipc_event_data_free(struct ipc_event_data *data)
{
    json_object_put(data->obj);
    g_free(data);
}

/*
 * Queue a request to be sent to the daemon. If "callback" is NULL, then any
 * responses are ignored.
 */
void
ipc_queue_request(
    struct ipc         *ipc,
    const char         *type,
    struct json_object *req,
    request_callback    callback,
    void               *udata
)
{
    struct ipc_request_data *data = g_new(struct ipc_request_data, 1);

    add_json_string(req, "type", type, true);

    data->obj = req;
    data->callback = callback;
    data->udata = udata;

    g_async_queue_push(ipc->request_queue, data);
    ipc_thread_wakeup(ipc);
}
