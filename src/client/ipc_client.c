#include "ipc_client.h"
#include "base64.h"
#include "event.h"
#include "log.h"
#include "util.h"
#include <json.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// clang-format off
static void ipc_request_free(struct ipc_request *req);
static void ipc_event_free(struct ipc_event *event);
static void signal_handler(int signo UNUSED, void *udata);
static void *ipc_thread_cb(void *udata);
// clang-format on

/*
 * Start IPC client, this will add a SIGUSR1 handler to the event loop, so that
 * it can wake it up if there is a new event/response. Return OK on success and
 * FAIL on failure.
 */
int
ipc_client_init(
    struct ipc_client *client,
    struct eventloop  *loop,
    ipc_event_callback event_callback,
    void              *udata
)
{
    const char *path = getenv("WLIP_SOCK");

    memset(client, 0, sizeof(*client));

    if (path == NULL)
    {
        const char *display = getenv("WAYLAND_DISPLAY");

        if (display == NULL)
        {
            log_error("$WAYLAND_DISPLAY not set in environment");
            return FAIL;
        }
        char *dir = get_base_dir(XDG_RUNTIME_DIR, "wlip");

        if (dir == NULL)
            return FAIL;
        client->path = wlip_strdup_printf("%s/%s", dir, display);
        free(dir);
    }
    else
        client->path = strdup(path);

    if (client->path == NULL)
        return FAIL;

    if (eventloop_add_signal(loop, SIGUSR1, signal_handler, client) == FAIL)
    {
        free(client->path);
        return FAIL;
    }

    pthread_mutex_init(&client->req_mut, NULL);
    pthread_mutex_init(&client->resp_mut, NULL);
    pthread_mutex_init(&client->event_mut, NULL);
    pthread_mutex_init(&client->stop_mut, NULL);

    client->event_callback = event_callback;
    client->callback_udata = udata;
    client->loop = loop;
    client->main_thread = pthread_self();

    pthread_create(&client->ipc_thread, NULL, ipc_thread_cb, client);

    return OK;
}

void
ipc_client_uninit(struct ipc_client *client)
{
    pthread_mutex_lock(&client->stop_mut);
    client->stop = true;
    pthread_mutex_unlock(&client->stop_mut);
    pthread_kill(client->ipc_thread, SIGUSR1);
    pthread_join(client->ipc_thread, NULL);

    struct ipc_request *req;
    while ((req = client->req_first) != NULL)
    {
        client->req_first = req->next;
        ipc_request_free(req);
    }

    struct ipc_request *resp;
    while ((resp = client->resp_first) != NULL)
    {
        client->resp_first = resp->next;
        ipc_request_free(resp);
    }

    struct ipc_event *event;
    while ((event = client->event_first) != NULL)
    {
        client->event_first = event->next;
        ipc_event_free(event);
    }

    pthread_mutex_destroy(&client->req_mut);
    pthread_mutex_destroy(&client->resp_mut);
    pthread_mutex_destroy(&client->event_mut);
    pthread_mutex_destroy(&client->stop_mut);
    free(client->path);

    eventloop_del_signal(client->loop, SIGUSR1);
}

void
ipc_request_free(struct ipc_request *req)
{
    switch (req->type)
    {
    case IPC_REQUEST_GET_ENTRY:
    {
        struct ipc_request_get_entry *areq = (void *)req;

        for (int i = 0; i < areq->n_mime_types; i++)
            free(areq->mime_types[i]);
        free(areq->mime_types);
        break;
    }
    case IPC_REQUEST_LOAD_MIMETYPE_DATA:
    {
        struct ipc_request_load_mimetype_data *areq = (void *)req;
        free(areq->mimetype);
        free(areq->data);
        break;
    }
    default:
        break;
    }
    free(req->errmsg);
    free(req);
}

void
ipc_event_free(struct ipc_event *event)
{
    free(event);
}

struct ipc_request *
ipc_request_new(
    enum ipc_request_type type, ipc_request_callback callback, void *udata
)
{
    struct ipc_request *req;

    switch (type)
    {
    case IPC_REQUEST_LISTEN_EVENT_STREAM:
        req = calloc(1, sizeof(struct ipc_request_listen_event_stream));
        break;
    case IPC_REQUEST_GET_ENTRY:
        req = calloc(1, sizeof(struct ipc_request_get_entry));
        break;
    case IPC_REQUEST_LOAD_MIMETYPE_DATA:
        req = calloc(1, sizeof(struct ipc_request_load_mimetype_data));
        break;
    case IPC_REQUEST_GET_HISTORY_SIZE:
        req = calloc(1, sizeof(struct ipc_request_get_history_size));
        break;
    default:
        log_abort("Unknown request type %d", type);
    }

    req->type = type;
    req->callback = callback;
    req->callback_udata = udata;

    return req;
}

/*
 * Send a request to the daemon. Takes ownership of "req"
 */
void
ipc_client_request(struct ipc_client *client, struct ipc_request *req)
{
    pthread_mutex_lock(&client->req_mut);
    if (client->req_last == NULL)
        client->req_first = req;
    else
        client->req_last->next = req;
    client->req_last = req;
    pthread_mutex_unlock(&client->req_mut);
    pthread_kill(client->ipc_thread, SIGUSR1);
}

static void
signal_handler(int signo UNUSED, void *udata)
{
    struct ipc_client *client = udata;
    struct ipc_event  *event = NULL;

    while (true)
    {
        pthread_mutex_lock(&client->event_mut);
        if (event == NULL)
            event = client->event_first;
        if (event == NULL)
        {
            pthread_mutex_unlock(&client->event_mut);
            break;
        }
        struct ipc_event *next = event->next;

        client->event_first = next;
        if (client->event_last == event)
            client->event_last = NULL;
        pthread_mutex_unlock(&client->event_mut);

        client->event_callback(event, client->callback_udata);
        ipc_event_free(event);

        event = next;
    }

    struct ipc_request *resp = NULL;

    while (true)
    {
        pthread_mutex_lock(&client->resp_mut);
        if (resp == NULL)
            resp = client->resp_first;
        if (resp == NULL)
        {
            pthread_mutex_unlock(&client->resp_mut);
            break;
        }
        struct ipc_request *next = resp->next;

        client->resp_first = next;
        if (client->resp_last == resp)
            client->resp_last = NULL;
        pthread_mutex_unlock(&client->resp_mut);

        resp->callback(resp, resp->callback_udata);
        ipc_request_free(resp);

        resp = next;
    }
}

static void
message_callback(struct json_object *msg, void *udata)
{
    struct ipc_client   *client = ((void **)udata)[0];
    struct ipc_request **reqp = ((void **)udata)[1];
    struct ipc_request  *req = *reqp;
    bool                *received = ((void **)udata)[2];

    const char *type;

    if (extract_json_object(msg, "s", "type", &type) == FAIL)
        goto exit;

    if (strcmp(type, "event") == 0)
    {
        // Event
        const char *event_type;

        if (client->event_callback == NULL)
            goto exit;

        if (extract_json_object(msg, "s", "event", &event_type) == FAIL)
            goto exit;

        struct ipc_event *event;
        int               ret = FAIL;

        if (strcmp(event_type, "entry_added") == 0)
        {
            struct ipc_event_entry_added *aevent = calloc(1, sizeof(*aevent));

            event = (void *)aevent;
            if (aevent != NULL)
                ret = extract_json_object(msg, "i", "id", &aevent->id);
        }
        else if (strcmp(event_type, "entry_deleted") == 0)
        {
            struct ipc_event_entry_deleted *aevent = calloc(1, sizeof(*aevent));

            event = (void *)aevent;
            if (aevent != NULL)
                ret = extract_json_object(
                    msg, "ii", "id", &aevent->id, "pos", &aevent->pos
                );
        }
        else if (strcmp(event_type, "entry_updated") == 0)
        {
            struct ipc_event_entry_updated *aevent = calloc(1, sizeof(*aevent));
            bool                            update_time, starred, current;

            event = (void *)aevent;
            if (aevent != NULL)
                ret = extract_json_object(
                    msg,
                    "i?i?b?b",
                    "id",
                    &aevent->id,
                    "update_time",
                    &update_time,
                    &aevent->update_time,
                    "starred",
                    &starred,
                    &aevent->starred,
                    "current",
                    &current,
                    &aevent->current
                );

            if (ret == OK)
            {
                aevent->update_time_specified = update_time;
                aevent->starred_specified = starred;
                aevent->current_specified = current;
            }
        }
        else
            goto exit;

        if (ret == OK)
        {
            pthread_mutex_lock(&client->event_mut);
            if (client->event_last != NULL)
                client->event_last->next = event;
            client->event_last = event;
            pthread_mutex_unlock(&client->event_mut);

            pthread_kill(client->main_thread, SIGUSR1);
        }
        else if (event != NULL)
            ipc_event_free(event);
    }
    else if (req != NULL)
    {
        // Response to request. Must always call callback! Don't want to leave
        // it hanging.
        *received = true;
        *reqp = NULL;

        if (strcmp(type, "error") == 0)
        {
            const char *desc;

            if (extract_json_object(msg, "s", "desc", &desc) == OK)
                req->errmsg = strdup(desc);
            else
                req->errmsg = NULL;
            req->is_error = true;

            goto send_req;
        }

        int ret;

        switch (req->type)
        {
        case IPC_REQUEST_LISTEN_EVENT_STREAM:
        {
            struct ipc_request_listen_event_stream *areq = (void *)req;

            ret = extract_json_object(msg, "b", &areq->success);
            break;
        }
        case IPC_REQUEST_GET_ENTRY:
        {
            struct ipc_request_get_entry *areq = (void *)req;
            struct json_object           *mime_types;

            ret = extract_json_object(
                msg,
                "iiibbo",
                "id",
                &areq->id,
                "creation_time",
                &areq->creation_time,
                "update_time",
                &areq->update_time,
                "starred",
                &areq->starred,
                "current",
                &areq->current,
                "mime_types",
                json_type_array,
                &mime_types
            );

            if (ret == OK)
            {
                int len = json_object_array_length(mime_types);

                if (len == 0)
                {
                    areq->mime_types = NULL;
                    break;
                }

                areq->n_mime_types = 0;
                areq->mime_types = malloc(
                    sizeof(char *) * json_object_array_length(mime_types)
                );

                if (areq->mime_types == NULL)
                    break;

                for (int i = 0; i < len; i++)
                {
                    struct json_object *mime_type =
                        json_object_array_get_idx(mime_types, i);

                    if (!json_object_is_type(mime_type, json_type_string))
                        continue;

                    char *str = strdup(json_object_get_string(mime_type));

                    if (str == NULL)
                        continue;

                    areq->mime_types[areq->n_mime_types++] = str;
                }

                if (areq->n_mime_types == 0)
                {
                    free(areq->mime_types);
                    areq->mime_types = NULL;
                }
            }
            break;
        }
        case IPC_REQUEST_LOAD_MIMETYPE_DATA:
        {
            struct ipc_request_load_mimetype_data *areq = (void *)req;

            const char *b64;
            size_t      blen;

            ret = extract_json_object(msg, "S", "data", &b64, &blen);

            if (ret == OK && blen <= UINT_MAX)
            {
                char *data = malloc(b64d_size((uchar *)b64, blen));

                if (data == NULL)
                {
                    ret = FAIL;
                    break;
                }

                uint dlen = b64_decode((uchar *)b64, (uint)blen, (uchar *)data);

                areq->data = (uint8_t *)data;
                areq->len = dlen;
            }
            else if (blen > UINT_MAX)
                ret = FAIL;
            break;
        }
        case IPC_REQUEST_GET_HISTORY_SIZE:
        {
            struct ipc_request_get_history_size *areq = (void *)req;

            ret = extract_json_object(msg, "i", "size", &areq->size);
            break;
        }
        default:
            log_abort("Unknown request type %d", req->type);
        }

        if (ret == FAIL)
        {
            req->errmsg = strdup("Invalid response");
            req->is_error = true;
        }

send_req:
        pthread_mutex_lock(&client->resp_mut);
        if (client->resp_last != NULL)
            client->resp_last->next = req;
        client->resp_last = req;
        if (client->resp_first == NULL)
            client->resp_first = req;
        pthread_mutex_unlock(&client->resp_mut);
        pthread_kill(client->main_thread, SIGUSR1);
    }

exit:
    json_object_put(msg);
}

void *
ipc_thread_cb(void *udata)
{
    struct ipc_client *client = udata;

    // Block USR1 signal so that we only handle it when we poll for events
    sigset_t block, old;

    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    if (pthread_sigmask(SIG_BLOCK, &block, &old) == -1)
    {
        log_errerror("Error blocking signal");
        return NULL;
    }
    sigdelset(&old, SIGUSR1);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd == -1)
    {
        log_errerror("Error creating socket");
        return NULL;
    }

    struct sockaddr_un addr;

    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", client->path);
    addr.sun_family = AF_UNIX;

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        log_errerror("Error connecting to daemon");
        close(fd);
        return NULL;
    }

    struct json_tokener *tokener = json_tokener_new();

    if (tokener == NULL)
    {
        log_errerror("Error allocating JSON tokener");
        close(fd);
        return NULL;
    }

    char buf[4096];

    while (true)
    {
        pthread_mutex_lock(&client->stop_mut);
        bool stop = client->stop;
        pthread_mutex_unlock(&client->stop_mut);

        if (stop)
            break;

        pthread_mutex_lock(&client->req_mut);
        struct ipc_request *req = client->req_first;

        // Must check if there any requests queued first, because signal may
        // have arrived before it was blocked.
        if (req != NULL)
        {
            client->req_first = req->next;
            if (client->req_last == req)
                client->req_last = NULL;
            req->next = NULL;
        }
        pthread_mutex_unlock(&client->req_mut);

        if (req != NULL)
        {
            int ret;

            switch (req->type)
            {
            case IPC_REQUEST_LISTEN_EVENT_STREAM:
            {
                struct ipc_request_listen_event_stream *areq = (void *)req;

                ret = dprintf(
                    fd,
                    "{\"type\":\"listen_event_stream\",\"enable\":%s}\n",
                    areq->enable ? "true" : "false"
                );
                break;
            }
            case IPC_REQUEST_GET_ENTRY:
            {
                struct ipc_request_get_entry *areq = (void *)req;

                ret = dprintf(
                    fd,
                    "{\"type\":\"get_entry\",\"pos\":%" PRId64 "}\n",
                    areq->pos
                );
                break;
            }
            case IPC_REQUEST_LOAD_MIMETYPE_DATA:
            {
                struct ipc_request_load_mimetype_data *areq = (void *)req;

                // Sanitize mime type string, since it is untrusted data
                struct json_object *obj =
                    json_object_new_string(areq->mimetype);

                if (obj == NULL)
                {
                    ret = FAIL;
                    break;
                }
                const char *str = json_object_to_json_string(obj);

                ret = dprintf(
                    fd,
                    "{\"type\":\"load_mimetype_data\",\"id\":%" PRId64
                    ",\"mime_type\":%s}\n",
                    areq->id,
                    str
                );
                json_object_put(obj);
                break;
            }
            case IPC_REQUEST_GET_HISTORY_SIZE:
            {
                ret = dprintf(fd, "{\"type\":\"get_history_size\"}\n");
                break;
            }
            default:
                log_abort("Unknown request type %d", req->type);
            };

            if (ret == -1)
                log_errwarn("Error writing IPC request");

            if (req->callback == NULL)
            {
                // Response not needed
                ipc_request_free(req);
                req = NULL;
            }
        }

        // Read events or response. If USR1 signal interrupted, only exit
        // loop if "req" is NULL (not waiting for a response).
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        bool          closed = false;

        while (true)
        {
            int ret = ppoll(&pfd, 1, NULL, &old);

            if (ret == -1)
            {
                if (errno == EINTR)
                {
                    pthread_mutex_lock(&client->stop_mut);
                    bool stop = client->stop;
                    pthread_mutex_unlock(&client->stop_mut);

                    if (stop)
                    {
                        closed = true;
                        break;
                    }
                    else if (req == NULL)
                        break;
                    continue;
                }
                log_errwarn("Error polling IPC connection");
                closed = true;
                break;
            }

            if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
            {
                closed = true;
                break;
            }
            else if (!(pfd.revents & POLLIN))
                continue;

            ssize_t r = read(fd, buf, sizeof(buf));

            if (r == -1)
            {
                log_errwarn("Error reading from IPC connection");
                closed = true;
                break;
            }
            else if (r == 0)
            {
                // EOF, connection closed
                closed = true;
                break;
            }

            bool received = false;
            // We need to take address of request, since we may process mutliple
            // messages after the request is responsed to.
            void *ctx[] = {client, &req, &received};

            process_json_buffer(buf, r, tokener, message_callback, ctx);

            if (received)
                break;
        }

        if (closed)
        {
            if (req != NULL)
                ipc_request_free(req);
            break;
        }
    }

    close(fd);
    json_tokener_free(tokener);

    return NULL;
}
