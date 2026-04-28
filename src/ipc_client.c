#include "ipc_client.h"
#include "log.h"
#include "util.h"
#include <errno.h> // IWYU pragma: keep
#include <fcntl.h>
#include <json.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/*
 * Connect to wlip daemon. Returns OK on success and FAIL on failure.
 */
int
ipc_client_init(struct ipc_client *client)
{
    const char *path = getenv("WLIP_SOCK");
    char       *tofree = NULL;

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
        tofree = wlip_strdup_printf("%s/%s", dir, display);
        path = tofree;
        free(dir);
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd == -1)
    {
        log_errerror("Error creating socket");
        free(tofree);
        return FAIL;
    }

    struct sockaddr_un addr;

    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    addr.sun_family = AF_UNIX;
    free(tofree);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        log_errerror("Error connecting to daemon");
        return FAIL;
    }

    client->tokener = json_tokener_new();
    if (client->tokener == NULL)
    {
        close(fd);
        return FAIL;
    }

    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    client->fd = fd;
    client->requests = NULL;
    client->requests_end = NULL;
    client->pending_requests = NULL;
    client->serial_gen = 0;

    return OK;
}

void
ipc_client_uninit(struct ipc_client *client)
{
    struct ipc_request *req, *next;

    for (req = client->requests; req != NULL; req = next)
    {
        next = req->next;
        ipc_request_free(req);
    }
    for (req = client->pending_requests; req != NULL; req = next)
    {
        next = req->next;
        ipc_request_free(req);
    }

    json_tokener_free(client->tokener);
    close(client->fd);
}

/*
 * Add a new request for the JSON object, taking ownership of it. Returns OK on
 * success and FAIL on failure.
 */
int
ipc_client_queue_request(
    struct ipc_client  *client,
    struct json_object *obj,
    request_callback    callback,
    void               *udata
)
{
    struct ipc_request *req = malloc(sizeof(*req));

    if (req == NULL)
    {
        json_object_put(obj);
        log_errwarn("Error allocating IPC request");
        return FAIL;
    }

    req->req = obj;
    req->serial = client->serial_gen++;
    add_json_integer(obj, "serial", req->serial, true);

    req->data = json_object_to_json_string_length(
        obj, JSON_C_TO_STRING_PLAIN, &req->remaining
    );

    req->callback = callback;
    req->udata = udata;

    req->next = NULL;
    if (client->requests == NULL)
        client->requests = req;
    if (client->requests_end != NULL)
        client->requests_end->next = req;
    client->requests_end = req;

    return OK;
}

/*
 * Should be called before polling
 */
void
ipc_client_prepare(struct ipc_client *client, struct pollfd *pfd)
{
    pfd->fd = client->fd;
    pfd->events = POLLIN;

    if (client->requests != NULL)
        pfd->events |= POLLOUT;
}

static void
response_handler(struct json_object *resp, void *udata)
{
    struct ipc_client  *client = udata;
    struct ipc_request *req, *next, *prev = NULL;
    int64_t             serial;

    if (get_json_integer(resp, "serial", &serial) == FAIL)
        goto exit;

    // Find pending request that this response is for.
    for (req = client->pending_requests; req != NULL; req = next)
    {
        next = req->next;
        if (req->serial == serial)
        {
            req->callback(resp, req->udata);
            if (prev != NULL)
                prev->next = req->next;
            if (client->pending_requests == req)
                client->pending_requests = req->next;
            ipc_request_free(req);
            return;
        }
        prev = req;
    }
exit:
    json_object_put(resp);
}

/*
 * Should be called after polling. Returns FAIL if connection lost or
 * fatal error occured.
 */
int
ipc_client_check(struct ipc_client *client, int revents)
{
    if (!(revents & POLLIN) && !(revents & POLLOUT))
        return FAIL;
    else if (!(revents & POLLIN))
        goto try_write;

    static char buf[4096];
    ssize_t     r = read(client->fd, buf, 4096);

    if (r == -1)
    {
        log_errwarn("Error reading from IPC connection");
        return FAIL;
    }
    else if (r == 0)
    {
        if (revents & POLLOUT || client->requests != NULL)
            goto try_write;
        return FAIL;
    }

    // Read data from buffer into JSON tokener until empty. Each request is
    // newline delimited.
    process_json_buffer(buf, r, client->tokener, response_handler, client);

try_write:
    if (revents & POLLOUT)
    {
        // Write any pending responses from the queue
        struct ipc_request *req = client->requests;
        ssize_t             w;

        if (req->remaining == 0)
            w = write(client->fd, "\n", 1);
        else
            w = write(client->fd, req->data, req->remaining);

        if (w >= 0)
        {
            req->remaining -= w;

            if (req->remaining > 0)
            {
                req->data += w;
                return OK;
            }
            else
                w = write(client->fd, "\n", 1);
        }

        if (w == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return OK;

        // Go onto next response if any
        if (req == client->requests_end)
            client->requests_end = NULL;
        client->requests = req->next;

        json_object_put(req->req);
        req->req = NULL;

        req->next = client->pending_requests;
        client->pending_requests = req;

        client->events = POLLIN;
    }

    return OK;
}

static void
roundtrip_response_handler(struct json_object *resp, void *udata)
{
    struct json_object **store = udata;

    *store = resp;
}

/*
 * Send a request to the daemon and wait for a response back synchronously.
 * Returns NULL on failure. Takes ownership of "req".
 */
struct json_object *
ipc_client_roundtrip(
    struct ipc_client *client, const char *type, struct json_object *req
)
{
    struct json_object *resp = NULL;

    add_json_string(req, "type", type, true);

    if (ipc_client_queue_request(
            client, req, roundtrip_response_handler, &resp
        ) == FAIL)
        return NULL;

    while (resp == NULL)
    {
        struct pollfd pfd;

        ipc_client_prepare(client, &pfd);

        int ret = poll(&pfd, 1, -1);

        if (ret == -1)
            break;
        if (ipc_client_check(client, pfd.revents) == FAIL)
            break;
    }

    return resp;
}

/*
 * Note that this does not unlink the request from the list
 */
void
ipc_request_free(struct ipc_request *req)
{
    if (req->req != NULL)
        json_object_put(req->req);
    free(req);
}
