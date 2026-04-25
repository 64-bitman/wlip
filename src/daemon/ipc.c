#include "ipc.h"
#include "base64.h"
#include "config.h"
#include "sys/socket.h"
#include "sys/un.h"
#include "util.h"
#include "wlip.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int  ipc_connection_add(struct ipc *ipc, int fd);
static void ipc_connection_free(struct ipc_connection *ct);
static void ipc_connection_handle(int revents, void *udata);

// clang-format off
static void ipc_request_get_entry(struct ipc_connection *ct, struct json_object *req);
static void ipc_request_set_entry(struct ipc_connection *ct, struct json_object *req);
static void ipc_request_delete_entry(struct ipc_connection *ct, struct json_object *req);
// clang-format on

/*
 * Initialize IPC server at "socket_path". If "socket_path" is NULL, then
 * automatically create a path based on the Wayland display name. Returns OK on
 * success and FAIL on failure.
 */
int
ipc_init(
    struct ipc    *ipc,
    const char    *socket_path,
    struct config *config,
    struct wlip   *wlip
)
{
    char *path;
    char *lock_path;

    if (socket_path == NULL)
    {
        char *dir = get_base_dir(XDG_RUNTIME_DIR, "wlip");

        if (dir == NULL)
            return FAIL;
        if (mkdir(dir, 0755) == -1 && errno != EEXIST)
        {
            wlip_err("Error creating directory '%s'", dir);
            free(dir);
            return FAIL;
        }

        const char *display = config->display_name;

        if (display == NULL)
            display = getenv("WAYLAND_DISPLAY");
        if (display == NULL)
        {
            // Shouldn't happen, because we initialize wayland connection before
            // this.
            free(dir);
            return FAIL;
        }

        path = wlip_strdup_printf("%s/%s", dir, display);
        lock_path = wlip_strdup_printf("%s/%s.lock", dir, display);
        free(dir);
    }
    else
    {
        path = strdup(socket_path);
        lock_path = wlip_strdup_printf("%s.lock", socket_path);
    }

    if (path == NULL || lock_path == NULL)
    {
        wlip_err("Error allocating socket path");
        goto fail;
    }

    // Check if socket exists. If so, then check if it is actually used by a
    // process, and if so, delete it.
    pid_t pid = lock_is_locked(lock_path);

    if (pid == 0)
        goto fail;
    else if (pid != -1)
    {
        wlip_log("Error starting IPC server, process %d owns socket path", pid);
        goto fail;
    }
    else
    {
        unlink(path);
        unlink(lock_path);
    }

    if (create_lock(lock_path, &ipc->lock_fd) == FAIL)
        goto fail;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd == -1)
    {
        wlip_err("Error creating IPC socket");
        unlink(lock_path);
        goto fail;
    }

    struct sockaddr_un addr;

    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    addr.sun_family = AF_UNIX;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        wlip_err("Error binding to IPC socket");
        unlink(lock_path);
        goto fail;
    }

    if (listen(fd, 5) == -1)
    {
        wlip_err("Error listening to IPC socket");
        unlink(lock_path);
        goto fail;
    }

    ipc->path = path;
    ipc->lock_path = lock_path;
    ipc->fd = fd;
    ipc->wlip = wlip;
    wl_list_init(&ipc->connections);

    return OK;
fail:
    free(path);
    free(lock_path);
    return FAIL;
}

void
ipc_uninit(struct ipc *ipc)
{
    struct ipc_connection *ct, *tmp;

    wl_list_for_each_safe(ct, tmp, &ipc->connections, link)
    {
        ipc_connection_free(ct);
    }

    close(ipc->fd);
    close(ipc->lock_fd);
    unlink(ipc->path);
    unlink(ipc->lock_path);
    free(ipc->path);
    free(ipc->lock_path);
}

void
ipc_accept(struct ipc *ipc)
{
    int fd = accept(ipc->fd, NULL, NULL);

    if (fd == -1)
    {
        wlip_err("Error accepting IPC client");
        return;
    }

    // Make fd non blocking
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    if (ipc_connection_add(ipc, fd) == FAIL)
        close(fd);
}

/*
 * Create new connection for fd and add it, returns FAIL on failure.
 */
static int
ipc_connection_add(struct ipc *ipc, int fd)
{
    struct ipc_connection *ct = malloc(sizeof(*ct));

    if (ct == NULL)
        return FAIL;

    ct->tokener = json_tokener_new();
    if (ct->tokener == NULL)
    {
        wlip_err("Error allocating JSON tokener");
        free(ct);
        return FAIL;
    }

    ct->ipc = ipc;
    ct->write_queue = ct->write_queue_end = NULL;

    wl_list_insert(&ipc->connections, &ct->link);

    wlip_start_source(
        ipc->wlip, &ct->source, fd, POLLIN, ipc_connection_handle, ct
    );

    return OK;
}

static void
ipc_connection_free(struct ipc_connection *ct)
{
    wlip_stop_source(&ct->source);

    struct ipc_response *resp = ct->write_queue;

    while (resp != NULL)
    {
        struct ipc_response *next = resp->next;

        json_object_put(resp->resp);
        free(resp);
        resp = next;
    }

    json_tokener_free(ct->tokener);
    close(ct->source.fd);
    wl_list_remove(&ct->link);
    free(ct);
}

/*
 * Handle new data to read for connection.
 */
static void
ipc_connection_handle(int revents, void *udata)
{
#define BUFSIZE 4096
    struct ipc_connection *ct = udata;

    if (revents == 0)
        return;
    else if (!(revents & POLLIN) && !(revents & POLLOUT))
    {
        if (revents & (POLLHUP | POLLERR | POLLNVAL))
            ipc_connection_free(ct);
        return;
    }
    else if (!(revents & POLLIN))
        goto try_write;

    static char buf[BUFSIZE];
    ssize_t     r = read(ct->source.fd, buf, BUFSIZE);
    size_t      left = r;

    if (r == -1)
    {
        wlip_err("Error reading from IPC connection");
        return;
    }
    else if (r == 0)
    {
        if (revents & POLLOUT)
            goto try_write;

        ipc_connection_free(ct);
        return;
    }

    // Read data from buffer into JSON tokener until empty. Each request is
    // newline delimited.
    while (left > 0)
    {
        size_t      len, off = r - left;
        const char *nl = memchr(buf + off, '\n', left);

        if (nl == NULL)
            len = left;
        else
            len = nl - (buf + off);

        if (len == 0)
        {
            // Consume newline
            left--;
            continue;
        }

        enum json_tokener_error j_err;
        struct json_object     *req;

        req = json_tokener_parse_ex(ct->tokener, buf + off, len);
        j_err = json_tokener_get_error(ct->tokener);

        if (j_err == json_tokener_success)
        {
            const char *type = get_json_string(req, "type");

            if (type != NULL)
            {
                if (strcmp(type, "get_entry") == 0)
                    ipc_request_get_entry(ct, req);
                else if (strcmp(type, "set_entry") == 0)
                    ipc_request_set_entry(ct, req);
                else if (strcmp(type, "delete_entry") == 0)
                    ipc_request_delete_entry(ct, req);
            }
            json_object_put(req);

            left -= len + (nl != NULL);
            json_tokener_reset(ct->tokener);
        }
        else if (j_err == json_tokener_continue)
            break;
        else
        {
            wlip_log(
                "Error parsing JSON message: %s", json_tokener_error_desc(j_err)
            );
            break;
        }
    }
#undef BUFSIZE

try_write:
    if (revents & POLLOUT)
    {
        // Write any pending responses from the queue
        struct ipc_response *resp = ct->write_queue;
        ssize_t              w;

        if (resp->remaining == 0)
            w = write(ct->source.fd, "\n", 1);
        else
            w = write(ct->source.fd, resp->data, resp->remaining);

        if (w >= 0)
        {
            ct->write_queue->remaining -= w;

            if (ct->write_queue->remaining > 0)
                return;
            else
                w = write(ct->source.fd, "\n", 1);
        }

        if (w == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;

        // Go onto next response if any
        if (resp == ct->write_queue_end)
        {
            ct->write_queue_end = NULL;
            ct->source.events = POLLIN;
        }
        ct->write_queue = resp->next;

        json_object_put(resp->resp);
        free(resp);
    }
}

/*
 * Queue response "obj" onto the connection queue, to be sent to the client.
 * Takes ownership of "obj".
 */
static void
ipc_connection_queue_response(
    struct ipc_connection *ct, struct json_object *obj
)
{
    struct ipc_response *resp = malloc(sizeof(*resp));

    if (resp == NULL)
        return;

    resp->resp = obj;
    resp->data = json_object_to_json_string_length(
        obj, JSON_C_TO_STRING_PLAIN, &resp->remaining
    );
    resp->next = NULL;
    if (resp->data == NULL)
    {
        free(resp);
        json_object_put(obj);
        return;
    }

    if (ct->write_queue == NULL)
        ct->write_queue = resp;
    if (ct->write_queue_end != NULL)
        ct->write_queue_end->next = resp;
    ct->write_queue_end = resp;
    ct->source.events |= POLLOUT;
}

#define IPC_ERROR_MEMORY(ct)                                                   \
    ipc_connection_send_error(                                                 \
        ct, "memory", "Memory allocation failure: %s", strerror(errno)         \
    );

/*
 * Send an error response to the client, with the given error type and
 * description.
 */
static void
ipc_connection_send_error(
    struct ipc_connection *ct, const char *type, const char *fmt, ...
)
{
    struct json_object *resp = json_object_new_object();

    if (resp == NULL)
        return;

    add_json_string(resp, "type", "error", true);
    add_json_string(resp, "error_type", type, true);

    char   *str;
    va_list ap;
    int     len;

    va_start(ap, fmt);
    len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    str = malloc(len + 1);
    if (str == NULL)
    {
        json_object_put(resp);
        return;
    }

    va_start(ap, fmt);
    vsnprintf(str, len + 1, fmt, ap);
    va_end(ap);

    add_json_string(resp, "desc", str, true);
    free(str);

    ipc_connection_queue_response(ct, resp);
}

static void
ipc_request_get_entry(struct ipc_connection *ct, struct json_object *req)
{
    struct database *db = &ct->ipc->wlip->database;
    int64_t          idx;

    if (get_json_integer(req, "index", &idx) == FAIL)
        return;

    struct database_entry entry;

    if (database_deserialize_entry(db, idx, &entry) == FAIL)
    {
        ipc_connection_send_error(
            ct, "deserialize", "Error deserializing entry %d", idx
        );
        return;
    }

    struct json_object *resp = json_object_new_object();

    if (resp == NULL)
    {
        IPC_ERROR_MEMORY(ct);
        return;
    }

    add_json_integer(resp, "id", entry.id, true);
    add_json_integer(resp, "creation_time", entry.creation_time, true);
    add_json_integer(resp, "update_time", entry.update_time, true);
    add_json_boolean(resp, "starred", entry.starred, true);

    struct json_object *arr = json_object_new_array();

    if (arr != NULL)
    {
        database_add_mime_types(db, entry.id, arr);
        json_object_object_add_ex(
            resp, "mime_types", arr, JSON_C_OBJECT_ADD_CONSTANT_KEY
        );
    }

    ipc_connection_queue_response(ct, resp);
}

static void
ipc_request_set_entry(struct ipc_connection *ct, struct json_object *req)
{
    struct database *db = &ct->ipc->wlip->database;
    int64_t          id;

    if (get_json_integer(req, "id", &id) == FAIL)
        return;

    // Check if ID is valid
    if (id != -1 && !database_id_exists(db, id))
        return;

    wayland_set_selection(&ct->ipc->wlip->wayland, id);
}

static void
ipc_request_delete_entry(struct ipc_connection *ct, struct json_object *req)
{
    struct database *db = &ct->ipc->wlip->database;
    int64_t          id;

    if (get_json_integer(req, "id", &id) == FAIL)
        return;

    database_delete_entry(db, id);

    // If entry is the currently active, then use the previous most recent
    // entry.
    if (id != ct->ipc->wlip->wayland.entry_id)
        return;

    struct database_entry entry = {0};

    if (database_deserialize_entry(db, 0, &entry) == OK)
        wayland_set_selection(&ct->ipc->wlip->wayland, entry.id);
}
