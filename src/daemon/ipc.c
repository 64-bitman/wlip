#include "ipc.h"
#include "base64.h"
#include "config.h"
#include "util.h"
#include "wlip.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

// clang-format off
static void ipc_check(int revents, void *udata);

static int  ipc_connection_add(struct ipc *ipc, int fd);
static void ipc_connection_free(struct ipc_connection *ct);
static void ipc_connection_check(int revents, void *udata);
static void ipc_connection_queue_message(struct ipc_connection *ct, struct json_object *obj, const char *type);

static void ipc_request_get_entry(struct ipc_connection *ct, struct json_object *req, int64_t serial);
static void ipc_request_get_mime_type(struct ipc_connection *ct, struct json_object *req, int64_t serial);
static void ipc_request_set_entry(struct ipc_connection *ct, struct json_object *req, int64_t serial);
static void ipc_request_delete_entry(struct ipc_connection *ct, struct json_object *req, int64_t serial);
static void ipc_request_subscribe( struct ipc_connection *ct, struct json_object *req, int64_t serial);
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
        goto fail2;
    }

    struct sockaddr_un addr;

    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    addr.sun_family = AF_UNIX;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        wlip_err("Error binding to IPC socket");
        goto fail;
    }

    if (listen(fd, 5) == -1)
    {
        wlip_err("Error listening to IPC socket");
        goto fail2;
    }

    eventsource_init(&ipc->source, 0, fd, EPOLLIN, ipc_check, ipc);
    if (eventloop_add_source(wlip->loop, &ipc->source) == FAIL)
        goto fail2;

    ipc->path = path;
    ipc->lock_path = lock_path;
    ipc->fd = fd;
    ipc->wlip = wlip;
    wl_list_init(&ipc->connections);

    return OK;
fail2:
    unlink(lock_path);
    close(fd);
    close(ipc->lock_fd);
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

    eventsource_uninit(&ipc->source);

    close(ipc->fd);
    close(ipc->lock_fd);
    unlink(ipc->path);
    unlink(ipc->lock_path);
    free(ipc->path);
    free(ipc->lock_path);
}

static void
ipc_check(int revents, void *udata)
{
    struct ipc *ipc = udata;

    if (!(revents & EPOLLIN))
    {
        wlip_log("IPC server lost");
        eventsource_uninit(&ipc->source);
        return;
    }

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
 * Emit an event to all subscribers, if "ignore" is not NULL, then the event is
 * not sent to "ignore". Takes ownership of "args".
 */
void
ipc_emit_event(
    struct ipc            *ipc,
    enum ipc_event         type,
    struct json_object    *args,
    struct ipc_connection *ignore
)
{
    struct ipc_connection *ct;

    switch (type)
    {
    case IPC_EVENT_SELECTION:
        add_json_string(args, "event", "selection", true);
        break;
    case IPC_EVENT_ENTRY_CHANGED:
        add_json_string(args, "event", "entry_changed", true);
        break;
    default:
        wlip_abort("Unknown event type %d", type);
    }

    wl_list_for_each(ct, &ipc->connections, link)
    {
        if (ct != ignore && ct->subbed_events & type)
        {
            json_object_get(args);
            ipc_connection_queue_message(ct, args, "event");
        }
    }
    json_object_put(args);
}

void
ipc_emit_event_selection(struct ipc *ipc, int64_t id)
{
    struct json_object *event = json_object_new_object();

    if (event != NULL)
    {
        add_json_integer(event, "id", id, true);
        ipc_emit_event(ipc, IPC_EVENT_SELECTION, event, NULL);
    }
}

void
ipc_emit_event_entry_changed(struct ipc *ipc, int64_t id, const char *change)
{
    struct json_object *event = json_object_new_object();

    if (event != NULL)
    {
        add_json_integer(event, "id", id, true);
        add_json_string(event, "change", change, true);
        ipc_emit_event(ipc, IPC_EVENT_ENTRY_CHANGED, event, NULL);
    }
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

    eventsource_init(&ct->source, 0, fd, EPOLLIN, ipc_connection_check, ct);
    if (eventloop_add_source(ipc->wlip->loop, &ct->source) == FAIL)
    {
        json_tokener_free(ct->tokener);
        free(ct);
        return FAIL;
    }

    ct->ipc = ipc;
    wl_list_init(&ct->write_queue);

    wl_list_insert(&ipc->connections, &ct->link);

    return OK;
}

static void
ipc_connection_free(struct ipc_connection *ct)
{
    eventsource_uninit(&ct->source);

    struct ipc_response *resp, *tmp;

    wl_list_for_each_safe(resp, tmp, &ct->write_queue, link)
    {
        json_object_put(resp->resp);
        free(resp);
    }

    json_tokener_free(ct->tokener);
    close(ct->source.fd);
    wl_list_remove(&ct->link);
    free(ct);
}

static void
request_handler(struct json_object *req, void *udata)
{
    struct ipc_connection *ct = udata;
    const char            *type = get_json_string(req, "type");
    int64_t                serial;

    if (type != NULL && get_json_integer(req, "serial", &serial) == OK)
    {
        if (strcmp(type, "get_entry") == 0)
            ipc_request_get_entry(ct, req, serial);
        else if (strcmp(type, "get_mime_type") == 0)
            ipc_request_get_mime_type(ct, req, serial);
        else if (strcmp(type, "set_entry") == 0)
            ipc_request_set_entry(ct, req, serial);
        else if (strcmp(type, "delete_entry") == 0)
            ipc_request_delete_entry(ct, req, serial);
        else if (strcmp(type, "subscribe") == 0)
            ipc_request_subscribe(ct, req, serial);
    }
    json_object_put(req);
}

/*
 * Handle new data to read for connection.
 */
static void
ipc_connection_check(int revents, void *udata)
{
    struct ipc_connection *ct = udata;

    if (!(revents & EPOLLIN) && !(revents & EPOLLOUT))
    {
        ipc_connection_free(ct);
        return;
    }
    else if (!(revents & EPOLLIN))
        goto try_write;

    static char buf[4096];
    ssize_t     r = read(ct->source.fd, buf, 4096);

    if (r == -1)
    {
        wlip_err("Error reading from IPC connection");
        return;
    }
    else if (r == 0)
    {
        if (revents & EPOLLOUT || !wl_list_empty(&ct->write_queue))
            goto try_write;

        ipc_connection_free(ct);
        return;
    }

    // Read data from buffer into JSON tokener until empty. Each request is
    // newline delimited.
    process_json_buffer(buf, r, ct->tokener, request_handler, ct);

try_write:
    if (revents & EPOLLOUT)
    {
        // Write any pending responses from the queue
        struct ipc_response *resp =
            wl_container_of(ct->write_queue.next, resp, link);
        ssize_t w;

        if (resp->remaining == 0)
            w = write(ct->source.fd, "\n", 1);
        else
            w = write(ct->source.fd, resp->data, resp->remaining);

        if (w >= 0)
        {
            resp->remaining -= w;

            if (resp->remaining > 0)
            {
                resp->data += w;
                return;
            }
            else
                w = write(ct->source.fd, "\n", 1);
        }

        if (w == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;

        // Go onto next response if any
        wl_list_remove(&resp->link);
        if (wl_list_empty(&ct->write_queue))
        {
            ct->source.events = EPOLLIN;
            if (eventsource_modify(&ct->source, EPOLLIN) == FAIL)
            {
                ipc_connection_free(ct);
                return;
            }
        }

        json_object_put(resp->resp);
        free(resp);
    }
}

/*
 * Queue message "obj" onto the connection queue, to be sent to the client.
 * Takes ownership of "obj".
 */
static void
ipc_connection_queue_message(
    struct ipc_connection *ct, struct json_object *obj, const char *type
)
{
    struct ipc_response *resp = malloc(sizeof(*resp));

    if (resp == NULL)
    {
        json_object_put(obj);
        return;
    }

    add_json_string(obj, "type", type, true);

    resp->resp = obj;
    resp->data = json_object_to_json_string_length(
        obj, JSON_C_TO_STRING_PLAIN, &resp->remaining
    );
    if (resp->data == NULL)
    {
        free(resp);
        json_object_put(obj);
        return;
    }

    if (eventsource_modify(&ct->source, EPOLLIN | EPOLLOUT) == FAIL)
    {
        free(resp);
        json_object_put(obj);
        return;
    }
    ct->source.events = EPOLLIN | EPOLLOUT;

    // Insert after last element
    wl_list_insert(ct->write_queue.prev, &resp->link);
}

static void
ipc_connection_queue_response(
    struct ipc_connection *ct,
    struct json_object    *obj,
    const char            *type,
    int64_t                serial
)
{
    add_json_integer(obj, "serial", serial, true);
    ipc_connection_queue_message(ct, obj, type);
}

/*
 * Send a response indicating success.
 */
static void
ipc_connection_send_success(struct ipc_connection *ct, int64_t serial)
{
    struct json_object *resp = json_object_new_object();

    ipc_connection_queue_response(ct, resp, "success", serial);
}

#define IPC_ERROR_MEMORY(ct, serial)                                           \
    ipc_connection_send_error(                                                 \
        ct, serial, "memory", "Memory allocation failure: %s", strerror(errno) \
    );
#define IPC_ERROR_ID(ct, serial)                                               \
    ipc_connection_send_error(ct, serial, "id", "Invalid ID")

/*
 * Send an error response to the client, with the given error type and
 * description.
 */
static void
ipc_connection_send_error(
    struct ipc_connection *ct,
    int64_t                serial,
    const char            *type,
    const char            *fmt,
    ...
)
{
    struct json_object *resp = json_object_new_object();

    if (resp == NULL)
        return;

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

    ipc_connection_queue_response(ct, resp, "error", serial);
}

static void
ipc_request_get_entry(
    struct ipc_connection *ct, struct json_object *req, int64_t serial
)
{
    struct database      *db = &ct->ipc->wlip->database;
    int64_t               idx, id;
    struct database_entry entry;

    if (get_json_integer(req, "index", &idx) == FAIL)
    {
        if (get_json_integer(req, "id", &id) == FAIL)
        {
            IPC_ERROR_ID(ct, serial);
            return;
        }
        else if (database_deserialize_entry_id(db, id, &entry) == FAIL)
        {
            ipc_connection_send_error(
                ct, serial, "deserialize", "Error deserializing entry %d", idx
            );
            return;
        }
    }
    else if (database_deserialize_entry(db, idx, &entry) == FAIL)
    {
        ipc_connection_send_error(
            ct, serial, "deserialize", "Error deserializing entry idx %d", idx
        );
        return;
    }

    struct json_object *resp = json_object_new_object();

    if (resp == NULL)
    {
        IPC_ERROR_MEMORY(ct, serial);
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

    ipc_connection_queue_response(ct, resp, "response", serial);
}

static void
ipc_request_get_mime_type(
    struct ipc_connection *ct, struct json_object *req, int64_t serial
)
{
    struct database *db = &ct->ipc->wlip->database;
    int64_t          id;

    if (get_json_integer(req, "id", &id) == FAIL)
    {
        IPC_ERROR_ID(ct, serial);
        return;
    }

    const char *mime_type = get_json_string(req, "mime_type");

    if (mime_type == NULL)
    {
        ipc_connection_send_error(ct, serial, "mimetype", "Invalid mime type");
        return;
    }

    sqlite3_stmt *stmt = database_deserialize_mime_type_data(db, id, mime_type);

    if (stmt == NULL)
    {
        ipc_connection_send_error(
            ct, serial, "deserialize", "Error deserializing mime type"
        );
        return;
    }

    const uint8_t      *data = sqlite3_column_blob(stmt, 0);
    int                 len = sqlite3_column_bytes(stmt, 0);
    struct json_object *resp = json_object_new_object();

    if (resp == NULL)
        goto exit;

    if (data != NULL && len > 0)
    {
        char *buf = malloc(b64e_size(len) + 1);

        if (buf == NULL)
        {
            IPC_ERROR_MEMORY(ct, serial);
            json_object_put(resp);
            goto exit;
        }

        b64_encode(data, len, (unsigned char *)buf);
        add_json_string(resp, "data", buf, true);
        free(buf);
    }
    else
        add_json_string(resp, "data", "", true);

    ipc_connection_queue_response(ct, resp, "response", serial);

exit:
    sqlite3_reset(stmt);
}

static void
ipc_request_set_entry(
    struct ipc_connection *ct, struct json_object *req, int64_t serial
)
{
    struct database *db = &ct->ipc->wlip->database;
    int64_t          id;

    if (get_json_integer(req, "id", &id) == FAIL)
    {
        IPC_ERROR_ID(ct, serial);
        return;
    }

    // Check if ID is valid
    if (id != -1 && !database_id_exists(db, id))
    {
        IPC_ERROR_ID(ct, serial);
        return;
    }

    wayland_set_selection(&ct->ipc->wlip->wayland, id);
    ipc_connection_send_success(ct, serial);
}

static void
ipc_request_delete_entry(
    struct ipc_connection *ct, struct json_object *req, int64_t serial
)
{
    struct database *db = &ct->ipc->wlip->database;
    int64_t          id;

    if (get_json_integer(req, "id", &id) == FAIL)
    {
        IPC_ERROR_ID(ct, serial);
        return;
    }

    if (database_delete_entry(db, id) == OK)
        ipc_emit_event_entry_changed(ct->ipc, id, "delete");

    // If entry is the currently active, then use the previous most recent
    // entry.
    if (id != ct->ipc->wlip->wayland.entry_id)
        return;

    struct database_entry entry = {0};

    if (database_deserialize_entry(db, 0, &entry) == OK)
    {
        wayland_set_selection(&ct->ipc->wlip->wayland, entry.id);
        ipc_connection_send_success(ct, serial);
    }
    else
        ipc_connection_send_error(
            ct, serial, "deserialize", "Error deleting entry %d", id
        );
}

static void
ipc_request_subscribe(
    struct ipc_connection *ct, struct json_object *req, int64_t serial
)
{
    const char    *event_name = get_json_string(req, "event");
    enum ipc_event event = IPC_EVENT_NONE;

    if (event_name != NULL)
    {
        if (strcmp(event_name, "selection") == 0)
            event = IPC_EVENT_SELECTION;
        if (strcmp(event_name, "entry_changed") == 0)
            event = IPC_EVENT_ENTRY_CHANGED;
    }

    if (event == IPC_EVENT_NONE)
    {
        ipc_connection_send_error(ct, serial, "event", "Unknown event");
        return;
    }

    ct->subbed_events |= event;
    ipc_connection_send_success(ct, serial);
}
