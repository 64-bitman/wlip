#include "ipc.h"
#include "base64.h"
#include "config.h"
#include "log.h"
#include "util.h"
#include "wlip.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define ERRMSG_MEM "Out of memory"
#define ERRMSG_DB "Database transaction failed"
#define ERRMSG_INVALID_ARGS "Missing or invalid arguments"

// clang-format off
static void ipc_check(int revents, void *udata);

static int  ipc_connection_add(struct ipc *ipc, int fd);
static void ipc_connection_free(struct ipc_connection *ct);
static void ipc_connection_check(int revents, void *udata);

static void ipc_connection_queue_message(struct ipc_connection *ct, struct json_object *obj);

static void ipc_connection_error(struct ipc_connection *ct, int64_t serial, const char *desc);

static void ipc_connection_handle_listen_event_stream(struct ipc_connection *ct, int64_t serial, struct json_object *req);
static void ipc_connection_handle_get_entry(struct ipc_connection *ct, int64_t serial, struct json_object *req);
static void ipc_connection_handle_load_mimetype_data(struct ipc_connection *ct, int64_t serial, struct json_object *req);
static void ipc_connection_handle_set_entry(struct ipc_connection *ct, int64_t serial, struct json_object *req);
static void ipc_connection_handle_delete_entry(struct ipc_connection *ct, int64_t serial, struct json_object *req);
static void ipc_connection_handle_get_history_size(struct ipc_connection *ct, int64_t serial, struct json_object *req);
static void ipc_connection_handle_set_starred(struct ipc_connection *ct, int64_t serial, struct json_object *req);
// clang-format on

#define REQUEST_HANDLER(name) {STRINGIFY(name), ipc_connection_handle_##name}
static struct request_handler
{
    const char *name;
    // clang-format off
    void (*callback)(struct ipc_connection *ct, int64_t serial, struct json_object *req);
    // clang-format on
} REQUEST_HANDLERS[] = {
    /*
     * "event_stream" request:
     * Enable or disable receiving events from the daemon. Arguments:
     * "enable": boolean
     * If events should be received
     */
    REQUEST_HANDLER(listen_event_stream),
    /*
     * "entry" request:
     * Get info about an entry at a given position. Arguments:
     * "pos": int64_t
     * Position of entry to use
     *
     * Returned fields:
     * "id": int64_t
     * ID of entry
     * "creation_time": int64_t
     * Creation time in Unix time (ms)
     * "update_time": int64_t
     * Last time entry was updated/used in Unix time (ms)
     * "starred": boolean
     * If entry is starred
     * "current": boolean
     * If entry is currently set as the current entry
     * "mime_types" const char *[]
     * Array of mime types for this entry
     */
    REQUEST_HANDLER(get_entry),
    /*
     * "mimetype" request:
     * Get the contents of a mime type as a base64 encoded string. Arguments:
     * "id": int64_t
     * ID of entry to use
     * "mime_type": const char *
     * Mime type to use
     *
     * Returned fields:
     * "data": const char *
     * Base64 encoded string of contents
     */
    REQUEST_HANDLER(load_mimetype_data),
    /*
     * "set" request:
     * Set the current entry. Arguments:
     * "id": int64_t
     * ID of entry to set
     *
     * Return success response
     */
    REQUEST_HANDLER(set_entry),
    /*
     * "delete" request:
     * Delete a entry. Arguments:
     * "id" int64_t
     * ID of entry to delete
     *
     * Return success response
     */
    REQUEST_HANDLER(delete_entry),
    /*
     * "history_size" request:
     * Get number of entries in clipboard history.
     *
     * Returned fields:
     * "size": int64_t
     * Number of entries
     */
    REQUEST_HANDLER(get_history_size),
    /*
     * "starred" request:
     * Set starred state of entry. Arguments:
     * "id" int64_t
     * ID of entry to change
     * "starred": boolean
     * New starred state to use
     */
    REQUEST_HANDLER(set_starred),
};
#undef REQUEST_HANDLER

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
            log_errerror("Error creating directory '%s'", dir);
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
        log_errerror("Error allocating socket path");
        goto fail;
    }

    // Check if socket exists. If so, then check if it is actually used by a
    // process, and if so, delete it.
    pid_t pid = lock_is_locked(lock_path);

    if (pid == 0)
        goto fail;
    else if (pid != -1)
    {
        log_error(
            "Error starting IPC server, process %d owns socket path", pid
        );
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
        log_errerror("Error creating IPC socket");
        goto fail2;
    }

    struct sockaddr_un addr;

    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    addr.sun_family = AF_UNIX;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        log_errerror("Error binding to IPC socket");
        goto fail2;
    }

    if (listen(fd, 5) == -1)
    {
        log_errerror("Error listening to IPC socket");
        goto fail2;
    }

    eventsource_init(&ipc->source, 0, fd, POLLIN, ipc_check, ipc);
    eventloop_add_source(wlip->loop, &ipc->source);

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

    if (!(revents & POLLIN))
    {
        log_warn("IPC server lost");
        eventsource_uninit(&ipc->source);
        return;
    }

    int fd = accept(ipc->fd, NULL, NULL);

    if (fd == -1)
    {
        log_errwarn("Error accepting IPC client");
        return;
    }

    if (set_fd_nonblocking(fd) == FAIL)
    {
        close(fd);
        return;
    }

    if (ipc_connection_add(ipc, fd) == FAIL)
        close(fd);
}

/*
 * Emit the given event with arguments depending on "fmt". See
 * build_json_object() on how format string works.
 */
void
ipc_emit_event(struct ipc *ipc, const char *event, const char *fmt, ...)
{
    struct json_object *msg = NULL;
    va_list             ap;

    if (wl_list_empty(&ipc->connections))
        return;

    msg = build_json_object(msg, "ss", "type", "event", "event", event);
    va_start(ap, fmt);
    msg = build_json_object_va(msg, fmt, ap);
    va_end(ap);
    if (msg == NULL)
        return;

    struct ipc_connection *ct;

    wl_list_for_each(ct, &ipc->connections, link)
    {
        if (ct->events)
            ipc_connection_queue_message(ct, msg);
    }
    json_object_put(msg);
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
        log_errerror("Error allocating JSON tokener");
        free(ct);
        return FAIL;
    }

    eventsource_init(&ct->source, 0, fd, POLLIN, ipc_connection_check, ct);
    eventloop_add_source(ipc->wlip->loop, &ct->source);

    ct->ipc = ipc;
    ct->events = false;
    wl_list_init(&ct->write_queue);

    wl_list_insert(&ipc->connections, &ct->link);

    return OK;
}

static void
ipc_connection_free(struct ipc_connection *ct)
{
    eventsource_uninit(&ct->source);

    struct ipc_message *resp, *tmp;

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
request_handler(struct json_object *req_obj, void *udata)
{
    struct ipc_connection *ct = udata;

    const char *type;
    int64_t     serial;

    if (extract_json_object(req_obj, "si", "type", &type, "serial", &serial) ==
        FAIL)
        goto exit;

    if (type != NULL)
    {
        struct request_handler *handler = NULL;

        for (int i = 0; i < N_ELEMENTS(REQUEST_HANDLERS); i++)
            if (strcmp(type, REQUEST_HANDLERS[i].name) == 0)
            {
                handler = REQUEST_HANDLERS + i;
                break;
            }
        if (handler == NULL)
            ipc_connection_error(ct, serial, ERRMSG_INVALID_ARGS);
        else
            handler->callback(ct, serial, req_obj);
    }

exit:
    json_object_put(req_obj);
}

/*
 * Handle new data to read for connection.
 */
static void
ipc_connection_check(int revents, void *udata)
{
    struct ipc_connection *ct = udata;

    if (!(revents & (POLLIN | POLLOUT)))
    {
        ipc_connection_free(ct);
        return;
    }
    else if (!(revents & POLLIN))
        goto try_write;

    static char buf[4096];
    ssize_t     r = read(ct->source.fd, buf, 4096);

    if (r == -1)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            goto try_write;
        log_errwarn("Error reading from IPC connection");
        ipc_connection_free(ct);
        return;
    }
    else if (r == 0)
    {
        if (revents & POLLOUT || !wl_list_empty(&ct->write_queue))
            goto try_write;

        ipc_connection_free(ct);
        return;
    }

    // Read data from buffer into JSON tokener until empty. Each request is
    // newline delimited.
    process_json_buffer(buf, r, ct->tokener, request_handler, ct);

try_write:
    if (revents & POLLOUT)
    {
        // Write any pending responses from the queue
        struct ipc_message *resp =
            wl_container_of(ct->write_queue.next, resp, link);
        ssize_t w;

        if (resp == NULL)
        {
            // Not sure if this can happen but handle it
            ct->source.events = POLLIN;
            return;
        }

        if (resp->remaining == 0)
            w = write(ct->source.fd, "\n", 1);
        else
        {
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
        }

        if (w == -1)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                log_errwarn("Error writing to IPC connection");
                ipc_connection_free(ct);
            }
            return;
        }

        // Go onto next response if any
        wl_list_remove(&resp->link);
        if (wl_list_empty(&ct->write_queue))
            ct->source.events = POLLIN;

        json_object_put(resp->resp);
        free(resp);
    }
}

/*
 * Queue message "obj" onto the connection queue, to be sent to the client. Adds
 * a new reference to "obj".
 */
static void
ipc_connection_queue_message(struct ipc_connection *ct, struct json_object *obj)
{
    struct ipc_message *msg = malloc(sizeof(*msg));

    if (msg == NULL)
        return;

    msg->resp = obj; // Reference is added at end of func
    msg->data = json_object_to_json_string_length(
        obj, JSON_C_TO_STRING_PLAIN, &msg->remaining
    );
    if (msg->data == NULL)
    {
        free(msg);
        return;
    }
    ct->source.events = POLLIN | POLLOUT;

    // Insert after last element
    wl_list_insert(ct->write_queue.prev, &msg->link);
    json_object_get(obj);
}

/*
 * Send back a response using "fmt" for the arguments.
 */
static void
ipc_connection_respond(
    struct ipc_connection *ct, int64_t serial, const char *fmt, ...
)
{
    struct json_object *resp = NULL;

    resp = build_json_object(resp, "si", "type", "response", "serial", serial);

    va_list ap;
    va_start(ap, fmt);
    resp = build_json_object_va(resp, fmt, ap);
    va_end(ap);
    if (resp == NULL)
        return;

    ipc_connection_queue_message(ct, resp);
    json_object_put(resp);
}

/*
 * Send back a success response
 */
static void
ipc_connection_success(struct ipc_connection *ct, int64_t serial)
{
    struct json_object *resp = NULL;

    resp = build_json_object(resp, "si", "type", "success", "serial", serial);
    if (resp == NULL)
        return;

    ipc_connection_queue_message(ct, resp);
    json_object_put(resp);
}

/*
 * Send back an error response
 */
static void
ipc_connection_error(
    struct ipc_connection *ct, int64_t serial, const char *desc
)
{
    struct json_object *resp = NULL;

    resp = build_json_object(
        resp, "sis", "type", "error", "serial", serial, "desc", desc
    );
    if (resp == NULL)
        return;

    ipc_connection_queue_message(ct, resp);
    json_object_put(resp);
}

static void
ipc_connection_handle_listen_event_stream(
    struct ipc_connection *ct, int64_t serial, struct json_object *req
)
{
    bool enable;

    if (extract_json_object(req, "b", "enable", &enable) == FAIL)
    {
        ipc_connection_error(ct, serial, ERRMSG_INVALID_ARGS);
        return;
    }

    ct->events = enable;
    ipc_connection_success(ct, serial);
}

static void
ipc_connection_handle_get_entry(
    struct ipc_connection *ct, int64_t serial, struct json_object *req
)
{
    int64_t index;

    if (extract_json_object(req, "i", "pos", &index) == FAIL)
    {
        ipc_connection_error(ct, serial, ERRMSG_INVALID_ARGS);
        return;
    }

    struct database      *db = &ct->ipc->wlip->database;
    struct database_entry entry;

    if (database_deserialize_entry(db, index, &entry) == FAIL)
    {
        ipc_connection_error(ct, serial, ERRMSG_DB);
        return;
    }

    struct json_object *mime_types = json_object_new_array();

    if (mime_types != NULL)
        database_add_mime_types_to_json(db, entry.id, mime_types);

    ipc_connection_respond(
        ct,
        serial,
        "iiibbo",
        "id",
        entry.id,
        "creation_time",
        entry.creation_time,
        "update_time",
        entry.update_time,
        "starred",
        entry.starred,
        "current",
        entry.id == ct->ipc->wlip->wayland.entry_id,
        "mime_types",
        mime_types
    );
    json_object_put(mime_types);
}

static void
ipc_connection_handle_load_mimetype_data(
    struct ipc_connection *ct, int64_t serial, struct json_object *req
)
{
    int64_t     id;
    const char *mime_type;

    if (extract_json_object(req, "is", "id", &id, "mime_type", &mime_type) ==
        FAIL)
    {
        ipc_connection_error(ct, serial, ERRMSG_INVALID_ARGS);
        return;
    }

    struct database *db = &ct->ipc->wlip->database;

    sqlite3_stmt *stmt = database_deserialize_mime_type_data(db, id, mime_type);

    if (stmt == NULL)
    {
        ipc_connection_error(ct, serial, ERRMSG_DB);
        return;
    }

    const uint8_t *data = sqlite3_column_blob(stmt, 0);
    int            len = sqlite3_column_bytes(stmt, 0);

    if (data != NULL && len > 0)
    {
        char *buf = malloc(b64e_size(len) + 1);

        if (buf == NULL)
        {
            ipc_connection_error(ct, serial, ERRMSG_MEM);
            goto exit;
        }

        b64_encode(data, len, (unsigned char *)buf);
        ipc_connection_respond(ct, serial, "s", "data", buf);
        free(buf);
    }
    else
        ipc_connection_respond(ct, serial, "s", "data", "");

exit:
    sqlite3_reset(stmt);
}

static void
ipc_connection_handle_set_entry(
    struct ipc_connection *ct, int64_t serial, struct json_object *req
)
{
    int64_t id;

    if (extract_json_object(req, "i", "id", &id) == FAIL)
    {
        ipc_connection_error(ct, serial, ERRMSG_INVALID_ARGS);
        return;
    }

    struct database *db = &ct->ipc->wlip->database;

    // Check if ID is valid
    if (!database_id_exists(db, id))
    {
        ipc_connection_error(ct, serial, ERRMSG_INVALID_ARGS);
        return;
    }

    wayland_set_selection(&ct->ipc->wlip->wayland, id, true);
    ipc_connection_success(ct, serial);
}

static void
ipc_connection_handle_delete_entry(
    struct ipc_connection *ct, int64_t serial, struct json_object *req
)
{
    int64_t id;

    if (extract_json_object(req, "i", "id", &id) == FAIL)
    {
        ipc_connection_error(ct, serial, ERRMSG_INVALID_ARGS);
        return;
    }

    struct database *db = &ct->ipc->wlip->database;
    struct wayland  *wayland = &ct->ipc->wlip->wayland;

    int64_t pos = database_get_index(db, id);

    if (pos == -1 || database_delete_entry(db, id) == FAIL)
    {
        ipc_connection_error(ct, serial, ERRMSG_DB);
        return;
    }

    ipc_emit_event(ct->ipc, IPC_EVENT_DELETE, "ii", IPC_ID, id, IPC_POS, pos);

    // If entry is the currently active, then just clear the selection.
    if (id == wayland->entry_id)
        wayland_set_selection(wayland, -1, true);

    ipc_connection_success(ct, serial);
}

static void
ipc_connection_handle_get_history_size(
    struct ipc_connection *ct, int64_t serial, struct json_object *req UNUSED
)
{
    struct database *db = &ct->ipc->wlip->database;
    int64_t          n = database_get_history_size(db);

    if (n == -1)
    {
        ipc_connection_error(ct, serial, ERRMSG_DB);
        return;
    }

    ipc_connection_respond(ct, serial, "i", "size", n);
}

static void
ipc_connection_handle_set_starred(
    struct ipc_connection *ct, int64_t serial, struct json_object *req
)
{
    int64_t id;
    bool    starred;

    if (extract_json_object(req, "ib", "id", &id, "starred", &starred) == FAIL)
    {
        ipc_connection_error(ct, serial, ERRMSG_INVALID_ARGS);
        return;
    }

    struct database      *db = &ct->ipc->wlip->database;
    struct database_entry entry;

    entry.id = id;
    entry.starred = starred;
    entry.flags = DATABASE_ENTRY_STARRED;

    if (database_serialize_entry(db, &entry) == -1)
    {
        ipc_connection_error(ct, serial, ERRMSG_DB);
        return;
    }

    ipc_emit_event(
        ct->ipc,
        IPC_EVENT_UPDATE,
        "ib",
        IPC_UPDATE_TIME,
        entry.update_time,
        IPC_STARRED,
        starred
    );
    ipc_connection_success(ct, serial);
}
