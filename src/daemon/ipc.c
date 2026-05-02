#include "ipc.h"
#include "base64.h"
#include "config.h"
#include "log.h"
#include "util.h"
#include "wlip.h"
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

struct ipc_request
{
    struct ipc_connection *ct;
    struct json_object    *req;
    struct json_object    *resp;
};

// clang-format off
static void ipc_check(int revents, void *udata);

static int  ipc_connection_add(struct ipc *ipc, int fd);
static void ipc_connection_free(struct ipc_connection *ct);
static void ipc_connection_check(int revents, void *udata);

static void ipc_connection_queue_message(struct ipc_connection *ct, struct json_object *obj);
static void ipc_request_respond_error(struct ipc_request *req, const char *desc);

static void ipc_request_handle_entry(struct ipc_request *req);
static void ipc_request_handle_mimetype(struct ipc_request *req);
static void ipc_request_handle_set(struct ipc_request *req);
static void ipc_request_handle_delete(struct ipc_request *req);
static void ipc_request_handle_subscribe(struct ipc_request *req);
static void ipc_request_handle_history_size(struct ipc_request *req);
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
 * Emit an event to all subscribers. Takes ownership of "args".
 */
void
ipc_emit_event(struct ipc *ipc, enum ipc_event type, struct json_object *event)
{
    struct ipc_connection *ct;

    switch (type)
    {
    case IPC_EVENT_SELECTION:
        add_json_string(event, "event", IPC_EVENT_SELECTION_STR, true);
        break;
    case IPC_EVENT_CHANGE:
        add_json_string(event, "event", IPC_EVENT_CHANGE_STR, true);
        break;
    default:
        log_abort("Unknown event type %d", type);
    }
    add_json_string(event, "type", "event", true);

    wl_list_for_each(ct, &ipc->connections, link)
    {
        if (ct->subbed_events & type)
            ipc_connection_queue_message(ct, event);
    }
    json_object_put(event);
}

void
ipc_emit_event_selection(struct ipc *ipc, int64_t id)
{
    struct json_object *event = json_object_new_object();

    if (event != NULL)
    {
        add_json_integer(event, "id", id, true);
        ipc_emit_event(ipc, IPC_EVENT_SELECTION, event);
    }
}

void
ipc_emit_event_change(struct ipc *ipc, int64_t id, const char *change)
{
    struct json_object *event = json_object_new_object();

    if (event != NULL)
    {
        add_json_integer(event, "id", id, true);
        add_json_string(event, "change", change, true);
        ipc_emit_event(ipc, IPC_EVENT_CHANGE, event);
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
        log_errerror("Error allocating JSON tokener");
        free(ct);
        return FAIL;
    }

    eventsource_init(&ct->source, 0, fd, POLLIN, ipc_connection_check, ct);
    eventloop_add_source(ipc->wlip->loop, &ct->source);

    ct->ipc = ipc;
    ct->subbed_events = IPC_EVENT_NONE;
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
    struct ipc_request     req;
    int64_t                serial;

    req.resp = json_object_new_object();
    if (req.resp == NULL ||
        get_json_integer(req_obj, "serial", &serial) == FAIL)
        goto exit;

    add_json_integer(req.resp, "serial", serial, true);
    req.ct = ct;
    req.req = req_obj;

    const char *type = get_json_string(req_obj, "type");

    if (type != NULL)
    {
        if (strcmp(type, "entry") == 0)
            ipc_request_handle_entry(&req);
        else if (strcmp(type, "mimetype") == 0)
            ipc_request_handle_mimetype(&req);
        else if (strcmp(type, "set") == 0)
            ipc_request_handle_set(&req);
        else if (strcmp(type, "delete") == 0)
            ipc_request_handle_delete(&req);
        else if (strcmp(type, "subscribe") == 0)
            ipc_request_handle_subscribe(&req);
        else if (strcmp(type, "history_size") == 0)
            ipc_request_handle_history_size(&req);
        else
            ipc_request_respond_error(&req, ERRMSG_INVALID_ARGS);
    }

exit:
    if (req.resp != NULL)
        json_object_put(req.resp);
    json_object_put(req.req);
}

/*
 * Handle new data to read for connection.
 */
static void
ipc_connection_check(int revents, void *udata)
{
    struct ipc_connection *ct = udata;

    if (!(revents & POLLIN) && !(revents & POLLOUT))
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
        log_errwarn("Error reading from IPC connection");
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

        if (w == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;

        // Go onto next response if any
        wl_list_remove(&resp->link);
        if (wl_list_empty(&ct->write_queue))
            ct->source.events = POLLIN;

        json_object_put(resp->resp);
        free(resp);
    }
}

/*
 * Queue message "obj" onto the connection queue, to be sent to the client.
 * Creates a new reference to "obj".
 */
static void
ipc_connection_queue_message(struct ipc_connection *ct, struct json_object *obj)
{
    struct ipc_message *msg = malloc(sizeof(*msg));

    if (msg == NULL)
        return;

    msg->resp = obj;
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
 * Respond to the given request using the response object in "req".
 */
static void
ipc_request_respond(struct ipc_request *req)
{
    add_json_string(req->resp, "type", "response", true);
    ipc_connection_queue_message(req->ct, req->resp);
}

/*
 * Send a response indicating success.
 */
static void
ipc_request_respond_success(struct ipc_request *req)
{
    add_json_string(req->resp, "type", "success", true);
    ipc_connection_queue_message(req->ct, req->resp);
}

/*
 * Send an error response to the client, with the given description.
 */
static void
ipc_request_respond_error(struct ipc_request *req, const char *desc)
{
    add_json_string(req->resp, "type", "error", true);
    add_json_string(req->resp, "desc", desc, true);
    ipc_connection_queue_message(req->ct, req->resp);
}

/*
 * Add relevant information of an entry to the request response. Returns OK on
 * success and FAIL on failure. If FAIL is returned, an error response will be
 * queued for the request.
 */
static int
construct_entry_response(
    struct database *db, struct database_entry *entry, struct ipc_request *req
)
{
    struct json_object *arr = json_object_new_array();

    if (arr != NULL)
    {
        database_add_mime_types(db, entry->id, arr);
        json_object_object_add_ex(
            req->resp, "mime_types", arr, JSON_C_OBJECT_ADD_CONSTANT_KEY
        );
    }
    else
    {
        ipc_request_respond_error(req, ERRMSG_MEM);
        return FAIL;
    }

    add_json_integer(req->resp, "id", entry->id, true);
    add_json_integer(req->resp, "creation_time", entry->creation_time, true);
    add_json_integer(req->resp, "update_time", entry->update_time, true);
    add_json_boolean(req->resp, "starred", entry->starred, true);

    return OK;
}

static void
ipc_request_handle_entry(struct ipc_request *req)
{
    struct ipc_connection *ct = req->ct;
    struct database       *db = &ct->ipc->wlip->database;
    int64_t                idx, id;
    struct database_entry  entry;

    if (database_do_transaction(db, TRANSACTION_BEGIN) == FAIL)
    {
        ipc_request_respond_error(req, ERRMSG_DB);
        return;
    }

    if (get_json_integer(req->req, "index", &idx) == FAIL)
    {
        if (get_json_integer(req->req, "id", &id) == FAIL)
        {
            ipc_request_respond_error(req, ERRMSG_INVALID_ARGS);
            goto exit;
        }
        else if (database_deserialize_entry_id(db, id, &entry) == FAIL)
        {
            ipc_request_respond_error(req, ERRMSG_DB);
            goto exit;
        }
    }
    else if (database_deserialize_entry(db, idx, &entry) == FAIL)
    {
        ipc_request_respond_error(req, ERRMSG_DB);
        goto exit;
    }

    if (construct_entry_response(db, &entry, req) == OK)
        ipc_request_respond(req);

exit:
    database_do_transaction(db, TRANSACTION_COMMIT);
}

static void
ipc_request_handle_mimetype(struct ipc_request *req)
{
    struct database *db = &req->ct->ipc->wlip->database;
    int64_t          id;

    if (get_json_integer(req->req, "id", &id) == FAIL)
    {
        ipc_request_respond_error(req, ERRMSG_INVALID_ARGS);
        return;
    }

    const char *mime_type = get_json_string(req->req, "mime_type");

    if (mime_type == NULL)
    {
        ipc_request_respond_error(req, ERRMSG_INVALID_ARGS);
        return;
    }

    sqlite3_stmt *stmt = database_deserialize_mime_type_data(db, id, mime_type);

    if (stmt == NULL)
    {
        ipc_request_respond_error(req, ERRMSG_DB);
        return;
    }

    const uint8_t *data = sqlite3_column_blob(stmt, 0);
    int            len = sqlite3_column_bytes(stmt, 0);

    if (data != NULL && len > 0)
    {
        char *buf = malloc(b64e_size(len) + 1);

        if (buf == NULL)
        {
            ipc_request_respond_error(req, ERRMSG_MEM);
            goto exit;
        }

        b64_encode(data, len, (unsigned char *)buf);
        add_json_string(req->resp, "data", buf, true);
        free(buf);
    }
    else
        add_json_string(req->resp, "data", "", true);

    ipc_request_respond(req);

exit:
    sqlite3_reset(stmt);
}

static void
ipc_request_handle_set(struct ipc_request *req)
{
    struct database *db = &req->ct->ipc->wlip->database;
    int64_t          id;

    if (get_json_integer(req->req, "id", &id) == FAIL)
    {
        ipc_request_respond_error(req, ERRMSG_INVALID_ARGS);
        return;
    }

    // Check if ID is valid
    if (id != -1 && !database_id_exists(db, id))
    {
        ipc_request_respond_error(req, ERRMSG_INVALID_ARGS);
        return;
    }

    wayland_set_selection(&req->ct->ipc->wlip->wayland, id);
    ipc_request_respond_success(req);
}

static void
ipc_request_handle_delete(struct ipc_request *req)
{
    struct wayland  *wayland = &req->ct->ipc->wlip->wayland;
    struct database *db = &req->ct->ipc->wlip->database;
    int64_t          id;

    if (get_json_integer(req->req, "id", &id) == FAIL)
    {
        ipc_request_respond_error(req, ERRMSG_INVALID_ARGS);
        return;
    }

    if (database_delete_entry(db, id) == FAIL)
    {
        ipc_request_respond_error(req, ERRMSG_DB);
        return;
    }

    // If entry is the currently active, then use the previous most recent
    // entry.
    if (id != req->ct->ipc->wlip->wayland.entry_id)
        goto exit;

    struct database_entry entry = {0};

    if (database_deserialize_entry(db, 0, &entry) == OK)
        wayland_set_selection(wayland, entry.id);
    else
    {
        ipc_request_respond_error(req, ERRMSG_DB);
        return;
    }
exit:
    ipc_request_respond_success(req);
}

static void
ipc_request_handle_subscribe(struct ipc_request *req)
{
    struct json_object *events_arr;
    int                 events = IPC_EVENT_NONE;

    if (json_object_object_get_ex(req->req, "events", &events_arr) &&
        json_object_is_type(events_arr, json_type_array))
    {
        int len = json_object_array_length(events_arr);

        for (int i = 0; i < len; i++)
        {
            struct json_object *j_event =
                json_object_array_get_idx(events_arr, i);
            enum ipc_event event = IPC_EVENT_NONE;

            if (json_object_is_type(j_event, json_type_string))
            {
                const char *event_name = json_object_get_string(j_event);

                if (strcmp(event_name, IPC_EVENT_SELECTION_STR) == 0)
                    event = IPC_EVENT_SELECTION;
                if (strcmp(event_name, IPC_EVENT_CHANGE_STR) == 0)
                    event = IPC_EVENT_CHANGE;
            }

            if (event == IPC_EVENT_NONE)
            {
                ipc_request_respond_error(req, ERRMSG_INVALID_ARGS);
                return;
            }
            events |= event;
        }
    }
    else
    {
        ipc_request_respond_error(req, ERRMSG_INVALID_ARGS);
        return;
    }

    req->ct->subbed_events |= events;
    ipc_request_respond_success(req);
}

static void
ipc_request_handle_history_size(struct ipc_request *req)
{
    struct database *db = &req->ct->ipc->wlip->database;
    int64_t          n = database_get_history_size(db);

    if (n == -1)
    {
        ipc_request_respond_error(req, ERRMSG_DB);
        return;
    }

    add_json_integer(req->resp, "size", n, true);
    ipc_request_respond(req);
}
