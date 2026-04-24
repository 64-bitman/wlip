#include "ipc.h"
#include "base64.h"
#include "config.h"
#include "database.h"
#include "sys/socket.h"
#include "sys/un.h"
#include "util.h"
#include "wlip.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int  ipc_connection_add(struct ipc *ipc, int fd);
static void ipc_connection_free(struct ipc_connection *ct);
static void ipc_connection_handle(struct ipc_connection *ct);

static void
ipc_parse_message(struct ipc_connection *ct, struct json_object *root);
static void ipc_handle_request_get_entry(
    struct ipc_connection *ct, struct json_object *req
);
static void ipc_handle_request_edit_entry(
    struct ipc_connection *ct, struct json_object *req
);
static void ipc_handle_request_set_entry(
    struct ipc_connection *ct, struct json_object *req
);
static void ipc_handle_request_delete_entry(
    struct ipc_connection *ct, struct json_object *req
);

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
        wlip_err("Error accepting IPC client");

    // Make fd non blocking
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    if (ipc_connection_add(ipc, fd) == FAIL)
        close(fd);
}

/*
 * Populate pollfd array and return number of slots populated.
 */
int
ipc_set_pfds(struct ipc *ipc, struct pollfd *pfds, int max)
{
    struct ipc_connection *ct;
    int                    n = 0;

    wl_list_for_each(ct, &ipc->connections, link)
    {
        pfds[n].fd = ct->fd;
        pfds[n].events = POLLIN;
        ct->pfd_idx = n;
        n++;
        if (n >= max)
            break;
    }

    return n;
}

void
ipc_check_pfds(struct ipc *ipc, struct pollfd *pfds)
{
    struct ipc_connection *ct, *tmp;

    wl_list_for_each_safe(ct, tmp, &ipc->connections, link)
    {
        if (ct->pfd_idx == -1)
            continue;

        struct pollfd pfd = pfds[ct->pfd_idx];

        if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
        {
            ipc_connection_free(ct);
        }
        else if (pfd.revents & POLLIN)
            ipc_connection_handle(ct);
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

    ct->fd = fd;
    ct->pfd_idx = -1;
    ct->ipc = ipc;

    wl_list_insert(&ipc->connections, &ct->link);

    return OK;
}

static void
ipc_connection_free(struct ipc_connection *ct)
{
    json_tokener_free(ct->tokener);
    close(ct->fd);
    wl_list_remove(&ct->link);
    free(ct);
}

/*
 * Handle new data to read for connection.
 */
static void
ipc_connection_handle(struct ipc_connection *ct)
{
#define IPC_BUFSIZE 4096
    static char buf[IPC_BUFSIZE];
    char       *ptr = buf;
    ssize_t     r = read(ct->fd, buf, IPC_BUFSIZE);

    if (r == -1)
    {
        wlip_err("Error reading from IPC connection");
        return;
    }

    while (r > 0)
    {
        enum json_tokener_error j_err;
        struct json_object     *root;

        root = json_tokener_parse_ex(ct->tokener, ptr, r);
        j_err = json_tokener_get_error(ct->tokener);

        if (j_err == json_tokener_success)
        {
            // Recevied a complete JSON message, execute it. if there is another
            // JSON message after it in the buffer, then start parsing it.
            ipc_parse_message(ct, root);
            json_object_put(root);

            size_t off = json_tokener_get_parse_end(ct->tokener);
            ptr += off;
            r -= off;
        }
        else
        {
            if (j_err != json_tokener_continue)
                wlip_log(
                    "Error parsing JSON message: %s",
                    json_tokener_error_desc(j_err)
                );
            break;
        }
    }
#undef IPC_BUFSIZE
}

static void
ipc_parse_message(struct ipc_connection *ct, struct json_object *root)
{
    const char *type = get_json_string(root, "type");

    if (strcmp(type, "get_entry") == 0)
        ipc_handle_request_get_entry(ct, root);
    else if (strcmp(type, "edit_entry") == 0)
        ipc_handle_request_edit_entry(ct, root);
    else if (strcmp(type, "set_entry") == 0)
        ipc_handle_request_set_entry(ct, root);
    else if (strcmp(type, "delete_entry") == 0)
        ipc_handle_request_delete_entry(ct, root);
}

static void
database_entry_callback(struct database_entry *info, void *udata)
{
    void                 **arr = udata;
    struct ipc_connection *ct = arr[0];
    struct json_object    *mime_types_req = arr[1];
    struct json_object    *resp = json_object_new_object();

    if (resp == NULL)
        return;

    add_json_integer(resp, "id", info->id, true);
    add_json_integer(resp, "creation_time", info->creation_time, true);
    add_json_integer(resp, "update_time", info->update_time, true);
    add_json_boolean(resp, "starred", info->starred, true);

    // Each key is the mime type and value is the data of the mime type encoded
    // in base64, otherwise null.
    struct json_object *mime_types_resp = json_object_new_object();

    if (mime_types_resp == NULL)
        goto exit;

    // Initially set all mime types in this entry to null. Mime types requested
    // in "mime_types_req" will have their value set to their contents.
    database_add_mime_types(
        &ct->ipc->wlip->database, info->id, mime_types_resp
    );

    if (mime_types_req == NULL)
    {
        // Do not send mime type data if there are no requested mime types to
        // send.
        json_object_object_add_ex(
            resp, "mime_types", mime_types_resp, JSON_C_OBJECT_ADD_CONSTANT_KEY
        );
        goto exit;
    }

    size_t len = json_object_array_length(mime_types_req);

    for (size_t i = 0; i < len; i++)
    {
        struct json_object *j_mime_type =
            json_object_array_get_idx(mime_types_req, i);

        if (j_mime_type == NULL ||
            !json_object_is_type(j_mime_type, json_type_string))
            continue;

        const char   *mime_type = json_object_get_string(j_mime_type);
        sqlite3_stmt *stmt = database_deserialize_mime_type_data(
            &ct->ipc->wlip->database, info->id, mime_type
        );

        if (stmt == NULL)
            continue;

        const uint8_t *data = sqlite3_column_blob(stmt, 0);
        int            sz = sqlite3_column_bytes(stmt, 0);

        if (data != NULL)
        {
            char *str = malloc(b64e_size(sz) + 1);

            if (str != NULL)
            {
                b64_encode(data, sz, (unsigned char *)str);
                add_json_string(mime_types_resp, mime_type, str, false);
                free(str);
            }
        }
        sqlite3_reset(stmt);
    }

    json_object_object_add_ex(
        resp, "mime_types", mime_types_resp, JSON_C_OBJECT_ADD_CONSTANT_KEY
    );
exit:
    send_json(ct->fd, resp);
    json_object_put(resp);
}

/*
 * Handle "get_entry" request.
 */
static void
ipc_handle_request_get_entry(struct ipc_connection *ct, struct json_object *req)
{
    int64_t start;
    int64_t n;

    if (get_json_integer(req, "start", &start) == FAIL ||
        get_json_integer(req, "number", &n) == FAIL)
        return;

    struct json_object *j_mime_types = NULL;

    json_object_object_get_ex(req, "mime_types", &j_mime_types);
    if (!json_object_is_type(j_mime_types, json_type_array))
        j_mime_types = NULL;

    const void *udata[3] = {ct, j_mime_types};

    if (database_do_transaction(&ct->ipc->wlip->database, TRANSACTION_BEGIN) ==
        FAIL)
        return;

    database_deserialize_entries(
        &ct->ipc->wlip->database, start, n, database_entry_callback, udata
    );

    database_do_transaction(&ct->ipc->wlip->database, TRANSACTION_COMMIT);

    // Send terminator response (empty object) to indicate the end
    if (write_data(ct->fd, (uint8_t *)"{}", 2) == FAIL)
        wlip_err("Error writing terminator response");
}

/*
 * Handle "edit_entry" request.
 */
static void
ipc_handle_request_edit_entry(
    struct ipc_connection *ct, struct json_object *req
)
{
    struct database_entry info = {0};

    if (get_json_integer(req, "id", &info.id) == FAIL)
        return;

    if (get_json_boolean(req, "starred", &info.starred) == OK)
        info.flags |= DATABASE_ENTRY_STARRED;

    info.update_time = get_time_ns(CLOCK_REALTIME) / 1000000;
    info.flags |= DATABASE_ENTRY_UPDATE;

    database_serialize_entry(&ct->ipc->wlip->database, &info);
}

/*
 * Handle "set_entry" request.
 */
static void
ipc_handle_request_set_entry(struct ipc_connection *ct, struct json_object *req)
{
    int64_t id;

    // If "id" is -1, then clear all selections
    if (get_json_integer(req, "id", &id) == FAIL)
        return;

    // Check if ID is valid
    if (id != -1 && !database_id_exists(&ct->ipc->wlip->database, id))
        return;

    wayland_set_selection(&ct->ipc->wlip->wayland, id);
}

/*
 * Handle "delete_entry" request.
 */
static void
ipc_handle_request_delete_entry(
    struct ipc_connection *ct, struct json_object *req
)
{
    int64_t id;

    if (get_json_integer(req, "id", &id) == FAIL)
        return;

    database_delete_entry(&ct->ipc->wlip->database, id);

    // If entry is the currently active, then use the previous most recent
    // entry.
    if (id != ct->ipc->wlip->wayland.entry_id)
        return;

    struct database_entry entry = {0};

    if (database_deserialize_entry(&ct->ipc->wlip->database, 0, &entry) == OK)
        wayland_set_selection(&ct->ipc->wlip->wayland, entry.id);
}
