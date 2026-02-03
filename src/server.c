#include "server.h"
#include "alloc.h"
#include "array.h"
#include "event.h"
#include "ringbuffer.h"
#include "server_api.h"
#include <assert.h>
#include <fcntl.h>
#include <json.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/*
 * Commands are newline terminated JSON strings in the format of:
 *
 * {
 *   "command": <name>
 *   ...OPTIONAL...
 *   "serial": <int>
 *   "args": <any>
 *   "size": <int>
 * }
 *
 * Serial is a unique integer that is used by the client to identify replies
 * that came from a specific command. The serial is optional, and if excluded,
 * then a default serial of zero is returned inside replies.
 *
 * If "args" is not specified, then the command is assumed to have no arguments.
 *
 * If "size" is specified, then there should be "size" bytes of data after the
 * newline terminator sent along as well.
 */

// Represents a message that is to be sent to the client
typedef struct message_S message_T;
struct message_S
{
    uint32_t size;
    uint32_t remaining;
    message_T *next;
    connection_T *ct;
    bool popped;

    uint8_t data[1]; // Actually longer
};

#define BUFFER_SIZE 256

// Represents a connection to a client.
struct connection_S
{
    int refcount;

    int fd;

    // Ring buffer that stores incoming data.
    uint8_t buf[BUFFER_SIZE];
    ringbuffer_T rb;

    // Stores binary data that may come after the JSON message.
    array_T binary_data;
    uint32_t binary_remaining;
    bool binary; // true if we are receiving binary data.

    struct json_tokener *tokener;
    struct json_object *saved; // Only set when message has binary data attached
                               // to it.

    // Queue of pending messages waiting to be sent.
    message_T *queue;
    message_T *queue_end;

    bool sending; // true if we are writing a message to the connection

    connection_T *next;
};

static struct
{
    bool running;

    char *socket_path;
    char *lock_path;
    int lock_fd;

    int sock_fd;

    // Linked list of all open connections
    connection_T *connections;
} SERVER;

static bool socket_check_cb(int fd, int revents, void *udata);

/*
 * Create a lock file at the given path, and store its file descriptor in
 * "lock_fd". Returns OK on success and FAIL on failure.
 */
int
create_lock(const char *path, int *lock_fd)
{
    assert(path != NULL);
    assert(lock_fd != NULL);

    int fd = open(path, O_RDWR | O_CREAT);

    if (fd == -1)
    {
        wlip_warn("Error creating lock file '%s': %s", path, strerror(errno));
        return FAIL;
    }

    struct flock fl;

    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = fl.l_len = 0;

    if (fcntl(fd, F_SETLK, &fl) == -1)
    {
        wlip_warn("Error locking file '%s': %s", path, strerror(errno));
        close(fd);
        return FAIL;
    }

    *lock_fd = fd;
    return OK;
}

/*
 * Returns locking PID if file is locked, otherwise -1 if unlocked or if it
 * doesn't exist. Returns 0 if an error occured.
 */
pid_t
lock_is_locked(const char *path)
{
    assert(path != NULL);

    chmod(path, 0644);
    int fd = open(path, O_RDWR);

    if (fd == -1)
    {
        if (errno == ENOENT)
            return -1;
        else
        {
            wlip_warn("Failed opening file '%s': %s", path, strerror(errno));
            return 0;
        }
    }

    struct flock fl;
    int ret;

    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = fl.l_len = 0;

    ret = fcntl(fd, F_GETLK, &fl);
    close(fd);

    if (ret != -1)
        return fl.l_type == F_WRLCK ? fl.l_pid : -1;
    return 0;
}

/*
 * Initialize the server and start serving requests. Returns OK on success and
 * FAIL on failure.
 */
int
server_init(void)
{
    assert(!SERVER.running);

    const char *socket_env = getenv("WLIP_SOCK");

    char socket_path[PATH_MAX];
    char lock_path[PATH_MAX];

    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    addr.sun_family = AF_UNIX;

    if (socket_env != NULL)
    {
        wlip_snprintf(socket_path, PATH_MAX, "%s", socket_env);
        wlip_snprintf(lock_path, PATH_MAX, "%s.lock", socket_env);

        pid_t pid = lock_is_locked(lock_path);

        if (pid == 0)
            goto fail;
        else if (pid > 0)
        {
            wlip_error(
                "Socket path '%s' is in use by PID %d", socket_path, pid
            );
            goto fail;
        }
        wlip_snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        {
            wlip_error("Error binding to socket: %s", strerror(errno));
            goto fail;
        }
    }
    else
    {
        const char *display = getenv("WAYLAND_DISPLAY");
        const char *xdgruntime = getenv("XDG_RUNTIME_DIR");
        const char *socketdir_env = getenv("WLIP_SOCKDIR");
        char socketdir[PATH_MAX];

        assert(display != NULL);

        if (socketdir_env != NULL)
            wlip_snprintf(socketdir, PATH_MAX, "%s", socketdir_env);
        else if (xdgruntime != NULL)
            wlip_snprintf(socketdir, PATH_MAX, "%s", xdgruntime);
        else
            wlip_snprintf(socketdir, PATH_MAX, "/tmp");

        // Check if directory exists
        struct stat sb;

        if (stat(socketdir, &sb) == -1 || !S_ISDIR(sb.st_mode))
        {
            wlip_error("Socket directory '%s' does not ecist", socketdir);
            goto fail;
        }

        if (strrchr(display, '/') != NULL)
            display = strrchr(display, '/');

        bool found = false;

        // Increment a number until there is an available socket. If there is a
        // socket but it is dead (when the lock file is not locked), then it is
        // replaced.
        for (int i = 0; i < 1000; i++)
        {
            wlip_snprintf(
                socket_path, PATH_MAX, "%s/wlip.%s.%d", socketdir, display, i
            );
            wlip_snprintf(lock_path, PATH_MAX, "%s.lock", socket_path);

            // Check if lock file is not locked
            pid_t pid = lock_is_locked(lock_path);

            if (pid == 0)
                goto fail;
            else if (pid > 0)
                continue;
            else if (unlink(socket_path) == -1 && errno != ENOENT)
            {
                wlip_error(
                    "Error removing file '%s': %s", socket_path, strerror(errno)
                );
                goto fail;
            }

            wlip_snprintf(
                addr.sun_path, sizeof(addr.sun_path), "%s", socket_path
            );

            if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
            {
                if (errno != EADDRINUSE)
                {
                    wlip_error("Error binding to socket: %s", strerror(errno));
                    goto fail;
                }
                continue;
            }

            if (create_lock(lock_path, &SERVER.lock_fd) == FAIL)
                goto fail;

            found = true;
            break;
        }

        if (!found)
        {
            wlip_error("Cannot find an available socket name");
            goto fail;
        }
    }

    if (listen(fd, 5) == -1)
    {
        wlip_error("Error listening to socket: %s", strerror(errno));
        goto fail;
    }

    wlip_debug("Initialized server at '%s'", socket_path);

    SERVER.socket_path = wlip_strdup(socket_path);
    SERVER.lock_path = wlip_strdup(lock_path);

    SERVER.sock_fd = fd;
    SERVER.connections = NULL;
    SERVER.running = true;

    event_add_fd(SERVER.sock_fd, POLLIN, 0, NULL, socket_check_cb, NULL);

    return OK;
fail:
    close(fd);
    return FAIL;
}

static void connection_remove(connection_T *ct);

void
server_uninit(void)
{
    unlink(SERVER.socket_path);
    unlink(SERVER.lock_path);
    close(SERVER.lock_fd);

    close(SERVER.sock_fd); // Redundant but eh...
    event_remove_fd(SERVER.sock_fd);

    wlip_free(SERVER.socket_path);
    wlip_free(SERVER.lock_path);

    while (SERVER.connections != NULL)
        connection_remove(SERVER.connections);

    SERVER.running = false;
}

static connection_T *connection_ref(connection_T *ct);
static void connection_unref(connection_T *ct);

/*
 * Add a message to the end of the queue that is able to hold a message of
 * "size" bytes. Actual contents should be memcpy'd in manually right after.
 */
static message_T *
message_append(connection_T *ct, uint32_t size)
{
    assert(ct != NULL);

    message_T *msg = wlip_malloc(sizeof(*msg) + size - 1);

    msg->size = msg->remaining = size;
    msg->ct = ct;
    msg->next = NULL;
    msg->popped = false;

    if (ct->queue == NULL)
        ct->queue = msg;
    else
        ct->queue_end->next = msg;
    ct->queue_end = msg;
    return msg;
}

/*
 * Pop a message from the start of the queue. May return NULL.
 */
static message_T *
message_pop(connection_T *ct)
{
    assert(ct != NULL);

    if (ct->queue == NULL)
        return NULL;

    message_T *msg = ct->queue;

    ct->queue = msg->next;
    msg->popped = true;
    connection_ref(ct); // Must add reference, since connection may be closed
                        // later.
    if (msg == ct->queue_end)
        ct->queue_end = NULL;

    return msg;
}

static void
message_free(message_T *msg)
{
    if (msg->popped)
        connection_unref(msg->ct);
    wlip_free(msg);
}

/*
 * Add a new server connection to the list and return it
 */
static connection_T *
add_connection(int fd)
{
    assert(fd >= 0);

    connection_T *ct = wlip_calloc(1, sizeof(*ct));

    ct->refcount = 1;
    ct->fd = fd;
    ct->tokener = json_tokener_new();
    ringbuffer_init(&ct->rb, ct->buf, BUFFER_SIZE);

    if (ct->tokener == NULL)
    {
        fprintf(stderr, "json_tokener_new() fail: %s\n", strerror(errno));
        abort();
    }

    if (SERVER.connections == NULL)
        SERVER.connections = ct;
    else
        for (connection_T *c = SERVER.connections; c != NULL; c = c->next)
        {
            if (c->next == NULL)
            {
                c->next = ct;
                break;
            }
        }

    return ct;
}

/*
 * Remove a server connection from the list
 */
static void
connection_remove(connection_T *ct)
{
    assert(ct != NULL);

    connection_T *cur = SERVER.connections;
    connection_T *prev = NULL;

    while (cur != ct)
    {
        prev = cur;
        cur = cur->next;
    }

    if (prev != NULL)
        prev->next = cur->next;
    else
        SERVER.connections = NULL;

    message_T *msg;
    while ((msg = message_pop(ct)) != NULL)
        message_free(msg);

    json_tokener_free(cur->tokener);
    array_clear(&cur->binary_data);
    if (cur->saved != NULL)
        json_object_put(cur->saved);
    array_clear(&cur->binary_data);
    close(cur->fd);
    wlip_free(cur);
}

static connection_T *
connection_ref(connection_T *ct)
{
    assert(ct != NULL);
    ct->refcount++;
    return ct;
}

static void
connection_unref(connection_T *ct)
{
    assert(ct != NULL);
    if (--ct->refcount <= 0)
        connection_remove(ct);
}

static void connection_try_send(connection_T *ct);

static bool
message_check_cb(int fd, int revents, void *udata)
{
    message_T *msg = udata;

    if (revents == 0)
        return false;
    else if (revents & POLLOUT)
    {
        ssize_t w =
            write(fd, msg->data + (msg->size - msg->remaining), msg->remaining);

        if (w == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return false;
        else if (w >= 0)
        {
            msg->remaining -= w;
            if (msg->remaining > 0)
                return false;
            else
            {
                msg->ct->sending = false;

                // Check the next message in the queue
                connection_try_send(msg->ct);
                message_free(msg);
                return true;
            }
        }
    }
    // Connection lost
    message_free(msg);
    msg->ct->sending = false;
    return true;
}

/*
 * Try sending a message to the client if we aren't already and the queue has
 * stuff in it. If the queue is empty or we are already in the middle of sending
 * a message, then don't do anything.
 */
static void
connection_try_send(connection_T *ct)
{
    assert(ct != NULL);

    if (ct->sending || ct->queue == NULL)
        return;

    ct->sending = true;
    message_T *msg = message_pop(ct);

    event_add_fd(ct->fd, POLLOUT, 0, NULL, message_check_cb, msg);
}

/*
 * Send a reply to the client that this command comes from. "ret" may be NULL.
 * The reply will be in the format:
 * {
 *   "success": <true|false>,
 *   "serial": <int>
 *   "size": <int>,
 *   "value": ...
 * }
 *
 * If there is binary data attached, then "size" field is set. If "ret" is not
 * NULL, then the "value" field is set.
 *
 * Ownership of "ret" or "binary_data" is not taken.
 */
void
command_send_reply(
    command_T *cmd, bool success, struct json_object *ret,
    const uint8_t *binary_data, uint32_t binary_len
)
{
    assert(cmd != NULL);

    size_t json_len;
    const char *json = NULL;

    if (ret != NULL)
    {
        json = json_object_to_json_string_length(
            ret, JSON_C_TO_STRING_PLAIN, &json_len
        );
        WLIP_JSON_CHECK(json_object_to_json_string_length, json);
    }
    else
        json_len = 0;

    // Shouldn't ever happen but still check I guess
    if (json_len > UINT32_MAX)
        return;

    char fmt[100]; // Should be big enough
    char *start = fmt;

    start += sprintf(
        start, "{\"success\":%s,\"serial\":%" PRId64 "",
        success ? "true" : "false", cmd->serial
    );

    if (binary_data != NULL)
        start += sprintf(start, ",\"size\":%u", binary_len);
    if (ret != NULL)
        start += sprintf(start, ",\"value\":%%s");
    start += sprintf(start, "}");

    uint32_t len = start - fmt;

    message_T *msg = message_append(
        cmd->ct, len + json_len + 1 + (ret == NULL ? 0 : -2) +
                     (binary_data == NULL ? 0 : binary_len)
    );

    if (ret != NULL)
        len = sprintf((char *)msg->data, fmt, json);
    else
        len = sprintf((char *)msg->data, "%s", fmt);

    msg->data[len] = '\n';
    if (binary_data != NULL)
        memcpy(msg->data + len + 1, binary_data, binary_len);

    connection_try_send(cmd->ct);
}

/*
 * Create a command_T struct with the JSON message and execute the command.
 * "binary_data" may be NULL if there is no binary data attached. Ownership of
 * "binary_data" is taken.
 */
static void
do_command(
    connection_T *ct, struct json_object *root, uint8_t *binary_data,
    uint32_t binary_len
)
{
    assert(ct != NULL);
    assert(root != NULL);

    command_T cmd = {.binary = binary_data, .binary_len = binary_len, .ct = ct};

    struct json_object *j_name;
    struct json_object *j_args;
    struct json_object *j_serial;

    if (json_object_object_get_ex(root, "command", &j_name) &&
        json_object_is_type(j_name, json_type_string))
        cmd.name = json_object_get_string(j_name);
    else
        // Ignore message
        return;

    if (json_object_object_get_ex(root, "args", &j_args))
        cmd.args = j_args;
    else
        cmd.args = NULL;

    if (json_object_object_get_ex(root, "serial", &j_serial) &&
        json_object_is_type(j_serial, json_type_int))
        cmd.serial = json_object_get_int64(j_serial);
    else
        cmd.serial = 0;

    server_api_exec(&cmd);

    // If the command handler took ownership of the binary data, then
    // "cmd.binary" will be set to NULL.
    wlip_free(cmd.binary);
}

/*
 * Try reading the attached binary data into the array and execute command if
 * done. Return 1 if done reading, 0 if there is no binary data to be read, or
 * -1 if no -1 if read binary data.
 */
static int
try_read_binary_data(connection_T *ct)
{
    assert(ct != NULL);

    if (!ct->binary)
        return 0;

    const uint8_t *region1, *region2;
    uint32_t len1 = 0, len2 = 0;

    ringbuffer_get(&ct->rb, &region1, &len1, &region2, &len2);
    if (region1 == NULL)
        return 1;

    uint32_t consume = MIN(ct->binary_remaining, len1);

    ct->binary_remaining -= consume;
    array_add(&ct->binary_data, region1, consume);
    ringbuffer_consume(&ct->rb, consume);

    if (region2 != NULL)
    {
        consume = MIN(ct->binary_remaining, len2);
        ct->binary_remaining -= consume;
        array_add(&ct->binary_data, region2, consume);
        ringbuffer_consume(&ct->rb, consume);
    }

    if (ct->binary_remaining > 0)
        return -1;
    ct->binary = false;

    do_command(ct, ct->saved, ct->binary_data.data, ct->binary_data.len);
    json_object_put(ct->saved);

    ct->saved = NULL;
    ct->binary_data.data = NULL;

    return 1;
}

/*
 * Process the incoming data (which should be JSON). Returns true if a JSON
 * message was fully parsed.
 */
static bool
process_data(connection_T *ct)
{
    assert(ct != NULL);

    if (try_read_binary_data(ct) == -1)
        return true;

    const uint8_t *region1, *region2;
    uint32_t len1, len2;

    ringbuffer_get(&ct->rb, &region1, &len1, &region2, &len2);

    if (region1 == NULL)
        // Finished all messages in the buffer
        return false;

    enum json_tokener_error err;
    struct json_object *root = NULL;

    // Find newline if any, otherwise assume message is incomplete (wait for
    // more data).
    uint8_t *nl = memchr(region1, '\n', len1);

    if (nl == NULL)
    {
        // First region does not have a newline, just use the full length
        root = json_tokener_parse_ex(ct->tokener, (char *)region1, len1);

        ringbuffer_consume(&ct->rb, len1);
        err = json_tokener_get_error(ct->tokener);

        if (err == json_tokener_continue && region2 != NULL)
        {
            // Try region2 if it exists
            nl = memchr(region2, '\n', len2);

            if (nl == NULL)
            {
                root =
                    json_tokener_parse_ex(ct->tokener, (char *)region2, len2);
                ringbuffer_consume(&ct->rb, len2);
            }
            else
            {
                root = json_tokener_parse_ex(
                    ct->tokener, (char *)region2, nl - region2
                );
                // Add one to also consume newline
                ringbuffer_consume(&ct->rb, nl - region2 + 1);
            }
        }
    }
    else
    {
        // Found newline, finish parsing the message.
        root =
            json_tokener_parse_ex(ct->tokener, (char *)region1, nl - region1);
        ringbuffer_consume(&ct->rb, nl - region1 + 1);
    }

    if (nl == NULL && root == NULL)
        return false;

    err = json_tokener_get_error(ct->tokener);
    json_tokener_reset(ct->tokener);

    if (err != json_tokener_success)
    {
        if (err == json_tokener_continue)
            wlip_debug("Error parsing message: incomplete JSON string");
        else
        {
            const char *errmsg = json_tokener_error_desc(err);
            wlip_debug("Error parsing message: %s", errmsg);
        }
        return true;
    }

    struct json_object *j_size;

    // Check if there may be binary data attached to message
    if (json_object_object_get_ex(root, "size", &j_size) &&
        json_object_is_type(j_size, json_type_int))
    {
        int64_t sz = json_object_get_int64(j_size);

        // Check for overflow as well
        if (sz <= UINT32_MAX && sz > 0)
        {
            ct->binary_remaining = sz;
            ct->binary = true;
            ct->saved = root;
            array_init(&ct->binary_data, 1, 256);
            if (try_read_binary_data(ct))
                // Binary data fits into buffer, finalize the message now.
                return true;
            return false;
        }
    }

    do_command(ct, root, NULL, 0);
    json_object_put(root);

    return true;
}

/*
 * Called when there is stuff to be read in the socket connection.
 */
static bool
connection_check_cb(int fd, int revents, void *udata)
{
    connection_T *ct = udata;

    if (revents == 0)
        return false;
    else if (!(revents & POLLIN))
        // Connection closed.
        goto close;

    ssize_t ret = ringbuffer_read(&ct->rb, fd);

    if (ret == 0 || ret == -1)
        // Assume connection is closed. Note that if "ret" is 0, then it only
        // indicates that the read fd has been closed, write fd may still be
        // open.
        goto close;
    else if (ret == -2)
        // Shouldn't happen
        wlip_warn("Ring buffer is full?");

    // Process the buffer until empty
    while (process_data(ct))
        ;

    (void)message_append;

    return false;
close:
    connection_unref(ct);
    return true;
}

/*
 * Called when there is a new client
 */
static bool
socket_check_cb(int fd, int revents, void *udata UNUSED)
{
    if (revents == 0)
        return false;
    else if (!(revents & POLLIN))
    {
        wlip_debug("Error polling server socket");
        server_uninit();
        return true;
    }

    // Accept and create new connection
    int ct_fd = accept(fd, NULL, NULL);

    if (ct_fd == -1)
    {
        wlip_warn("Failed accepting client: %s", strerror(errno));
        return false;
    }

    // Make fd non blocking
    fcntl(ct_fd, F_SETFL, fcntl(ct_fd, F_GETFL, 0) | O_NONBLOCK);

    connection_T *ct = add_connection(ct_fd);
    event_add_fd(ct_fd, POLLIN, 0, NULL, connection_check_cb, ct);
    return false;
}

/* static int */
/* compare_command_name(const void *key, const void *member) */
/* { */
/*     return strcmp(key, ((command_T *)member)->name); */
/* } */

/* const char *command = json_string_value(j_command); */
/* command_T *cmd = bsearch( */
/*     command, COMMANDS, ARRAY_SIZE(COMMANDS), sizeof(command_T), */
/*     compare_command_name */
/* ); */

// vim: ts=4 sw=4 sts=4 et
