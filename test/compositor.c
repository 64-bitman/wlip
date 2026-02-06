#include "ext-data-control-v1_server.h"
#include "wlr-data-control-unstable-v1_server.h"
#include <assert.h>
#include <errno.h> // IWYU pragma: keep
#include <json.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wayland-server-core.h>

#define LOG(f, ...)                                                            \
    fprintf(stderr, "%s:%d: " f "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define ABORT(f, ...)                                                          \
    do                                                                         \
    {                                                                          \
        fprintf(                                                               \
            stderr, "%s:%d: fail: %s\n", __FILE__, __LINE__, strerror(errno)   \
        );                                                                     \
        abort();                                                               \
    } while (false)

#define ARRAY_SIZE(arr) ((int)(sizeof(arr) / sizeof(*arr)))

#ifdef __GNUC__
#    define UNUSED __attribute__((__unused__))
#else
#    define UNUSED
#endif

typedef struct
{
    struct wl_display *display;
    struct wl_event_loop *loop;

    struct wl_event_source *input_source;
    struct json_tokener *input_tokener;

    struct wl_global *ext_data_control_manager_v1;
    struct wl_global *zwlr_data_control_manager_v1;
    struct wl_list data_control_manager_clients;

    struct wl_list seats;
} compositor_T;

// Represents a seat object for a client on the server side.
typedef struct
{
    struct wl_resource *resource;
    struct wl_list link;
} wlseat_client_T;

// Represents a global for a seat on the server side
typedef struct
{
    char *name;
    uint32_t capabilities;

    struct wl_list clients;

    struct wl_global *global;
    struct wl_list link;
} wlseat_T;

typedef enum
{
    DATAPROTOCOL_EXT,
    DATAPROTOCOL_WLR
} dataprotocol_T;

// Represents an ext-data-control-manager-v1 or zwlr-data-control-manager-v1
// object on the server side for a client.
typedef struct
{
    struct wl_resource *resource;
    dataprotocol_T protocol;
    struct wl_list devices;
    struct wl_list link;
} datamanager_client_T;

// Represents a data device on the server side for a client
typedef struct
{
    struct wl_resource *resource;

    datamanager_client_T *manager;
    wlseat_client_T *seat;

    // Current data offers for each selection
    struct wl_resource *regular_offer;
    struct wl_resource *primary_offer;

    struct wl_list link;
} datadevice_client_T;

// Represetns a data source on the server side for a client
typedef struct
{
    struct wl_resource *resource;
    struct wl_array mime_types;
} datasource_client_T;

typedef void (*command_func_T)(compositor_T *c, struct json_object *root);

typedef struct
{
    const char *name;
    command_func_T func;
} command_T;

static void *
xmalloc(size_t sz)
{
    void *ptr = malloc(sz);
    if (ptr == NULL)
    {
        LOG("malloc(%zu) fail: %s", sz, strerror(errno));
        abort();
    }
    return ptr;
}

static void *
xcalloc(size_t n, size_t sz)
{
    void *ptr = calloc(n, sz);
    if (ptr == NULL)
    {
        LOG("calloc(%zu, %zu) fail: %s", n, sz, strerror(errno));
        abort();
    }
    return ptr;
}

static void
xfree(void *ptr)
{
    free(ptr);
}

static char *
xstrdup(const char *str)
{
    void *ptr = strdup(str);
    if (ptr == NULL)
    {
        LOG("strdup(\"%s\") fail: %s", str, strerror(errno));
        abort();
    }
    return ptr;
}

static int
signal_handler(int signo UNUSED, void *udata)
{
    compositor_T *c = udata;

    wl_display_terminate(c->display);
    LOG("Exiting...");
    return 0;
}

static void
wlseat_free(wlseat_T *seat)
{
    assert(seat != NULL);

    wl_list_remove(&seat->link);
    xfree(seat->name);
    wl_global_destroy(seat->global);
    xfree(seat);
}

static void
wlseat_client_destroy(struct wl_resource *resource)
{
    wlseat_client_T *seat_client = wl_resource_get_user_data(resource);

    wl_list_remove(&seat_client->link);
    xfree(seat_client);
}

static void
handle_wl_seat_get_keyboard(
    struct wl_client *client UNUSED, struct wl_resource *resource,
    uint32_t id UNUSED
)
{
    wl_resource_post_error(
        resource, WL_SEAT_ERROR_MISSING_CAPABILITY,
        "wl_seat missing keyboard capability"
    );
}

static void
handle_wl_seat_get_pointer(
    struct wl_client *client UNUSED, struct wl_resource *resource,
    uint32_t id UNUSED
)
{
    wl_resource_post_error(
        resource, WL_SEAT_ERROR_MISSING_CAPABILITY,
        "wl_seat missing pointer capability"
    );
}

static void
handle_wl_seat_get_touch(
    struct wl_client *client UNUSED, struct wl_resource *resource,
    uint32_t id UNUSED
)
{
    wl_resource_post_error(
        resource, WL_SEAT_ERROR_MISSING_CAPABILITY,
        "wl_seat missing touch capability"
    );
}

static void
handle_wl_seat_release(
    struct wl_client *client UNUSED, struct wl_resource *resource
)
{
    wl_resource_destroy(resource);
}

static const struct wl_seat_interface wl_seat_implementation = {
    .get_keyboard = handle_wl_seat_get_keyboard,
    .get_pointer = handle_wl_seat_get_pointer,
    .get_touch = handle_wl_seat_get_touch,
    .release = handle_wl_seat_release,
};

static void
bind_wl_seat(
    struct wl_client *client, void *data, uint32_t version, uint32_t id
)
{
    wlseat_T *seat = data;
    wlseat_client_T *seat_client = xmalloc(sizeof(*seat_client));

    seat_client->resource =
        wl_resource_create(client, &wl_seat_interface, version, id);
    if (seat_client->resource == NULL)
        ABORT();

    wl_resource_set_implementation(
        seat_client->resource, &wl_seat_implementation, seat_client,
        wlseat_client_destroy
    );

    wl_list_init(&seat_client->link);
    wl_list_insert(&seat->clients, &seat_client->link);

    wl_seat_send_capabilities(seat_client->resource, seat->capabilities);
    wl_seat_send_name(seat_client->resource, seat->name);

    LOG("New client for seat '%s'", seat->name);
}

/*
 * Command: "SeatAdd"
 *
 * Add a new seat with the given name and capabilites (as a bitmask).
 * Args:
 *
 * "name": Name of seat
 */
static void
command_seatadd(compositor_T *c, struct json_object *root)
{
    struct json_object *j_name;
    const char *name;

    if (!json_object_object_get_ex(root, "name", &j_name) ||
        !json_object_is_type(j_name, json_type_string))
    {
        LOG("'name' argument not provided or not a string");
        return;
    }
    else
        name = json_object_get_string(j_name);

    wlseat_T *seat = xmalloc(sizeof(*seat));

    seat->name = xstrdup(name);
    seat->global =
        wl_global_create(c->display, &wl_seat_interface, 5, seat, bind_wl_seat);
    if (seat->global == NULL)
        ABORT();
    seat->capabilities = 0;
    wl_list_init(&seat->link);
    wl_list_init(&seat->clients);
    wl_list_insert(&c->seats, &seat->link);
}

static void
datadevice_client_T_destroy(struct wl_resource *resource)
{
    datadevice_client_T *device_client = wl_resource_get_user_data(resource);

    if (device_client->manager->protocol == DATAPROTOCOL_EXT)
        ext_data_control_device_v1_send_finished(device_client->resource);
    else if (device_client->manager->protocol == DATAPROTOCOL_WLR)
        ext_data_control_device_v1_send_finished(device_client->resource);
    else
        ABORT();

    if (device_client->regular_offer != NULL)
        wl_resource_destroy(device_client->regular_offer);
    if (device_client->primary_offer != NULL)
        wl_resource_destroy(device_client->primary_offer);

    wl_list_remove(&device_client->link);
}

static void
datamanager_client_destroy(struct wl_resource *resource)
{
    datamanager_client_T *manager_client = wl_resource_get_user_data(resource);

    wl_list_remove(&manager_client->link);

    datadevice_client_T *device_client, *tmp;
    wl_list_for_each_safe(device_client, tmp, &manager_client->devices, link) {
        wl_list_remove(&device_client->link);
    }
    xfree(manager_client);
}

static const struct ext_data_control_device_v1_interface
    ext_data_control_device_v1_implementation = {
        .set_selection = NULL,
        .set_primary_selection = NULL,
        .destroy = NULL,
};

static void
handle_data_control_manager_v1_get_data_device(
    struct wl_client *client, struct wl_resource *resource, uint32_t id,
    struct wl_resource *seat_resource
)
{
    datamanager_client_T *manager_client = wl_resource_get_user_data(resource);
    wlseat_client_T *seat_client = wl_resource_get_user_data(seat_resource);

    uint32_t version = wl_resource_get_version(manager_client->resource);
    datadevice_client_T *device_client = xcalloc(1, sizeof(*device_client));

    device_client->manager = manager_client;
    device_client->seat = seat_client;
    wl_list_init(&device_client->link);

    if (manager_client->protocol == DATAPROTOCOL_EXT)
    {
        device_client->resource = wl_resource_create(
            client, &ext_data_control_device_v1_interface, version, id
        );
        if (device_client->resource == NULL)
            ABORT();
        wl_resource_set_implementation(
            device_client->resource, &ext_data_control_device_v1_implementation,
            device_client, datadevice_client_T_destroy
        );
    }
    else if (manager_client->protocol == DATAPROTOCOL_WLR)
    {
        device_client->resource = wl_resource_create(
            client, &zwlr_data_control_device_v1_interface, version, id
        );
        if (device_client->resource == NULL)
            ABORT();
    }
    wl_list_insert(&manager_client->devices, &device_client->link);
}

static void
handle_data_control_manager_v1_create_data_source(
    struct wl_client *client, struct wl_resource *resource, uint32_t id
)
{
    (void)client;
    (void)resource;
    (void)id;
}

static const struct ext_data_control_manager_v1_interface
    ext_data_control_manager_v1_implementation = {
        .get_data_device = handle_data_control_manager_v1_get_data_device,
        .create_data_source = handle_data_control_manager_v1_create_data_source,
        .destroy = NULL
};

static void
bind_ext_data_control_manager_v1(
    struct wl_client *client, void *data, uint32_t version, uint32_t id
)
{
    compositor_T *c = data;

    datamanager_client_T *manager_client = xmalloc(sizeof(*manager_client));

    manager_client->resource = wl_resource_create(
        client, &ext_data_control_manager_v1_interface, version, id
    );
    if (manager_client->resource == NULL)
        // Honestly we don't need to check for out of memory but why not
        ABORT();

    wl_resource_set_implementation(
        manager_client->resource, &ext_data_control_manager_v1_implementation,
        manager_client, datamanager_client_destroy
    );

    wl_list_init(&manager_client->link);
    wl_list_init(&manager_client->devices);
    wl_list_insert(&c->data_control_manager_clients, &manager_client->link);

    LOG("New client for ext_data_control_manager_v1");
}

/*
 * Command: "DataControlAdd"
 *
 * Create a new data control manager global.
 * Args:
 *
 * "protocol": <ext|wlr>
 */
static void
command_datacontroladd(compositor_T *c, struct json_object *root)
{

    struct json_object *j_protocol;
    const char *protocol;

    if (!json_object_object_get_ex(root, "protocol", &j_protocol) ||
        !json_object_is_type(j_protocol, json_type_string))
    {
        LOG("'protocol' argument not provided or not a string");
        return;
    }
    else
        protocol = json_object_get_string(j_protocol);

    if (strcmp(protocol, "ext") == 0 && c->ext_data_control_manager_v1 == NULL)
    {
        c->ext_data_control_manager_v1 = wl_global_create(
            c->display, &ext_data_control_manager_v1_interface, 1, &c,
            bind_ext_data_control_manager_v1
        );
        if (c->ext_data_control_manager_v1 == NULL)
            ABORT();
    }
    else if (strcmp(protocol, "wlr") == 0 &&
             c->zwlr_data_control_manager_v1 == NULL)
    {
        // TODO:
        if (c->zwlr_data_control_manager_v1 == NULL)
            ABORT();
    }
    else
        LOG("Data control protocol '%s' does not exist or is already added",
            protocol);
}

/*
 * Command format:
 * {
 *   "command": <command name>,
 *   ...arguments...
 * }
 *
 * Commands are newline terminated
 */
static int
input_handler(int fd, uint32_t revents, void *udata)
{
    compositor_T *c = udata;
    struct json_tokener *tk = c->input_tokener;
    struct json_object *root;

    // Read one character at a time. Probably slow but who cares.
    if (revents & WL_EVENT_READABLE)
    {
        static char buf[1];

        if (read(fd, buf, 1) != 1)
            return 0;

        root = json_tokener_parse_ex(tk, buf, 1);

        if (root == NULL)
        {
            if (json_tokener_get_error(tk) != json_tokener_continue)
            {
                LOG("Invalid input");
                json_tokener_reset(tk);
            }
            // Wait for more input
            return 0;
        }
    }
    else if (revents & WL_EVENT_HANGUP)
    {
        wl_event_source_remove(c->input_source);
        c->input_source = NULL;
        return 0;
    }
    else
        return 0;

    static const command_T commands[] = {
        {"SeatAdd", command_seatadd}, {"DataControlAdd", command_datacontroladd}
    };

    struct json_object *j_command;
    const char *command;

    if (!json_object_object_get_ex(root, "command", &j_command) ||
        !json_object_is_type(j_command, json_type_string))
    {
        LOG("'command' argument not provided or not a string");
        goto exit;
    }
    else
        command = json_object_get_string(j_command);

    bool found = false;

    for (int i = 0; i < ARRAY_SIZE(commands); i++)
    {
        const command_T *cmd = commands + i;

        if (strcmp(cmd->name, command) == 0)
        {
            LOG("Executing command '%s'", cmd->name);
            cmd->func(c, root);
            found = true;
            break;
        }
    }

    if (!found)
        LOG("Command '%s' does not exist", command);

exit:
    json_object_put(root);
    json_tokener_reset(tk);

    return 0;
}

int
main(int argc, char **argv)
{
    if (argc != 2)
    {
        LOG("Display name must be provided");
        return EXIT_FAILURE;
    }

    const char *displayname = argv[1];

    compositor_T c = {0};

    c.display = wl_display_create();
    c.loop = wl_display_get_event_loop(c.display);
    if (wl_display_add_socket(c.display, displayname) == -1)
    {
        LOG("Failed creating socket '%s'", displayname);
        return EXIT_FAILURE;
    }

    c.input_tokener = json_tokener_new();

    wl_list_init(&c.seats);
    wl_list_init(&c.data_control_manager_clients);

    // Add signal handlers for SIGINT and SIGTERM for a clean exit.
    struct wl_event_source *sigint_source =
        wl_event_loop_add_signal(c.loop, SIGINT, signal_handler, &c);
    struct wl_event_source *sigterm_source =
        wl_event_loop_add_signal(c.loop, SIGTERM, signal_handler, &c);

    // Add source for stdin to watch for any commands.
    c.input_source = wl_event_loop_add_fd(
        c.loop, STDIN_FILENO, WL_EVENT_READABLE, input_handler, &c
    );

    wl_display_run(c.display);

    // Free all seats
    wlseat_T *seat, *tmp;
    wl_list_for_each_safe(seat, tmp, &c.seats, link) wlseat_free(seat);

    wl_event_source_remove(sigint_source);
    wl_event_source_remove(sigterm_source);
    if (c.input_source != NULL)
        wl_event_source_remove(c.input_source);

    wl_display_destroy_clients(c.display);
    wl_display_destroy(c.display);

    json_tokener_free(c.input_tokener);

    return EXIT_SUCCESS;
}
