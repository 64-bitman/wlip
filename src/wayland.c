#include "wayland.h"
#include "alloc.h"
#include "clipboard.h"
#include "ext-data-control-v1.h"
#include "hashtable.h"
#include "util.h"
#include "wlr-data-control-unstable-v1.h"
#include <assert.h>
#include <stdlib.h>
#include <uv.h>
#include <wayland-client.h>

#define DESTROY_DEVICE(d)                                                      \
    do                                                                         \
    {                                                                          \
        if (d == NULL)                                                         \
            break;                                                             \
        if (CONNECTION.protocol == DATA_PROTOCOL_EXT)                          \
            ext_data_control_device_v1_destroy(d);                             \
        else                                                                   \
            zwlr_data_control_device_v1_destroy(d);                            \
    } while (false)
#define DESTROY_SOURCE(s)                                                      \
    do                                                                         \
    {                                                                          \
        if (s == NULL)                                                         \
            break;                                                             \
        if (CONNECTION.protocol == DATA_PROTOCOL_EXT)                          \
            ext_data_control_source_v1_destroy(s);                             \
        else                                                                   \
            zwlr_data_control_source_v1_destroy(s);                            \
    } while (false)
#define DESTROY_OFFER(o)                                                       \
    do                                                                         \
    {                                                                          \
        if (o == NULL)                                                         \
            break;                                                             \
        if (CONNECTION.protocol == DATA_PROTOCOL_EXT)                          \
            ext_data_control_offer_v1_destroy(o);                              \
        else                                                                   \
            zwlr_data_control_offer_v1_destroy(o);                             \
    } while (false)

typedef struct
{
    // Unique identifier for selection. If -1, then selection is not available.
    int id;

    // Current data source, NULL if not the source client.
    union
    {
        struct ext_data_control_source_v1 *ext;
        struct zwlr_data_control_source_v1 *wlr;
        void *dummy;
    } source;

    // Current data offer
    union
    {
        struct ext_data_control_offer_v1 *ext;
        struct zwlr_data_control_offer_v1 *wlr;
        void *dummy;
    } offer;

    // Clipboard that this selection is attached to. May be NULL.
    clipboard_T *clipboard;
} wlselection_T;

typedef struct
{
    struct wl_seat *proxy;

    uint32_t capabilities;
    uint32_t numerical_name;

    union
    {
        struct ext_data_control_device_v1 *ext;
        struct zwlr_data_control_device_v1 *wlr;
        void *dummy;
    } device;

    wlselection_T regular;
    wlselection_T primary;

    char name[1]; // Actually longer (name of the seat).
} wlseat_T;

typedef enum
{
    DATA_PROTOCOL_NONE,
    DATA_PROTOCOL_EXT,
    DATA_PROTOCOL_WLR,
    DATA_PROTOCOL_WLR1, // Does not support primary selection
} dataprotocol_T;

// Global singleton state
static struct
{
    struct wl_display *display; // If NULL, then not connected.
    char *display_name;
    struct wl_registry *registry;

    // Global object proxies
    struct
    {
        hashtable_T seats;

        union
        {
            struct ext_data_control_manager_v1 *ext;
            struct zwlr_data_control_manager_v1 *wlr;
        } dac;
    } globals;

    // If we have called wl_display_prepare_read()
    bool reading;

    dataprotocol_T protocol;

    uv_loop_t *loop;
    uv_poll_t poll;
    uv_prepare_t prepare;
} CONNECTION;

// Timer used when connection is lost, checks every second to see if display is
// available again.
static uv_timer_t WATCH_TIMER;
static char *SAVED_DISPLAY; // Previous display name

static void registry_listener_event_global(
    void *data, struct wl_registry *registry, uint32_t name,
    const char *interface, uint32_t version
);
static void registry_listener_event_global_remove(
    void *data, struct wl_registry *registry, uint32_t name
);

static const struct wl_registry_listener registry_listener = {
    .global = registry_listener_event_global,
    .global_remove = registry_listener_event_global_remove
};

static void
wl_seat_listener_event_name(
    void *data, struct wl_seat *proxy UNUSED, const char *name
)
{
    wlseat_T **seat = data;

    *seat = realloc(*seat, sizeof(wlseat_T) + STRLEN(name));
    sprintf((*seat)->name, "%s", name);
}

static void
wl_seat_listener_event_capabilities(
    void *data, struct wl_seat *proxy UNUSED, uint32_t capabilities
)
{
    wlseat_T **seat = data;
    (*seat)->capabilities = capabilities;
}

static const struct wl_seat_listener wl_seat_listener = {
    .name = wl_seat_listener_event_name,
    .capabilities = wl_seat_listener_event_capabilities
};

/*
 * Allocate a new wlseat_T using the given seat proxy, and initialize
 * selections.
 */
static void
wlseat_new(struct wl_seat *proxy, uint32_t name)
{
    assert(proxy != NULL);

    // Create a new wlseat_T object and add it to the table. We will realloc
    // later to larger size to fit name.
    wlseat_T *seat = wlip_calloc(1, sizeof(wlseat_T));

    wl_seat_add_listener(proxy, &wl_seat_listener, &seat);
    wl_display_roundtrip(CONNECTION.display);

    seat->proxy = proxy;
    seat->numerical_name = name;

    wlip_debug("New seat '%s'", seat->name);

    hash_T hash = hash_get(seat->name);
    hashbucket_T *b =
        hashtable_lookup(&CONNECTION.globals.seats, seat->name, hash);

    assert(HB_ISEMPTY(b));
    hashtable_add(&CONNECTION.globals.seats, b, seat->name, hash);

    // Create data device
    if (CONNECTION.protocol == DATA_PROTOCOL_EXT)
        seat->device.ext = ext_data_control_manager_v1_get_data_device(
            CONNECTION.globals.dac.ext, proxy
        );
    else
        seat->device.wlr = zwlr_data_control_manager_v1_get_data_device(
            CONNECTION.globals.dac.wlr, proxy
        );

    static int id;

    seat->regular.id = ++id;

    // If we are using the
}

static void
wlseat_destroy(wlseat_T *seat)
{
    assert(seat != NULL);

    if (seat->device.dummy != NULL)
        DESTROY_DEVICE(seat->device.dummy);

    if (wl_seat_get_version(seat->proxy) >= 5)
        wl_seat_release(seat->proxy);
    else
        wl_seat_destroy(seat->proxy);

    wlip_free(seat);
}

static void
watch_timer_cb(uv_timer_t *handle)
{
    if (wayland_init(
            uv_handle_get_loop((uv_handle_t *)handle), SAVED_DISPLAY, NULL
        ) == OK)
    {
        wlip_debug("Connection to display '%s' back online", SAVED_DISPLAY);
        uv_timer_stop(handle);
        uv_close((uv_handle_t *)handle, NULL);
        wlip_free(SAVED_DISPLAY);
    }
}

static void
wayland_poll_cb(uv_poll_t *handle UNUSED, int status, int events)
{
    if (status < 0)
    {
        wlip_log("%s", uv_strerror(status));
        exit(1);
    }

    if (!CONNECTION.reading)
    {
        while (wl_display_prepare_read(CONNECTION.display) != 0)
            // Still more events to dispatch
            wl_display_dispatch_pending(CONNECTION.display);

        if (wl_display_flush(CONNECTION.display) == -1 && errno != EAGAIN)
            goto exit;
        CONNECTION.reading = true;
    }

    if (events & UV_READABLE)
    {
        if (wl_display_read_events(CONNECTION.display) == -1)
            goto exit;
        else
            CONNECTION.reading = false;
    }

    wl_display_dispatch_pending(CONNECTION.display);

    return;
exit:
    wlip_debug(
        "Connection to display '%s' lost, waiting for to be online again...",
        CONNECTION.display_name
    );

    // Create a timer that polls the display name every second
    uv_timer_init(CONNECTION.loop, &WATCH_TIMER);
    uv_timer_start(&WATCH_TIMER, watch_timer_cb, 1000, 1000);
    SAVED_DISPLAY = wlip_strdup(CONNECTION.display_name);
    wayland_uninit();
}

/*
 * Initialize the Wayland connection using the given display and attach it to
 * the event loop. If "display" is NULL, then libwayland chooses it. Returns OK
 * on success and FAIL on failure.
 */
int
wayland_init(uv_loop_t *loop, const char *display, error_T *error)
{
    assert(loop != NULL);
    assert(CONNECTION.display == NULL);

    const char *name = display == NULL ? getenv("WAYLAND_DISPLAY") : display;

    CONNECTION.display = wl_display_connect(display);
    if (CONNECTION.display == NULL)
    {
        error_set(
            error, ERROR_CONNECT, "Failed connecting to display '%s'", name
        );
        return FAIL;
    }

    if (name == NULL)
        name = "(unknown)";

    wlip_debug("Connected to display '%s'", name);

    CONNECTION.display_name = wlip_strdup(name);
    CONNECTION.registry = wl_display_get_registry(CONNECTION.display);
    CONNECTION.protocol = DATA_PROTOCOL_NONE;

    hashtable_init(&CONNECTION.globals.seats);

    wl_registry_add_listener(CONNECTION.registry, &registry_listener, NULL);
    wl_display_roundtrip(CONNECTION.display);

    CONNECTION.reading = false;
    uv_poll_init(loop, &CONNECTION.poll, wl_display_get_fd(CONNECTION.display));
    uv_poll_start(&CONNECTION.poll, UV_READABLE, wayland_poll_cb);

    uv_prepare_init(loop, &CONNECTION.prepare);
    uv_prepare_start(&CONNECTION.prepare, NULL);

    CONNECTION.loop = loop;

    return OK;
}

/*
 * If "check" is TRUE, then do not free the display name or the uv_loop_t it
 * that was being used.
 */
void
wayland_uninit(void)
{
    if (CONNECTION.display == NULL)
        return;

    uv_poll_stop(&CONNECTION.poll);
    uv_close((uv_handle_t *)&CONNECTION.poll, NULL);

    if (CONNECTION.protocol == DATA_PROTOCOL_EXT)
        ext_data_control_manager_v1_destroy(CONNECTION.globals.dac.ext);
    else
        zwlr_data_control_manager_v1_destroy(CONNECTION.globals.dac.wlr);

    hashtable_clear_func(
        &CONNECTION.globals.seats, (hb_free_func)wlseat_destroy,
        offsetof(wlseat_T, name)
    );

    wl_registry_destroy(CONNECTION.registry);
    wl_display_disconnect(CONNECTION.display);
    CONNECTION.display = NULL;

    wlip_free(CONNECTION.display_name);
}

static void
registry_listener_event_global(
    void *data UNUSED, struct wl_registry *registry UNUSED, uint32_t name,
    const char *interface, uint32_t version
)
{
    if (strcmp(interface, ext_data_control_manager_v1_interface.name) == 0)
    {
        if (CONNECTION.protocol != DATA_PROTOCOL_NONE)
        {
            wlip_debug("Discarding wlr data control protocol");
            zwlr_data_control_manager_v1_destroy(CONNECTION.globals.dac.wlr);
        }

        CONNECTION.globals.dac.ext = wl_registry_bind(
            registry, name, &ext_data_control_manager_v1_interface, 1
        );
        CONNECTION.protocol = DATA_PROTOCOL_EXT;
        wlip_debug("Using ext data control version %u", version);
    }
    // If we already have ext-data-control, then just ignore.
    else if (CONNECTION.protocol == DATA_PROTOCOL_NONE &&
             strcmp(interface, zwlr_data_control_manager_v1_interface.name) ==
                 0)
    {
        CONNECTION.globals.dac.wlr = wl_registry_bind(
            registry, name, &zwlr_data_control_manager_v1_interface,
            version > 2 ? 2 : version
        );
        CONNECTION.protocol =
            version >= 2 ? DATA_PROTOCOL_WLR : DATA_PROTOCOL_WLR1;

        wlip_debug("Using wlr data control version %u", version);
    }
    else if (strcmp(interface, wl_seat_interface.name) == 0)
    {
        struct wl_seat *proxy = wl_registry_bind(
            registry, name, &wl_seat_interface, version > 5 ? 5 : version
        );
        wlseat_new(proxy, name);
    }
}

/*
 * Only handle when the global is a seat. Otherwise don't do anything in order
 * to avoid race conditions, any operations on the removed global will be
 * ignored by the compositor anyways.
 */
static void
registry_listener_event_global_remove(
    void *data UNUSED, struct wl_registry *registry UNUSED, uint32_t name
)
{
    // Only handle if the global removed is a seat. For other globals just let
    // them be (the compositor will ignore any requests from them anyways).

    hashtableiter_T iter = HASHTABLEITER_INIT(&CONNECTION.globals.seats);
    wlseat_T *seat;

    while ((seat = hashtableiter_next(&iter, offsetof(wlseat_T, name))) != NULL)
        if (seat->numerical_name == name)
        {
            hashtableiter_remove(&iter);
            wlseat_destroy(seat);
            return;
        }
}

// vim: ts=4 sw=4 sts=4 et
