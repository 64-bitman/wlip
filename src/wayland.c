#include "wayland.h"
#include "alloc.h"
#include "clipboard.h"
#include "ext-data-control-v1.h"
#include "hashtable.h"
#include "util.h"
#include "wlr-data-control-unstable-v1.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
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
    // Unique identifier for selection.
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

typedef struct wlseat_S
{
    struct wl_seat *proxy;

    uint32_t capabilities;
    uint32_t numerical_name;

    bool started;

    // May be NULL in case finished event is received.
    union
    {
        struct ext_data_control_device_v1 *ext;
        struct zwlr_data_control_device_v1 *wlr;
        void *dummy;
    } device;

    // Table of mime types for the current data offer event if any
    hashtable_T mime_types;

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

// Global singleton state for display connection
static struct
{
    struct wl_display *display; // If NULL, then not connected.
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

    dataprotocol_T protocol;
} CONNECTION;

/*
 * WL_REGISTRY EVENT CALLBACKS
 */
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

/*
 * DATA_DEVICE EVENT CALLBACKS
 */
static void ext_device_listener_event_data_offer(
    void *data, struct ext_data_control_device_v1 *device UNUSED,
    struct ext_data_control_offer_v1 *offer
);
static void wlr_device_listener_event_data_offer(
    void *data, struct zwlr_data_control_device_v1 *device UNUSED,
    struct zwlr_data_control_offer_v1 *offer
);

static void ext_device_listener_event_selection(
    void *data, struct ext_data_control_device_v1 *device UNUSED,
    struct ext_data_control_offer_v1 *offer
);
static void wlr_device_listener_event_selection(
    void *data, struct zwlr_data_control_device_v1 *device UNUSED,
    struct zwlr_data_control_offer_v1 *offer
);

static void ext_device_listener_event_primary_selection(
    void *data, struct ext_data_control_device_v1 *device UNUSED,
    struct ext_data_control_offer_v1 *offer
);
static void wlr_device_listener_event_primary_selection(
    void *data, struct zwlr_data_control_device_v1 *device UNUSED,
    struct zwlr_data_control_offer_v1 *offer
);

static void ext_device_listener_event_finished(
    void *data, struct ext_data_control_device_v1 *device UNUSED
);
static void wlr_device_listener_event_finished(
    void *data, struct zwlr_data_control_device_v1 *device UNUSED
);

static const struct ext_data_control_device_v1_listener ext_device_listener = {
    .data_offer = ext_device_listener_event_data_offer,
    .selection = ext_device_listener_event_selection,
    .primary_selection = ext_device_listener_event_primary_selection,
    .finished = ext_device_listener_event_finished
};
static const struct zwlr_data_control_device_v1_listener wlr_device_listener = {
    .data_offer = wlr_device_listener_event_data_offer,
    .selection = wlr_device_listener_event_selection,
    .primary_selection = wlr_device_listener_event_primary_selection,
    .finished = wlr_device_listener_event_finished
};

/*
 * Get the specified wlselectioN_T with the given type from "seat".
 */
static wlselection_T *
wlselection_get(wlseat_T *seat, wlselection_type_T type)
{
    assert(seat != NULL);

    if (type == WLSELECTION_TYPE_REGULAR)
        return &seat->regular;
    else if (type == WLSELECTION_TYPE_PRIMARY)
        return &seat->primary;
    // Shouldn't happen
    abort();
}

/*
 * Convert selection type to a string.
 */
static const char *
wlselection_str(wlselection_type_T type)
{
    if (type == WLSELECTION_TYPE_REGULAR)
        return "regular";
    else if (type == WLSELECTION_TYPE_PRIMARY)
        return "primary";
    abort();
}

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
    hashtable_init(&seat->mime_types);

    wlip_debug("New seat '%s'", seat->name);

    hash_T hash = hash_get(seat->name);
    hashbucket_T *b =
        hashtable_lookup(&CONNECTION.globals.seats, seat->name, hash);

    assert(HB_ISEMPTY(b));
    hashtable_add(&CONNECTION.globals.seats, b, seat->name, hash);

    static int id;
    seat->regular.id = ++id;
    seat->primary.id = ++id;
}

/*
 * Start listening for events from the given Wayland seat.
 */
static void
wlseat_start(wlseat_T *seat)
{
    assert(seat != NULL);

    if (seat->started)
        return;
    seat->started = true;

    // Create data device and start listening for events
    if (CONNECTION.protocol == DATA_PROTOCOL_EXT)
    {
        seat->device.ext = ext_data_control_manager_v1_get_data_device(
            CONNECTION.globals.dac.ext, seat->proxy
        );
        ext_data_control_device_v1_add_listener(
            seat->device.ext, &ext_device_listener, seat
        );
    }
    else
    {
        seat->device.wlr = zwlr_data_control_manager_v1_get_data_device(
            CONNECTION.globals.dac.wlr, seat->proxy
        );
        zwlr_data_control_device_v1_add_listener(
            seat->device.wlr, &wlr_device_listener, seat
        );
    }
}

/*
 * Get the wlseat_T with the given name and start it (start listening for
 * events). Return NULL if seat doesn't exist.
 */
wlseat_T *
wayland_get_seat(const char *name)
{
    assert(name != NULL);

    hashbucket_T *b =
        hashtable_lookup(&CONNECTION.globals.seats, name, hash_get(name));

    if (HB_ISEMPTY(b))
        return NULL;

    wlseat_T *seat = HB_GET(b, wlseat_T, name);

    return seat;
}

/*
 * Attach the selection from the seat to the given clipboard. Additionally also
 * start the seat as well if it isn't (start listening for events)
 *
 * TODO: support updating the clipboard?
 */
void
wayland_attach_selection(
    wlseat_T *seat, wlselection_type_T type, clipboard_T *cb
)
{
    assert(seat != NULL);

    wlselection_T *sel = wlselection_get(seat, type);
    sel->clipboard = cb;

    wlseat_start(seat);
}

static void
wlseat_destroy(wlseat_T *seat)
{
    assert(seat != NULL);

    if (seat->device.dummy != NULL)
        DESTROY_DEVICE(seat->device.dummy);

    DESTROY_SOURCE(seat->regular.source.dummy);
    DESTROY_OFFER(seat->regular.offer.dummy);

    DESTROY_SOURCE(seat->primary.source.dummy);
    DESTROY_OFFER(seat->primary.offer.dummy);

    if (wl_seat_get_version(seat->proxy) >= 5)
        wl_seat_release(seat->proxy);
    else
        wl_seat_destroy(seat->proxy);

    hashtable_clear(&seat->mime_types);
    wlip_free(seat);
}

/*
 * Initialize the Wayland connection using the given display and attach it to
 * the event loop. If "display" is NULL, then libwayland chooses it. Returns OK
 * on success and FAIL on failure.
 */
int
wayland_init(const char *display, error_T *error)
{
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

    CONNECTION.registry = wl_display_get_registry(CONNECTION.display);
    CONNECTION.protocol = DATA_PROTOCOL_NONE;

    hashtable_init(&CONNECTION.globals.seats);

    wl_registry_add_listener(CONNECTION.registry, &registry_listener, NULL);
    wl_display_roundtrip(CONNECTION.display);

    return OK;
}

/*
 * Get the Wayland display file descriptor. Returns -1 if not connected.
 */
int
wayland_get_fd(void)
{
    return CONNECTION.display == NULL ? -1
                                      : wl_display_get_fd(CONNECTION.display);
}

/*
 * Get the Wayland display proxy. Returns NULL if not connected.
 */
struct wl_display *
wayland_get_display(void)
{
    return CONNECTION.display;
}

void
wayland_uninit(void)
{
    if (CONNECTION.display == NULL)
        return;

    if (CONNECTION.protocol == DATA_PROTOCOL_EXT)
        ext_data_control_manager_v1_destroy(CONNECTION.globals.dac.ext);
    else
        zwlr_data_control_manager_v1_destroy(CONNECTION.globals.dac.wlr);

    hashtable_clear_func(
        &CONNECTION.globals.seats, (hb_freefunc_T)wlseat_destroy,
        offsetof(wlseat_T, name)
    );

    wl_registry_destroy(CONNECTION.registry);
    wl_display_disconnect(CONNECTION.display);
    CONNECTION.display = NULL;
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

/*
 * Common handler for data offer "offer" event.
 */
static void
offer_listener_event_offer(wlseat_T *seat, const char *mime_type)
{
    assert(seat != NULL);
    assert(mime_type != NULL);

    hash_T hash = hash_get(mime_type);
    hashbucket_T *b = hashtable_lookup(&seat->mime_types, mime_type, hash);

    if (!HB_ISEMPTY(b))
        // Shouldn't happen?
        return;

    hashtable_add(&seat->mime_types, b, wlip_strdup(mime_type), hash);
}
static void
ext_offer_listener_event_offer(
    void *data, struct ext_data_control_offer_v1 *offer UNUSED,
    const char *mime_type
)
{
    offer_listener_event_offer(data, mime_type);
}
static void
wlr_offer_listener_event_offer(
    void *data, struct zwlr_data_control_offer_v1 *offer UNUSED,
    const char *mime_type
)
{
    offer_listener_event_offer(data, mime_type);
}

static const struct ext_data_control_offer_v1_listener ext_offer_listener = {
    .offer = ext_offer_listener_event_offer
};
static const struct zwlr_data_control_offer_v1_listener wlr_offer_listener = {
    .offer = wlr_offer_listener_event_offer
};

static void
ext_device_listener_event_data_offer(
    void *data, struct ext_data_control_device_v1 *device UNUSED,
    struct ext_data_control_offer_v1 *offer
)
{
    ext_data_control_offer_v1_add_listener(offer, &ext_offer_listener, data);
}
static void
wlr_device_listener_event_data_offer(
    void *data, struct zwlr_data_control_device_v1 *device UNUSED,
    struct zwlr_data_control_offer_v1 *offer
)
{
    zwlr_data_control_offer_v1_add_listener(offer, &wlr_offer_listener, data);
}

/*
 * Common handler for data device "selection" and "primary_selection" event.
 */
static void
device_listener_event_xselection(
    wlseat_T *seat, void *offer, wlselection_type_T type
)
{
    assert(seat != NULL);

    const char *sel_str = wlselection_str(type);

    wlip_debug("Received %s selection for seat '%s'", sel_str, seat->name);

    wlselection_T *sel = wlselection_get(seat, type);

    // Destroy previous data offer if any
    DESTROY_OFFER(sel->offer.dummy);

    if (sel->source.dummy != NULL)
    {
        // We are the source client, ignore selection event.
        DESTROY_OFFER(offer);
        sel->offer.dummy = NULL;
        return;
    }

    sel->offer.dummy = offer;

    // If offer is NULL, set the selection to the previous selection (only if
    // current clipboard entry is not NULL).
    if (offer == NULL)
    {
        assert(sel->clipboard != NULL);

        if (sel->clipboard->entry == NULL)
            return;
    }
}
static void
ext_device_listener_event_selection(
    void *data, struct ext_data_control_device_v1 *device UNUSED,
    struct ext_data_control_offer_v1 *offer
)
{
    device_listener_event_xselection(data, offer, WLSELECTION_TYPE_REGULAR);
}
static void
wlr_device_listener_event_selection(
    void *data, struct zwlr_data_control_device_v1 *device UNUSED,
    struct zwlr_data_control_offer_v1 *offer
)
{
    device_listener_event_xselection(data, offer, WLSELECTION_TYPE_REGULAR);
}

static void
ext_device_listener_event_primary_selection(
    void *data, struct ext_data_control_device_v1 *device UNUSED,
    struct ext_data_control_offer_v1 *offer
)
{
    device_listener_event_xselection(data, offer, WLSELECTION_TYPE_PRIMARY);
}
static void
wlr_device_listener_event_primary_selection(
    void *data, struct zwlr_data_control_device_v1 *device UNUSED,
    struct zwlr_data_control_offer_v1 *offer
)
{
    device_listener_event_xselection(data, offer, WLSELECTION_TYPE_PRIMARY);
}

/*
 * Common handler for data device "finished" event.
 */
static void
device_listener_event_finished(wlseat_T *seat)
{
    DESTROY_DEVICE(seat->device.dummy);
    seat->device.dummy = NULL;

    wlip_debug(
        "Received data device 'finished' event for seat '%s'", seat->name
    );
}
static void
ext_device_listener_event_finished(
    void *data, struct ext_data_control_device_v1 *device UNUSED
)
{
    device_listener_event_finished(data);
}
static void
wlr_device_listener_event_finished(
    void *data, struct zwlr_data_control_device_v1 *device UNUSED
)
{
    device_listener_event_finished(data);
}

// vim: ts=4 sw=4 sts=4 et
