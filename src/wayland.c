#include "wayland.h"
#include "alloc.h"
#include "clipboard.h"
#include "event.h"
#include "ext-data-control-v1.h"
#include "hashtable.h"
#include "util.h"
#include "wlr-data-control-unstable-v1.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <wayland-client.h>

#define DESTROY_DEVICE(d)                                                      \
    do                                                                         \
    {                                                                          \
        if (d == NULL)                                                         \
            break;                                                             \
        if (CONNECTION.protocol == DATA_PROTOCOL_EXT)                          \
            ext_data_control_device_v1_destroy(d);                             \
        else if (CONNECTION.protocol == DATA_PROTOCOL_WLR)                     \
            zwlr_data_control_device_v1_destroy(d);                            \
        else                                                                   \
            abort();                                                           \
    } while (false)
#define DESTROY_SOURCE(s)                                                      \
    do                                                                         \
    {                                                                          \
        if (s == NULL)                                                         \
            break;                                                             \
        if (CONNECTION.protocol == DATA_PROTOCOL_EXT)                          \
            ext_data_control_source_v1_destroy(s);                             \
        else if (CONNECTION.protocol == DATA_PROTOCOL_WLR)                     \
            zwlr_data_control_source_v1_destroy(s);                            \
        else                                                                   \
            abort();                                                           \
    } while (false)
#define DESTROY_OFFER(o)                                                       \
    do                                                                         \
    {                                                                          \
        if (o == NULL)                                                         \
            break;                                                             \
        if (CONNECTION.protocol == DATA_PROTOCOL_EXT)                          \
            ext_data_control_offer_v1_destroy(o);                              \
        else if (CONNECTION.protocol == DATA_PROTOCOL_WLR)                     \
            zwlr_data_control_offer_v1_destroy(o);                             \
        else                                                                   \
            abort();                                                           \
    } while (false)
#define OFFER_RECEIVE(o, m, f)                                                 \
    do                                                                         \
    {                                                                          \
        if (CONNECTION.protocol == DATA_PROTOCOL_EXT)                          \
            ext_data_control_offer_v1_receive(o, m, f);                        \
        else if (CONNECTION.protocol == DATA_PROTOCOL_WLR)                     \
            zwlr_data_control_offer_v1_receive(o, m, f);                       \
        else                                                                   \
            abort();                                                           \
    } while (false)
#define SOURCE_OFFER(s, m)                                                     \
    do                                                                         \
    {                                                                          \
        if (CONNECTION.protocol == DATA_PROTOCOL_EXT)                          \
            ext_data_control_source_v1_offer(s, m);                            \
        else if (CONNECTION.protocol == DATA_PROTOCOL_WLR)                     \
            zwlr_data_control_source_v1_offer(s, m);                           \
        else                                                                   \
            abort();                                                           \
    } while (false)
#define DEVICE_SET(d, s, t)                                                    \
    do                                                                         \
    {                                                                          \
        if ((t) == WLSELECTION_TYPE_REGULAR)                                   \
        {                                                                      \
            if (CONNECTION.protocol == DATA_PROTOCOL_EXT)                      \
                ext_data_control_device_v1_set_selection(d, s);                \
            else if (CONNECTION.protocol == DATA_PROTOCOL_WLR)                 \
                zwlr_data_control_device_v1_set_selection(d, s);               \
            else                                                               \
                abort();                                                       \
        }                                                                      \
        else if ((t) == WLSELECTION_TYPE_PRIMARY)                              \
        {                                                                      \
            if (CONNECTION.protocol == DATA_PROTOCOL_EXT)                      \
                ext_data_control_device_v1_set_primary_selection(d, s);        \
            else if (CONNECTION.protocol == DATA_PROTOCOL_WLR)                 \
                zwlr_data_control_device_v1_set_primary_selection(d, s);       \
            else                                                               \
                abort();                                                       \
        }                                                                      \
        else                                                                   \
            abort();                                                           \
    } while (false)

struct wlselection_S
{
    bool available;

    wlseat_T *seat; // Parent seat
    wlselection_type_T type;

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

    eventtimer_T null_timer;
    bool timer_running;

    bool ignore_next_null; // If next selection event should be ignored (if it
                           // is NULL).

    // Clipboard that this selection is attached to. May be NULL.
    clipboard_T *clipboard;
};

#define WLSEAT_NAME_MAXSIZE 32

struct wlseat_S
{
    int refcount;

    struct wl_seat *proxy;

    uint32_t capabilities;
    uint32_t numerical_name;

    // May be false if seat was removed, but is still referenced somewhere.
    bool started;
    bool got_name;

    union
    {
        struct ext_data_control_device_v1 *ext;
        struct zwlr_data_control_device_v1 *wlr;
        void *dummy;
    } device;

    // Table of mime types for the current data offer event if any.
    hashtable_T mime_types;

    wlselection_T regular;
    wlselection_T primary;

    wlseat_T *next; // Used when waiting for seat name. This is an edge case but
                    // handle it since not handling results in a memory leak.

    char name[WLSEAT_NAME_MAXSIZE];
};

typedef enum
{
    DATA_PROTOCOL_NONE,
    DATA_PROTOCOL_EXT,
    DATA_PROTOCOL_WLR,
} dataprotocol_T;

// Global singleton state for display connection
static struct
{
    struct wl_display *display; // If NULL, then not connected.
    struct wl_registry *registry;

    // Global object proxies
    struct
    {
        wlseat_T *waiting_seats;
        hashtable_T seats;

        union
        {
            struct ext_data_control_manager_v1 *ext;
            struct zwlr_data_control_manager_v1 *wlr;
            void *dummy;
        } dac;
    } globals;

    bool got_manager;
    bool reading; // If we have called wl_display_prepare_read().

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
remove_seat_from_waiting(wlseat_T *seat)
{
    assert(seat != NULL);

    wlseat_T *waiting = CONNECTION.globals.waiting_seats, *prev = NULL;

    while (waiting != NULL)
    {
        wlseat_T *next = waiting->next;

        if (waiting == seat)
        {
            if (prev != NULL)
                prev->next = next;
            if (CONNECTION.globals.waiting_seats == seat)
                CONNECTION.globals.waiting_seats = next;
            break;
        }

        prev = waiting;
        waiting = next;
    }
}

static void
wl_seat_listener_event_name(
    void *data, struct wl_seat *proxy UNUSED, const char *name
)
{
    wlseat_T *seat = data;

    if (strlen(name) >= WLSEAT_NAME_MAXSIZE)
    {
        wlip_warn("Wayland seat '%s' name too long", name);
        return;
    }

    hash_T hash = hash_get(name);
    hashbucket_T *b = hashtable_lookup(&CONNECTION.globals.seats, name, hash);

    // May be true if "name" event is received multiple times. If so then
    // re add to hash table with new name.
    if (seat->got_name)
    {
        wlip_debug("Seat '%s' renamed to '%s'", seat->name, name);
        hashtable_remove(&CONNECTION.globals.seats, seat->name, 0);
    }
    else if (!HB_ISEMPTY(b))
        // May happen if two seats have the same name, if so then just ignore
        return;
    else
    {
        wlip_debug("New seat '%s'", name);

        // Remove seat from waiting list
        remove_seat_from_waiting(seat);
    }

    seat->got_name = true;
    snprintf(seat->name, WLSEAT_NAME_MAXSIZE, "%s", name);
    hashtable_add(&CONNECTION.globals.seats, b, seat->name, hash);
}

static void
wl_seat_listener_event_capabilities(
    void *data, struct wl_seat *proxy UNUSED, uint32_t capabilities
)
{
    wlseat_T *seat = data;
    seat->capabilities = capabilities;
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

    // Seat is only added to table if name is received. If client connection is
    // closed but "name" event is never recieved, then it is freed,
    wlseat_T *seat = wlip_calloc(1, sizeof(wlseat_T));

    seat->proxy = proxy;
    seat->numerical_name = name;

    seat->regular.seat = seat;
    seat->primary.seat = seat;
    seat->regular.type = WLSELECTION_TYPE_REGULAR;
    seat->primary.type = WLSELECTION_TYPE_PRIMARY;
    seat->refcount = 1;
    seat->next = NULL;

    hashtable_init(&seat->mime_types, 0);
    eventsource_set_removed((eventsource_T *)&seat->regular.null_timer);
    eventsource_set_removed((eventsource_T *)&seat->primary.null_timer);

    if (CONNECTION.globals.waiting_seats == NULL)
        CONNECTION.globals.waiting_seats = seat;
    else
    {
        seat->next = CONNECTION.globals.waiting_seats;
        CONNECTION.globals.waiting_seats = seat;
    }

    wl_seat_add_listener(proxy, &wl_seat_listener, seat);
    wl_display_roundtrip(CONNECTION.display); // Initial roundtrip
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
 * Set the availability of the selections for seat.
 */
static void
wlseat_check(wlseat_T *seat)
{
    assert(seat != NULL);

    seat->regular.available = true;

    if (CONNECTION.protocol == DATA_PROTOCOL_EXT ||
        (CONNECTION.protocol == DATA_PROTOCOL_WLR &&
         zwlr_data_control_manager_v1_get_version(CONNECTION.globals.dac.wlr) >=
             2))
        seat->primary.available = true;
}

/*
 * Get the wlseat_T with the given name. Return NULL if it doesn't exist. If
 * "name" is NULL, then get the first found seat.
 */
wlseat_T *
wayland_get_seat(const char *name)
{
    if (name == NULL)
    {
        hashtableiter_T iter = HASHTABLEITER_INIT(&CONNECTION.globals.seats);
        wlseat_T *seat = hashtableiter_next(&iter, offsetof(wlseat_T, name));

        return seat;
    }

    hashbucket_T *b =
        hashtable_lookup(&CONNECTION.globals.seats, name, hash_get(name));

    if (HB_ISEMPTY(b))
        return NULL;

    wlseat_T *seat = HB_GET(b, wlseat_T, name);

    return seat;
}

/*
 * Return the wlselection_T from the seat. Returns NULL if selection is not
 * available.
 */
wlselection_T *
wlseat_get_selection(wlseat_T *seat, wlselection_type_T type)
{
    assert(seat != NULL);

    wlselection_T *sel = wlselection_get(seat, type);

    wlseat_check(seat);
    if (!sel->available)
    {
        DESTROY_DEVICE(seat->device.dummy);
        return sel;
    }
    wlseat_start(seat);
    return sel;
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

    event_remove((eventsource_T *)&seat->regular.null_timer);
    hashtable_clear_all(&seat->mime_types, 0);
    wlip_free(seat);
}

static wlseat_T *
wlseat_ref(wlseat_T *seat)
{
    assert(seat != NULL);
    seat->refcount++;
    return seat;
}

static void
wlseat_unref(wlseat_T *seat)
{
    assert(seat != NULL);

    if (--seat->refcount <= 0)
        wlseat_destroy(seat);
}

wlselection_T *
wlselection_ref(wlselection_T *sel)
{
    assert(sel != NULL);

    wlseat_ref(sel->seat);
    return sel;
}

void
wlselection_unref(wlselection_T *sel)
{
    assert(sel != NULL);
    wlseat_unref(sel->seat);
}

static void
wlseat_mark_invalid(wlseat_T *seat)
{
    assert(seat != NULL);

    seat->started = false;
    if (seat->regular.timer_running)
    {
        event_remove((eventsource_T *)&seat->regular.null_timer);
        wlseat_unref(seat);
    }
    if (seat->primary.timer_running)
    {
        event_remove((eventsource_T *)&seat->primary.null_timer);
        wlseat_unref(seat);
    }
    wlseat_unref(seat);
}

/*
 * Prepare to read the display fd. Returns true if connection is lost.
 */
bool
wayland_prepare(void)
{
    if (!CONNECTION.reading)
    {
        // Dispatch any pending events left in the queue
        while (wl_display_prepare_read(CONNECTION.display) == -1)
            wl_display_dispatch_pending(CONNECTION.display);
        CONNECTION.reading = true;
    }

    // Flush requests to commpositor
    if (wl_display_flush(CONNECTION.display) == -1 && errno != EAGAIN)
    {
        // Wayland connection lost, exit.
        wlip_debug("Wayland display connection lost, exiting...");
        return true;
    }
    return false;
}

/*
 * Eead the display fd and dispatch events. Returns true if connection is lost.
 */
bool
wayland_check(int revents)
{
    CONNECTION.reading = false;
    if (revents & POLLIN)
    {
        if (wl_display_read_events(CONNECTION.display) == -1 ||
            wl_display_dispatch_pending(CONNECTION.display) == -1)
        {
            // Wayland connection lost, exit.
            wlip_debug("Wayland display connection lost or error, exiting...");
            return true;
        }
    }
    else if (revents & (POLLERR | POLLHUP | POLLNVAL))
    {
        // Wayland connection lost, exit.
        wlip_debug("Wayland display connection lost, exiting...");
        return true;
    }
    else
        wl_display_cancel_read(CONNECTION.display);
    return false;
}

/*
 * Initialize the Wayland connection and attach it to the event loop. Returns OK
 * on success and FAIL on failure.
 */
int
wayland_init(void)
{
    assert(CONNECTION.display == NULL);

    const char *name = getenv("WAYLAND_DISPLAY");

    CONNECTION.display = wl_display_connect(NULL);
    if (CONNECTION.display == NULL)
    {
        wlip_warn("Failed connecting to display '%s'", name);
        return FAIL;
    }

    if (name == NULL)
        name = "(unknown)";

    wlip_debug("Connected to display '%s'", name);

    CONNECTION.registry = wl_display_get_registry(CONNECTION.display);
    CONNECTION.protocol = DATA_PROTOCOL_NONE;
    CONNECTION.got_manager = false;

    hashtable_init(&CONNECTION.globals.seats, 0);
    CONNECTION.globals.waiting_seats = NULL;

    wl_registry_add_listener(CONNECTION.registry, &registry_listener, NULL);
    wl_display_roundtrip(CONNECTION.display);
    if (CONNECTION.globals.dac.dummy == NULL)
    {
        wlip_error(
            "wlr-data-control-unstable-v1 or ext-data-control-v1 protocol not "
            "supported by compositor"
        );
        return FAIL;
    }
    CONNECTION.got_manager = true;
    return OK;
}

int
wayland_get_fd(void)
{
    assert(CONNECTION.display != NULL);

    return wl_display_get_fd(CONNECTION.display);
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
        &CONNECTION.globals.seats, (hb_freefunc_T)wlseat_mark_invalid,
        offsetof(wlseat_T, name)
    );

    while (CONNECTION.globals.waiting_seats != NULL)
        remove_seat_from_waiting(CONNECTION.globals.waiting_seats);

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
    if (!CONNECTION.got_manager &&
        strcmp(interface, ext_data_control_manager_v1_interface.name) == 0)
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
    else if (!CONNECTION.got_manager &&
             CONNECTION.protocol == DATA_PROTOCOL_NONE &&
             strcmp(interface, zwlr_data_control_manager_v1_interface.name) ==
                 0)
    {
        CONNECTION.globals.dac.wlr = wl_registry_bind(
            registry, name, &zwlr_data_control_manager_v1_interface,
            version > 2 ? 2 : version
        );
        CONNECTION.protocol = DATA_PROTOCOL_WLR;

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
            wlseat_mark_invalid(seat);
            return;
        }
}

typedef struct
{
    eventfd_T fdsource;
    clipdata_T *data;
    uint32_t w; // Number of bytes written so far
} sendctx_T;

static void
send_check_cb(eventsource_T *source)
{
    eventfd_T *fdsource = (eventfd_T *)source;
    sendctx_T *ctx = source->udata;

    if (fdsource->revents & POLLOUT)
    {
        uint8_t *buf = (uint8_t *)ctx->data->content.data + ctx->w;

        ssize_t w = write(fdsource->fd, buf, ctx->data->content.len - ctx->w);

        if (w == -1)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            wlip_warn("Error writing mime type contents: %s", strerror(errno));
        }
        else
        {
            ctx->w += w;
            if (ctx->w < ctx->data->content.len)
                return;
        }
    }
    else if (fdsource->revents == 0)
        return;
    else
        wlip_warn("Error occured while sending mime type contents");

    // Error occured or finished sending all data
    clipdata_unref(ctx->data);
    wlip_free(ctx);
    close(fdsource->fd);
    event_remove((eventsource_T *)&ctx->fdsource);
}

/*
 * Common handler for data source "send" event.
 */
static void
source_listener_event_send(wlselection_T *sel, const char *mime_type, int fd)
{
    assert(sel->clipboard != NULL);

    if (sel->clipboard->entry != NULL)
    {
        // Find mimetype_T (if it exists) and transfer its contents
        mimetype_T *mt = hashtable_find(
            &sel->clipboard->entry->mime_types, mime_type,
            offsetof(mimetype_T, name)
        );

        // If data is not loaded, then load it now.
        if (mt != NULL && mt->data != NULL && clipdata_load(mt->data) == OK)
        {
            sendctx_T *ctx = wlip_malloc(sizeof(sendctx_T));

            ctx->data = clipdata_ref(mt->data);
            ctx->w = 0;

            // Make fd non-blocking
            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
            event_add_fd(&ctx->fdsource, fd, POLLOUT, send_check_cb, ctx);
            return;
        }
    }
    close(fd);
}
static void
ext_source_listener_event_send(
    void *data, struct ext_data_control_source_v1 *source UNUSED,
    const char *mime_type, int32_t fd
)
{
    source_listener_event_send(data, mime_type, fd);
}
static void
wlr_source_listener_event_send(
    void *data, struct zwlr_data_control_source_v1 *source UNUSED,
    const char *mime_type, int32_t fd
)
{
    source_listener_event_send(data, mime_type, fd);
}

static void
ext_source_listener_event_cancelled(
    void *data, struct ext_data_control_source_v1 *source
)
{
    wlselection_T *sel = data;

    // Only set it to NULL if it is the same, because if we set the selection,
    // we will receive the cancelled event, and we don't want to discard the
    // source we just set by setting it to NULL.
    ext_data_control_source_v1_destroy(source);
    if (sel->source.dummy == source)
        sel->source.dummy = NULL;
}
static void
wlr_source_listener_event_cancelled(
    void *data, struct zwlr_data_control_source_v1 *source
)
{
    wlselection_T *sel = data;

    zwlr_data_control_source_v1_destroy(source);
    if (sel->source.dummy == source)
        sel->source.dummy = NULL;
}

static const struct ext_data_control_source_v1_listener ext_source_listener = {
    .send = ext_source_listener_event_send,
    .cancelled = ext_source_listener_event_cancelled
};
static const struct zwlr_data_control_source_v1_listener wlr_source_listener = {
    .send = wlr_source_listener_event_send,
    .cancelled = wlr_source_listener_event_cancelled
};

/*
 * Make the selection become the source client using the current clipboard entry
 * (own the Wayland selection it corresponds to). If the entry is NULL, then the
 * selection is cleared.
 */
static void
wlselection_set(wlselection_T *sel)
{
    assert(sel != NULL);
    assert(sel->clipboard != NULL);

    wlip_debug(
        "Setting %s selection for seat '%s'", wlselection_str(sel->type),
        sel->seat->name
    );

    if (sel->source.dummy != NULL)
    {
        // This will cause a NULL selection event, which we want to ignore.
        // Therefore signal that if the next selection event is a NULL one,
        // ignore it.
        DESTROY_SOURCE(sel->source.dummy);
        sel->ignore_next_null = true;
    }

    // TODO: remove hashtable and just use arrays
    clipentry_T *entry = sel->clipboard->entry;

    if (entry != NULL)
    {
        // Create data source and start listening to it
        if (CONNECTION.protocol == DATA_PROTOCOL_EXT)
        {
            sel->source.ext = ext_data_control_manager_v1_create_data_source(
                CONNECTION.globals.dac.ext
            );
            ext_data_control_source_v1_add_listener(
                sel->source.ext, &ext_source_listener, sel
            );
        }
        else
        {
            sel->source.wlr = zwlr_data_control_manager_v1_create_data_source(
                CONNECTION.globals.dac.wlr
            );
            zwlr_data_control_source_v1_add_listener(
                sel->source.wlr, &wlr_source_listener, sel
            );
        }

        hashtableiter_T iter = HASHTABLEITER_INIT(&entry->mime_types);
        mimetype_T *mime_type;

        while (
            (mime_type = hashtableiter_next(&iter, offsetof(mimetype_T, name)))
        )
            SOURCE_OFFER(sel->source.dummy, mime_type->name);
    }
    else
        sel->source.dummy = NULL;

    DEVICE_SET(sel->seat->device.dummy, sel->source.dummy, sel->type);

    wl_display_flush(CONNECTION.display);
}

/*
 * Make the wlselection_T set the selection to the current clipboard entry. If
 * the entry is NULL, then the selection is cleared.
 */
void
wlselection_update(wlselection_T *sel)
{
    assert(sel != NULL);
    assert(sel->clipboard != NULL);

    wlselection_set(sel);
}

/*
 * Return a file descriptor to read the contents of the given mime type from.
 * Returns -1 on error and -2 on fatal error.
 */
int
wlselection_get_fd(wlselection_T *sel, const char *mime_type)
{
    assert(sel != NULL);
    assert(mime_type != NULL);

    int fds[2];

    if (pipe(fds) == -1)
    {
        wlip_warn("Failed opening pipe: %s", strerror(errno));
        return -1;
    }

    // Note that a new selection event may come in and change the offer, meaning
    // sel->offer can be NULL.
    if (sel->offer.dummy == NULL)
    {
        wlip_debug("Cannot get file descriptor, selection cleared");
        return -2;
    }

    OFFER_RECEIVE(sel->offer.dummy, mime_type, fds[1]);

    // Close our write-end because we don't need it
    close(fds[1]);

    if (wl_display_flush(CONNECTION.display) == -1)
    {
        wlip_warn("Failed flushing display: %s", strerror(errno));
        close(fds[0]);
        return -1;
    }

    // Make fd non blocking
    fcntl(fds[0], F_SETFL, fcntl(fds[0], F_GETFL, 0) | O_NONBLOCK);

    return fds[0];
}

/*
 * Return true if the selection is still valid/available.
 */
bool
wlselection_is_valid(wlselection_T *sel)
{
    assert(sel != NULL);

    return sel->seat->started;
}

/*
 * Set the clipboard of selection to "cb" and return true. If selection already
 * set to clipboard, then do nothing and return false.
 */
bool
wlselection_set_clipboard(wlselection_T *sel, clipboard_T *cb)
{
    assert(sel != NULL);
    assert(cb != NULL);

    if (sel->clipboard != NULL)
        return false;
    sel->clipboard = cb;
    return true;
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

    // There may be duplicate mime types in the offer
    if (HB_ISEMPTY(b))
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
device_listener_event_data_offer(wlseat_T *seat)
{
    // Remove any previous mime types
    hashtable_remove_all(&seat->mime_types, 0);
}

static void
ext_device_listener_event_data_offer(
    void *data, struct ext_data_control_device_v1 *device UNUSED,
    struct ext_data_control_offer_v1 *offer
)
{
    device_listener_event_data_offer(data);
    ext_data_control_offer_v1_add_listener(offer, &ext_offer_listener, data);
}
static void
wlr_device_listener_event_data_offer(
    void *data, struct zwlr_data_control_device_v1 *device UNUSED,
    struct zwlr_data_control_offer_v1 *offer
)
{
    device_listener_event_data_offer(data);
    zwlr_data_control_offer_v1_add_listener(offer, &wlr_offer_listener, data);
}

static void
null_delay_cb(eventsource_T *source)
{
    wlselection_T *sel = source->udata;

    if (sel->offer.dummy == NULL)
    {
        wlip_debug("NULL selection event is valid, setting the selection");
        wlselection_set(sel);
    }
    else
        wlip_debug("NULL selection event is invalid");

    sel->timer_running = false;
    event_remove((eventsource_T *)&sel->null_timer);
    wlseat_unref(sel->seat);
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
    wlselection_T *sel = wlselection_get(seat, type);

    // Destroy previous data offer if any
    DESTROY_OFFER(sel->offer.dummy);

    if (sel->ignore_next_null)
    {
        sel->ignore_next_null = false;

        if (offer == NULL)
        {
            wlip_debug("Ignoring this NULL selection event");
            return;
        }
    }

    if (sel->timer_running)
    {
        event_remove((eventsource_T *)&sel->null_timer);
        wlseat_unref(sel->seat);
        sel->timer_running = false;
    }

    wlip_debug("Received %s selection for seat '%s'", sel_str, seat->name);

    if (sel->clipboard == NULL || sel->source.dummy != NULL)
    {
        // We are the source client or are not attached to a clipboard, ignore
        // selection event.
        DESTROY_OFFER(offer);
        sel->offer.dummy = NULL;

        wlip_debug("Source client is self, ignoring");
        return;
    }

    sel->offer.dummy = offer;

    // If offer is NULL, set the selection to the previous selection (only if
    // current clipboard entry is not NULL).
    if (offer == NULL)
    {
        if (sel->clipboard->entry == NULL)
            // No entry that we can set the selection to in the first place, so
            // ignore.
            return;

        // We want to delay setting the selection because the NULL selection
        // event may followed right after by the actual selection event. We
        // want to ignore the NULL selection event if so.
        wlip_debug("Got NULL selection event, delaying setting the selection");

        // Must add reference since seat may become invalid during the wait.
        wlseat_ref(seat);
        event_add_timer(&sel->null_timer, 1, null_delay_cb, sel);
    }
    else
    {
        hashtable_T mime_types = sel->seat->mime_types;

        memset(&sel->seat->mime_types, 0, sizeof(hashtable_T));
        // Push selection to clipboard
        assert(sel->clipboard != NULL);
        clipboard_push_selection(sel->clipboard, sel, mime_types);
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
    wlip_debug(
        "Received data device 'finished' event for seat '%s'", seat->name
    );

    // Remove seat from global table
    hashtable_remove(&CONNECTION.globals.seats, seat->name, 0);
    wlseat_mark_invalid(seat);
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
