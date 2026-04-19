#include "wlip.h"
#include "config.h"
#include "ext-data-control-v1.h"
#include "util.h"
#include <errno.h> // IWYU pragma: keep
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

struct wlip WLIP;

static int  wlip_seat_init(struct wlip_seat *seat);
static void wlip_seat_free(struct wlip_seat *seat);

static void wl_registry_listener_event_global(
    void               *udata,
    struct wl_registry *registry,
    uint32_t            name,
    const char         *interface,
    uint32_t            version
);
static void wl_registry_listener_event_global_remove(
    void *udata, struct wl_registry *registry, uint32_t name
);

static const struct wl_registry_listener wl_registry_listener = {
    .global = wl_registry_listener_event_global,
    .global_remove = wl_registry_listener_event_global_remove
};

/*
 * Initialize state and connect to Wayland compositor. Returns OK on success and
 * FAIL on failure.
 */
int
wlip_init(void)
{
    wl_list_init(&WLIP.seats);

    if (config_init(WLIP.config_dir) == FAIL)
        goto fail;

    if (WLIP.display_name == NULL)
    {
        const char *wayland_display = getenv("WAYLAND_DISPLAY");

        if (wayland_display == NULL)
        {
            wlip_log("$WAYLAND_DISPLAY is not defined in environment");
            goto fail;
        }

        WLIP.display_name = strdup(wayland_display);
        if (WLIP.display_name == NULL)
        {
            wlip_err("Error allocating display name");
            goto fail;
        }
    }

    WLIP.display = wl_display_connect(WLIP.display_name);
    if (WLIP.display == NULL)
    {
        wlip_log("Error connecting to display '%s'", WLIP.display_name);
        goto fail;
    }

    WLIP.registry = wl_display_get_registry(WLIP.display);
    if (WLIP.registry == NULL)
    {
        wlip_err("Error creating display registry");
        goto fail;
    }

    // Get initial globals/seats
    wl_registry_add_listener(WLIP.registry, &wl_registry_listener, NULL);
    if (wl_display_roundtrip(WLIP.display) == -1)
    {
        wlip_err("Initial roundtrip failed");
        goto fail;
    }

    // Check if compositor doesn't support ext-data-control-v1
    if (WLIP.manager == NULL)
    {
        wlip_log("Compositor does not support ext-data-control-v1 protocol");
        goto fail;
    }

    // Initialize any configured seats, since we now know that the data device
    // manager is set.
    struct wlip_seat *seat;

    wl_list_for_each(seat, &WLIP.seats, link)
    {
        if (seat->proxy != NULL && wlip_seat_init(seat) == FAIL)
        {
            wl_seat_destroy(seat->proxy);
            seat->proxy = NULL;
        }
    }

    return OK;
fail:
    wlip_uninit();
    return FAIL;
}

void
wlip_uninit(void)
{
    free(WLIP.config_dir);
    free(WLIP.database_dir);
    free(WLIP.display_name);

    if (WLIP.log_fp != NULL)
        fclose(WLIP.log_fp);

    struct wlip_seat *seat;
    struct wlip_seat *tmp;

    wl_list_for_each_safe(seat, tmp, &WLIP.seats, link)
    {
        wlip_seat_free(seat);
    }

    if (WLIP.manager != NULL)
        ext_data_control_manager_v1_destroy(WLIP.manager);

    if (WLIP.registry != NULL)
        wl_registry_destroy(WLIP.registry);
    if (WLIP.display != NULL)
        wl_display_disconnect(WLIP.display);
}

static volatile sig_atomic_t sigcount = 0;

static void
signal_handler(int signo UNUSED)
{
    sigcount++;
}

/*
 * Start running event loop. Returns OK on success and FAIL on failure.
 */
int
wlip_run(void)
{
    struct sigaction sa = {0};

    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct pollfd pfd = {
        .fd = wl_display_get_fd(WLIP.display), .events = POLLIN
    };

    while (sigcount == 0)
    {
        while (wl_display_prepare_read(WLIP.display) == -1)
            wl_display_dispatch_pending(WLIP.display);

        if (wl_display_flush(WLIP.display) == -1)
        {
            wlip_err("Error flushing display");
            break;
        }

        int ret = poll(&pfd, 1, -1);

        if (ret == -1)
        {
            if (errno == EINTR)
                continue;
            wlip_err("Error polling display");
            break;
        }

        if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
        {
            wl_display_cancel_read(WLIP.display);
            break;
        }

        if (wl_display_read_events(WLIP.display) == -1 ||
            wl_display_dispatch_pending(WLIP.display) == -1)
        {
            wlip_err("Display connection lost");
            break;
        }
    }

    wlip_log("Exiting...");

    return OK;
}

static void
wlip_selection_clear(struct wlip_selection *sel)
{
    if (sel->offer != NULL)
        ext_data_control_offer_v1_destroy(sel->offer);
    if (sel->source != NULL)
        ext_data_control_source_v1_destroy(sel->source);

    wl_array_release(&sel->mime_types);
}

static void
wlip_seat_free(struct wlip_seat *seat)
{
    free(seat->name);

    if (seat->proxy != NULL)
        wl_seat_destroy(seat->proxy);
    if (seat->device != NULL)
        ext_data_control_device_v1_destroy(seat->device);

    wlip_selection_clear(&seat->sel_regular);
    wlip_selection_clear(&seat->sel_primary);

    wl_list_remove(&seat->link);
    free(seat);
}

/*
 * Initialize seat, create data device and add listeners. Note that the seat
 * proxy should already be set and the data device manager should already be
 * binded to. Returns OK on success and FAIL on failure.
 */
static int
wlip_seat_init(struct wlip_seat *seat)
{
    return OK;
}

static void
wl_seat_listener_event_name(
    void *udata UNUSED, struct wl_seat *proxy, const char *name
)
{
    struct wlip_seat *seat;

    wl_list_for_each(seat, &WLIP.seats, link)
    {
        if (strcmp(seat->name, name) == 0)
        {
            seat->proxy = proxy;
            seat->id = wl_proxy_get_id((struct wl_proxy *)proxy);
            if (WLIP.manager != NULL && wlip_seat_init(seat) == FAIL)
            {
                wl_seat_destroy(proxy);
                seat->proxy = NULL;
            }
            return;
        }
    }
    wl_seat_destroy(proxy);
}

/*
 * Dummy function
 */
static void
wl_seat_listener_event_capabilities(
    void *udata           UNUSED,
    struct wl_seat *proxy UNUSED,
    uint32_t capabilities UNUSED
)
{
}

static const struct wl_seat_listener wl_seat_listener = {
    .name = wl_seat_listener_event_name,
    .capabilities = wl_seat_listener_event_capabilities
};

static void
wl_registry_listener_event_global(
    void *udata         UNUSED,
    struct wl_registry *registry,
    uint32_t            name,
    const char         *interface,
    uint32_t            version
)
{
    if (strcmp(interface, ext_data_control_manager_v1_interface.name) == 0)
        WLIP.manager = wl_registry_bind(
            registry, name, &ext_data_control_manager_v1_interface, 1
        );
    else if (strcmp(interface, wl_seat_interface.name) == 0)
    {
        struct wl_seat *proxy =
            wl_registry_bind(registry, name, &wl_seat_interface, version);

        if (proxy != NULL)
        {
            wl_seat_add_listener(proxy, &wl_seat_listener, NULL);
            wl_display_roundtrip(WLIP.display);
        }
        else
            wlip_err("Error binding to wl_seat global");
    }
}

static void
wl_registry_listener_event_global_remove(
    void *udata UNUSED, struct wl_registry *registry UNUSED, uint32_t name
)
{
    // Only check seat globals, since we can handle them properly.
    struct wlip_seat *seat;
    struct wlip_seat *tmp;

    wl_list_for_each_safe(seat, tmp, &WLIP.seats, link)
    {
        if (seat->id == name)
        {
            wlip_log("Seat '%s' removed", seat->name);
            wlip_seat_free(seat);
            break;
        }
    }
}
