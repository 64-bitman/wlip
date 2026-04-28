#include "wayland_base.h"
#include "log.h"
#include "util.h"
#include <limits.h>
#include <string.h>
#include <wayland-client.h>

static void wayland_display_check(int revents, void *udata);
static void wayland_display_prepare(void *udata);

/*
 * Connect to Wayland compositor and install event sources. If "display" is
 * NULL, then use $WAYLAND_DISPLAY. Returns OK on success and FAIL on failure.
 */
int
wayland_base_init(
    struct wayland_base *wbase, const char *display, struct eventloop *loop
)
{
    if (display == NULL)
        display = getenv("WAYLAND_DISPLAY");
    if (display == NULL)
    {
        log_error("$WAYLAND_DISPLAY not set");
        return FAIL;
    }

    wbase->display = wl_display_connect(display);
    if (wbase->display == NULL)
    {
        log_errerror("Error connecting to display '%s'", display);
        return FAIL;
    }

    wbase->registry = wl_display_get_registry(wbase->display);
    if (wbase->registry == NULL)
    {
        log_errerror("Error creating registry");
        wl_display_disconnect(wbase->display);
        return FAIL;
    }
    wbase->fd = wl_display_get_fd(wbase->display);

    eventsource_init(
        &wbase->source,
        INT_MIN, // Wayland source must be prioritized first, so that events are
                 // processed before we do anything else.
        wbase->fd,
        EPOLLIN,
        wayland_display_check,
        wbase
    );

    if (eventloop_add_source(loop, &wbase->source) == FAIL)
    {
        eventsource_uninit(&wbase->source);
        wl_registry_destroy(wbase->registry);
        wl_display_disconnect(wbase->display);
        return FAIL;
    }

    // Must have lowest priority, so that the display is flushed only after
    // doing everything.
    eventprepare_init(&wbase->prepare, INT_MAX, wayland_display_prepare, wbase);
    eventloop_add_prepare(loop, &wbase->prepare);

    wbase->loop = loop;
    wbase->reading = false;

    return OK;
}

void
wayland_base_uninit(struct wayland_base *wbase)
{
    eventsource_uninit(&wbase->source);
    eventprepare_uninit(&wbase->prepare);

    wl_registry_destroy(wbase->registry);
    wl_display_disconnect(wbase->display);
}

/*
 * Called after polling the display.
 */
static void
wayland_display_check(int revents, void *udata)
{
    struct wayland_base *wbase = udata;

    if (!(revents & EPOLLIN))
        goto stop;

    wbase->reading = false;
    if (wl_display_read_events(wbase->display) == -1 ||
        wl_display_dispatch_pending(wbase->display) == -1)
    {
        log_errerror("Error reading/dispatching display events");
        goto stop;
    }

    return;
stop:
    eventloop_stop(wbase->loop);
    return;
}

static void
wayland_display_prepare(void *udata)
{
    struct wayland_base *wbase = udata;

    if (!wbase->reading)
    {
        while (wl_display_prepare_read(wbase->display) == -1)
            if (wl_display_dispatch_pending(wbase->display) == -1)
            {
                log_errerror("Error dispatching display events");
                eventloop_stop(wbase->loop);
                return;
            }
        wbase->reading = true;
    }

    if (wl_display_flush(wbase->display) == -1)
    {
        log_errerror("Error flushing display");
        eventloop_stop(wbase->loop);
    }
}
