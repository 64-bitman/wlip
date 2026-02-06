#include "event.h"
#include "server.h"
#include "util.h"
#include "wayland.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

#define MAX_FDS 32 // Not including server and Wayland fd

// Singly linked list of all sources
static eventsource_T *SOURCES = NULL;
static volatile sig_atomic_t SIGCOUNT = 0;

static void
signal_handler(int signo UNUSED)
{
    SIGCOUNT++;
}

/*
 * Start running the event loop until SIGINT or SIGTERM is received (which
 * should be blocked before calling this function). Probably not reentrant.
 */
void
event_run(void)
{
    struct pollfd actual_pfds[2 + MAX_FDS];
    struct pollfd *pfds = actual_pfds + 2;

    actual_pfds[0].fd = wayland_get_fd();
    actual_pfds[0].events = POLLIN;

    actual_pfds[1].fd = server_get_fd();
    actual_pfds[1].events = POLLIN;

    struct sigaction sa = {0};
    sigset_t empty;

    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    sigemptyset(&empty);

    while (true)
    {
        int pfds_len = 0;
        int timeout = -1; // In milliseconds

        if (wayland_prepare())
            break;

        // Add the fds to the pfds array, and get the minimum timeout for the
        // timers.
        for (eventsource_T *source = SOURCES; source != NULL;
             source = source->next)
        {
            switch (source->type)
            {
            case EVENTSOURCE_TYPE_FD:
            {
                // If capacity is reached, then excess sources are just deferred
                // later.
                if (pfds_len < MAX_FDS)
                {
                    eventfd_T *fdsource = (eventfd_T *)source;
                    struct pollfd *pfd = pfds + pfds_len++;

                    pfd->fd = fdsource->fd;
                    pfd->events = fdsource->events;
                }
                break;
            }
            case EVENTSOURCE_TYPE_TIMER:
            {
                eventtimer_T *timer = (eventtimer_T *)source;
                if (timeout == -1 || timeout > timer->remaining)
                    timeout = timer->remaining;
                break;
            }
            default:
                abort();
            }
        }

        sig_atomic_t old_sigcount = SIGCOUNT;
        int64_t start = get_montonictime_us();
        struct timespec ts;

        if (timeout >= 0)
        {
            ts.tv_sec = timeout / 1000;
            ts.tv_nsec = (timeout % 1000) * 1000000;
        }

        int ret = ppoll(
            actual_pfds, pfds_len + 2, timeout == -1 ? NULL : &ts, &empty
        );
        bool caught = false;

        if (old_sigcount != SIGCOUNT)
        {
            // Caught SIGTERM or SIGINT
            wlip_log("Exiting...");
            break;
        }

        if (ret == -1)
        {
            if (errno != EINTR)
            {
                wlip_error("poll(...) error: %s", strerror(errno));
                abort();
            }
            else
                // Caught some other signal
                caught = true;
        }

        // Must always check the Wayland fd before doing anything else, so that
        // any events cannot be missed.
        if (!caught)
        {
            if (wayland_check(actual_pfds[0].revents))
                break;
            server_check_cb(actual_pfds[1].revents);
        }

        eventsource_T *source = SOURCES;
        int i = 0;

        while (source != NULL)
        {
            bool trigger = false;

            switch (source->type)
            {
            case EVENTSOURCE_TYPE_FD:
            {
                if (!caught && i < pfds_len)
                {
                    struct pollfd *pfd = pfds + i++;
                    eventfd_T *fdsource = (eventfd_T *)source;

                    fdsource->revents = pfd->revents;
                    trigger = true;
                }
                break;
            }
            case EVENTSOURCE_TYPE_TIMER:
            {
                eventtimer_T *timer = (eventtimer_T *)source;

                timer->remaining -= (get_montonictime_us() - start) / 1000;
                if (timer->remaining <= 0)
                {
                    timer->remaining = timer->interval;
                    trigger = true;
                }
                break;
            }
            default:
                abort();
            }

            // Source may have been removed and freed in "func", so keep a copy
            // of the next pointer.
            eventsource_T *next = source->next;

            if (trigger)
                source->func(source);
            source = next;
        }
    }
}

/*
 * Remove the given source from the event loop
 */
void
event_remove(eventsource_T *source)
{
    assert(source != NULL);

    if (source->next == NULL && source->prev == NULL && SOURCES != source)
        // Already removed
        return;

    eventsource_T *next = source->next, *prev = source->prev;

    if (source == SOURCES)
    {
        assert(prev == NULL);
        SOURCES = next;
        if (next != NULL)
            next->prev = NULL;
    }
    else
    {
        prev->next = next;
        if (next != NULL)
            next->prev = prev;
    }
    eventsource_set_removed(source);
}

/*
 * Doesn't actually do anything other than marking the source as "removed".
 */
void
eventsource_set_removed(eventsource_T *source)
{
    assert(source != NULL);
    source->next = source->prev = NULL;
}

static void
eventsource_init(
    eventsource_T *source, eventsource_type_T type, eventsource_func_T func,
    void *udata
)
{
    assert(source != NULL);
    assert(func != NULL);

    source->type = type;
    source->func = func;
    source->udata = udata;

    eventsource_set_removed(source);
}

static void
eventsource_add(eventsource_T *source)
{
    assert(source != NULL);

#ifndef NDEBUG
    // Assert that source is not already added
    for (eventsource_T *s = SOURCES; s != NULL; s = s->next)
        assert(s != source);
#endif

    // Always insert at the front of the list. This is so that any newly
    // added sources are deferred until the next event cycle.
    if (SOURCES == NULL)
        SOURCES = source;
    else
    {
        source->next = SOURCES;
        SOURCES->prev = source;
        SOURCES = source;
    }
}

/*
 * Watch a file descriptor for the given events.
 */
void
event_add_fd(
    eventfd_T *fdsource, int fd, int events, eventsource_func_T func,
    void *udata
)
{
    assert(fdsource != NULL);
    assert(fd >= 0);
    assert(func != NULL);

    eventsource_init(&fdsource->base, EVENTSOURCE_TYPE_FD, func, udata);

    fdsource->fd = fd;
    fdsource->events = events;

    eventsource_add(&fdsource->base);
}

/*
 * Add a timer to the event loop with the given interval in milliseconds.
 */
void
event_add_timer(
    eventtimer_T *timer, int interval, eventsource_func_T func, void *udata
)
{
    assert(timer != NULL);
    assert(interval > 0);
    assert(func != NULL);

    eventsource_init(&timer->base, EVENTSOURCE_TYPE_FD, func, udata);

    timer->interval = timer->remaining = interval;

    eventsource_add(&timer->base);
}

/*
 * Add a idle check source to the event loop. It will be called after the
 * Wayland display is read and dispatched.
 */
void
event_add_wlcheck(eventwlcheck_T *check, eventsource_func_T func, void *udata)
{
    assert(check != NULL);
    assert(func != NULL);

    eventsource_init(&check->base, EVENTSOURCE_TYPE_WLCHECK, func, udata);
    eventsource_add(&check->base);
}
