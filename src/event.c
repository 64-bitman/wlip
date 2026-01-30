#include "event.h"
#include "alloc.h"
#include "util.h"
#include <assert.h>
#include <errno.h> // IWYU pragma: keep
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>

// Maximum number of event sources that can be polled for at once.
#define MAX_SOURCES 32

typedef struct eventsource_S eventsource_T;
struct eventsource_S
{
    int fd;
    int events;
    int priority; // Between INT_MIN and INT_MAX, lower means higher priority.

    eventprepare_func_T prepare;
    eventcheck_func_T check;
    void *udata;

    eventsource_T *next;
};

typedef struct eventtimer_S eventtimer_T;
struct eventtimer_S
{
    uint32_t id; // Unique identifier, never zero (used to remove timer).

    int interval;
    int remaining;
    bool ready; // If timer is ready to be checked

    eventtimer_func_T func;
    void *udata;

    eventtimer_T *next;
};

// Number of times we have received SIGINT or SIGTERM
static volatile sig_atomic_t signal_count = 0;

static struct
{
    // First event source in the list, ordered in ascending priority.
    eventsource_T *source;

    // First timer in the list
    eventtimer_T *timer;

    bool run;
} EVENT;

static void
signal_handler(int signo UNUSED)
{
    signal_count++;
}

/*
 * Run the event loop until SIGTERM or SIGINT is received (or if event_stop() is
 * called).
 */
void
event_run(void)
{
    assert(!EVENT.run);

    if (EVENT.source == NULL)
        return;

    EVENT.run = true;

    // Handle SIGINT and SIGTERM
    struct sigaction sa = {0};

    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // Block SIGINT and SIGTERM outside ppoll() (so that there is no race
    // window).
    sigset_t block, empty;

    sigemptyset(&empty);
    sigemptyset(&block);

    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    sigprocmask(SIG_BLOCK, &block, NULL);

    struct pollfd pfds[MAX_SOURCES];

    while (EVENT.run)
    {
        int pfds_len = 0;
        eventsource_T *prevs = NULL;
        eventsource_T *source = EVENT.source;

        // Add the pollfd of each event source to the array, and call the
        // prepare callback (higher priority sources are called first).
        while (source != NULL)
        {
            struct pollfd *pfd = pfds + pfds_len;
            eventsource_T *next = source->next;

            if (pfds_len >= MAX_SOURCES)
            {
                // Maximum event source limit reached, don't add any more
                // (the rest will just be deferred until there space becomes
                // available).
                prevs = source;
                break;
            }
            else if (source->prepare != NULL &&
                     source->prepare(source->fd, source->udata))
            {
                // Callback may have added another event source
                next = source->next;
                // Remove event source
                wlip_free(source);
                if (prevs == NULL)
                    EVENT.source = next;
                else
                    prevs->next = next;
                continue;
            }

            pfd->fd = source->fd;
            pfd->events = source->events;
            pfds_len++;

            prevs = source;
            source = next;
        }

        int64_t start = get_montonictime_us() / 1000;
        int min_timeout = -1;

        // Find the timer with the least amount of time remaining.
        for (eventtimer_T *timer = EVENT.timer; timer != NULL;
             timer = timer->next)
        {
            assert(timer->remaining > 0);

            timer->ready = true;
            if (min_timeout == -1 || timer->remaining < min_timeout)
                min_timeout = timer->remaining;
        }

        if (!EVENT.run)
            break;

        int old_signal_count = signal_count;
        struct timespec ts;

        if (min_timeout >= 0)
        {
            ts.tv_sec = min_timeout / 1000;
            ts.tv_nsec = (min_timeout % 1000) * 1000000;
        }

        int ret = ppoll(pfds, pfds_len, min_timeout >= 0 ? &ts : NULL, &empty);

        if (old_signal_count != signal_count)
        {
            // Caught signal
            wlip_log("Exiting...");
            break;
        }

        if (ret == -1)
        {
            if (errno == EINTR)
                goto timers;
            wlip_error("poll(...) error: %s", strerror(errno));
            abort();
        }

        int i = 0;

        prevs = NULL;
        source = EVENT.source;

        // Check event sources (in same order as prepare).
        while (source != NULL && i < pfds_len)
        {
            struct pollfd *pfd = pfds + i;
            eventsource_T *next = source->next;

            if (source->check != NULL &&
                source->check(pfd->fd, pfd->revents, source->udata))
            {
                next = source->next;
                // Remove event source
                wlip_free(source);
                if (prevs == NULL)
                    EVENT.source = next;
                else
                    prevs->next = next;
            }
            else
                prevs = source;

            source = next;
            i++;
        }

timers:;
        // Check if any timers have triggered
        int64_t elapsed = (get_montonictime_us() / 1000) - start;
        eventtimer_T *prevt = NULL;
        eventtimer_T *timer = EVENT.timer;

        while (timer != NULL)
        {
            eventtimer_T *next = timer->next;

            if (timer->ready)
            {
                timer->remaining -= (int)elapsed;
                if (timer->remaining <= 0)
                {
                    if (timer->func(timer->udata))
                    {
                        // Remove timer from event loop
                        wlip_free(timer);
                        if (prevt == NULL)
                            EVENT.timer = next;
                        else
                            prevt->next = next;
                    }
                    else
                    {
                        // Timer still running, reset it.
                        timer->remaining = timer->interval;
                        prevt = timer;
                    }
                }
                else
                    prevt = timer;
            }

            timer = next;
        }
    }

    uint n_sources = 0, n_timers = 0;

    for (eventsource_T *source = EVENT.source; source != NULL;
         source = source->next)
        n_sources++;

    for (eventtimer_T *timer = EVENT.timer; timer != NULL; timer = timer->next)
        n_timers++;

    wlip_debug("Event loop statistics:");
    wlip_debug("Number of remaining sources: %u", n_sources);
    wlip_debug("Number of remaining timers: %u", n_timers);

    EVENT.run = false;
}

/*
 * Stop running the event loop. Loop must already be running. Note that this
 * doesn't not wake up the loop if it in the polling stage. Only useful when
 * called inside the event loop.
 */
void
event_stop(void)
{
    assert(EVENT.run);

    EVENT.run = false;
}

/*
 * Add a source using the file descriptor to the event loop polling for the
 * given events.
 */
void
event_add_fd(
    int fd, int events, int priority, eventprepare_func_T prepare,
    eventcheck_func_T check, void *udata
)
{
    assert(fd >= 0);

    eventsource_T *new = wlip_malloc(sizeof(eventsource_T));

    new->fd = fd;
    new->events = events;
    new->priority = priority;

    new->prepare = prepare;
    new->check = check;
    new->udata = udata;

    if (EVENT.source == NULL || priority < EVENT.source->priority)
    {
        new->next = EVENT.source;
        EVENT.source = new;
        return;
    }

    eventsource_T *cur = EVENT.source;
    // Append to end of list (after all the sources with higher priority).
    while (cur->next != NULL && cur->next->priority <= priority)
        cur = cur->next;

    new->next = cur->next;
    cur->next = new;
}

/*
 * Remove and close all sources that have the given fd. Note that file
 * descriptors may be reused by the kernel.
 */
void
event_remove_fd(int fd)
{
    assert(fd >= 0);

    eventsource_T *source = EVENT.source;
    eventsource_T *prev = NULL;

    while (source != NULL)
    {
        eventsource_T *next = source->next;
        if (source->fd == fd)
        {
            if (prev == NULL)
                EVENT.source = next;
            else
                prev->next = next;
            close(source->fd);
            wlip_free(source);
        }
        source = next;
    }
}

/*
 * Add a timer to the event loop with the given interval. Returns an ID that can
 * be used to remove the timer.
 */
int
event_add_timer(int interval, eventtimer_func_T func, void *udata)
{
    assert(interval >= 0);
    assert(func != NULL);

    eventtimer_T *new = wlip_malloc(sizeof(eventtimer_T));
    static uint32_t id;

    new->id = ++id;
    new->interval = new->remaining = interval;
    new->func = func;
    new->udata = udata;
    new->next = NULL;

    // Make the timer not ready at first. This is because the timers are checked
    // after the event sources are checked, meaning if a timer was added in the
    // check callback, it may just trigger right after which we don't want.
    new->ready = false;

    if (EVENT.timer == NULL)
        EVENT.timer = new;
    else
    {
        eventtimer_T *timer = EVENT.timer;
        while (timer->next != NULL)
            timer = timer->next;
        timer->next = new;
    }
    new->next = NULL;

    return new->id;
}

/*
 * Remove a timer with the ID from the event loop. Must not be called inside an
 * eventtimer_func_T callback. Returns true if timer was removed.
 */
bool
event_remove_timer(uint32_t id)
{
    assert(id > 0);

    eventtimer_T *timer = EVENT.timer;
    eventtimer_T *prev = NULL;

    while (timer != NULL)
    {
        if (timer->id == id)
        {
            eventtimer_T *next = timer->next;
            wlip_free(timer);
            if (prev == NULL)
                EVENT.timer = next;
            else
                prev->next = next;
            return true;
        }
        prev = timer;
        timer = timer->next;
    }

    return false;
}
