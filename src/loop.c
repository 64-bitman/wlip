#include "loop.h"
#include "util.h"
#include "wayland.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

// Maxmimum number of times that can be waiting for at once.
#define MAX_TIMERS 8

// Maximum number of file descriptors other than the Wayland display and server
// socket.
#define MAX_FDS 16
#define FDS_OFFSET 2 // (wayland display fd + server socket)

typedef struct
{
    int id;        // Unique identifier
    int interval;  // Interval between each trigger in milliseconds
    int remaining; // Time remaining in milliseconds
    timer_func_T func;
    void *user_data;
} timer_T;

// Auxillary info for a pollfd struct.
typedef struct
{
    fdprepare_func_T prepare;
    fdcheck_func_T check;
    void *user_data;
    int timeout;
} fdinfo_T;

static volatile sig_atomic_t got_signal = 0;

// Singleton state for event loop.
static struct
{
    timer_T timers[MAX_TIMERS];
    int timers_len;

    struct pollfd pfds[FDS_OFFSET + MAX_FDS];
    int pfds_len;

    // Indexed by file descriptor number (Should be same size as "pfds").
    fdinfo_T fdinfos[FDS_OFFSET + 3 + MAX_FDS]; // Also take into account
                                                // standard fds.
} LOOP;

static void
sig_handler(int signo)
{
    got_signal = signo;
}

/*
 * Run the event loop, subsystems should be initialized beforehand. Returns OK
 * on success and FAIL on failure. It will exit on SIGTERM or SIGINT.
 */
int
loop_run(void)
{
#ifndef TEST_LOOP_RAW
    struct wl_display *display = wayland_get_display();
    assert(display != NULL);

    LOOP.pfds[0].fd = wl_display_get_fd(display);
    LOOP.pfds[0].events = POLLIN;
#endif

    LOOP.pfds_len += 2;

    // Handle SIGINT and SIGTERM
    struct sigaction sa = {0};

    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    assert(sigaction(SIGINT, &sa, NULL) == 0);
    assert(sigaction(SIGTERM, &sa, NULL) == 0);

    // Block SIGINT and SIGTERM outside ppoll() (so that there is no race
    // window).
    sigset_t block, empty;

    sigemptyset(&empty);
    sigemptyset(&block);

    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    sigprocmask(SIG_BLOCK, &block, NULL);

    while (true)
    {
        int64_t start = get_montonictime_us() / 1000;

#ifndef TEST_LOOP_RAW
        // Dispatch any pending events in the queue
        while (wl_display_prepare_read(display) == -1)
            wl_display_dispatch_pending(display);

        // Flush requests to compositor
        if (wl_display_flush(display) == -1 && errno != EAGAIN)
        {
            wlip_log("Failed flushing display, exiting: %s", strerror(errno));
            return FAIL;
        }
#endif

        int min = -1;

        // Find the timer with the least amount of time remaining (if any)
        for (int i = 0; i < LOOP.timers_len; i++)
        {
            timer_T *timer = LOOP.timers + i;

            assert(timer->remaining > 0);
            if (min == -1 || timer->remaining < min)
                min = timer->remaining;
        }

        // Find the fd with the smallest timeout.
        for (int i = FDS_OFFSET; i < LOOP.pfds_len; i++)
        {
            struct pollfd *pfd = LOOP.pfds + i;
            fdinfo_T *info = LOOP.fdinfos + pfd->fd;

            if (info->prepare != NULL &&
                info->prepare(pfd, &info->timeout, info->user_data))
                // Remove pollfd from array
                LOOP.pfds[i--] = LOOP.pfds[--LOOP.pfds_len];
            else if (info->timeout != -1 && (min == -1 || info->timeout < min))
                min = info->timeout;
        }

        struct timespec ts;

        if (min >= 0)
        {
            ts.tv_sec = min / 1000;
            ts.tv_nsec = (min % 1000) * 1000000;
        }

#ifndef TEST_LOOP_RAW
        int ret =
            ppoll(LOOP.pfds, LOOP.pfds_len, min >= 0 ? &ts : NULL, &empty);
#else
        // Don't want to pollfds that haven't been initialized (we would be
        // polling stdout).
        int ret = ppoll(
            LOOP.pfds + 2, LOOP.pfds_len - 2, min >= 0 ? &ts : NULL, &empty
        );
#endif

        if (got_signal)
        {
            wlip_debug("Exiting...");
            break;
        }

        if (ret == -1)
        {
            if (errno == EINTR)
            {
#ifndef TEST_LOOP_RAW
                wl_display_cancel_read(display);
#endif
                goto check_timers;
            }
            else
            {
                fprintf(stderr, "poll(...) error: %s\n", strerror(errno));
                abort();
            }
        }

        if (ret == 0)
        {
#ifndef TEST_LOOP_RAW
            wl_display_cancel_read(display);
#endif
            goto check_timers;
        }

#ifndef TEST_LOOP_RAW
        // Check Wayland fd (this should always be done first)
        if (LOOP.pfds[0].revents & POLLIN)
        {
            if (wl_display_read_events(display) == -1 ||
                wl_display_dispatch_pending(display) == -1)
            {
                wlip_log(
                    "Failed dispatching/reading events, exiting...: %s",
                    strerror(errno)
                );
                return FAIL;
            }
        }
        else if (LOOP.pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL))
        {
            // Wayland connection lost, exit.
            wlip_debug("Wayland display connection lost, exiting...");
            return FAIL;
        }
        else
            wl_display_cancel_read(display);
#endif

        // Check fds
        for (int i = FDS_OFFSET; i < LOOP.pfds_len; i++)
        {
            struct pollfd *pfd = LOOP.pfds + i;
            fdinfo_T *info = LOOP.fdinfos + pfd->fd;

            if (info->check != NULL && info->check(pfd, info->user_data))
                // Remove pollfd from array
                LOOP.pfds[i--] = LOOP.pfds[--LOOP.pfds_len];
        }

check_timers:;
        int64_t elapsed = (get_montonictime_us() / 1000) - start;

        // Check if any timers have triggered
        for (int i = 0; i < LOOP.timers_len; i++)
        {
            timer_T *timer = LOOP.timers + i;

            timer->remaining -= elapsed;
            if (timer->remaining <= 0)
            {
                if (timer->func(timer->user_data))
                    // Remove timer (just move the last timer into the current
                    // index).
                    LOOP.timers[i--] = LOOP.timers[--LOOP.timers_len];
                else
                    timer->remaining = timer->interval;
            }
        }
    }
    return OK;
}

/*
 * Reset the event loop. Used for testing purposes
 */
void
loop_reset(void)
{
    memset(&LOOP, 0, sizeof(LOOP));
    got_signal = 0;

    sigset_t unblock;
    sigemptyset(&unblock);
    sigaddset(&unblock, SIGINT);
    sigaddset(&unblock, SIGTERM);
    sigprocmask(SIG_UNBLOCK, &unblock, NULL);
}

/*
 * Add a timer to the event loop. "interval" is in milliseconds. "interval" must
 * be greater than zero. This should not be called inside a timer callback.
 * Returns an ID that can be used to remove the timer.
 */
int
loop_add_timer(int interval, timer_func_T func, void *user_data)
{
    assert(interval > 0);
    assert(func != NULL);
    assert(LOOP.timers_len < MAX_TIMERS);

    timer_T *timer = LOOP.timers + LOOP.timers_len++;
    static int id;

    timer->id = ++id;
    timer->func = func;
    timer->user_data = user_data;
    timer->interval = timer->remaining = interval;

    return id;
}

/*
 * Return true if timer with ID is active.
 */
bool
loop_timer_active(int id)
{
    assert(id > 0);

    for (int i = 0; i < LOOP.timers_len; i++)
    {
        timer_T *timer = LOOP.timers + i;

        if (timer->id == id)
            return true;
    }
    return false;
}

/*
 * Remove the timer with the given ID. Returns true if timer was found.
 */
bool
loop_timer_stop(int id)
{
    for (int i = 0; i < LOOP.timers_len; i++)
    {
        timer_T *timer = LOOP.timers + i;

        if (timer->id == id)
        {
            LOOP.timers[i--] = LOOP.timers[--LOOP.timers_len];
            return true;
        }
    }
    return false;
}

/*
 * Add the fd to the event loop so it is polled for the given events. This
 * should not be called inside a prepare or check callback.
 */
void
loop_add_fd(
    int fd, int events, fdprepare_func_T prepare, fdcheck_func_T check,
    void *user_data
)
{
    assert(fd >= 0);

    struct pollfd *pfd = LOOP.pfds + FDS_OFFSET + LOOP.pfds_len++;
    fdinfo_T *info = LOOP.fdinfos + fd;

    pfd->fd = fd;
    pfd->events = events;

    info->prepare = prepare;
    info->check = check;
    info->timeout = -1;
    info->user_data = user_data;
}

// vim: ts=4 sw=4 sts=4 et
