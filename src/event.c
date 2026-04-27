#include "event.h"
#include "util.h"
#include <errno.h> // IWYU pragma: keep
#include <string.h>
#include <sys/epoll.h>

struct signalinfo
{
    int                   refcount;
    volatile sig_atomic_t active;
};

static volatile sig_atomic_t GOT_SIGNAL = false;
static struct signalinfo    *SIGARRAY = NULL;

static bool
sigarray_is_empty(void)
{
    if (SIGARRAY == NULL)
        return true;
    for (int i = 0; i < SIGRTMAX; i++)
        if (SIGARRAY[i].refcount > 0)
            return false;
    return true;
}

/*
 * Initialize the event loop. Returns OK on success and FAIL on failure.
 */
int
eventloop_init(struct eventloop *loop)
{
    // Get current signal mask
    if (sigprocmask(0, NULL, &loop->sigmask) == -1)
    {
        wlip_err("Error getting signal mask");
        return FAIL;
    }

    if (SIGARRAY == NULL)
    {
        SIGARRAY = calloc(SIGRTMAX, sizeof(*SIGARRAY));
        if (SIGARRAY == NULL)
        {
            wlip_err("Error allocating signal array");
            return FAIL;
        }
    }

    loop->epoll_fd = epoll_create1(0);
    if (loop->epoll_fd == -1)
    {
        wlip_err("Error creating epoll fd");
        if (sigarray_is_empty())
            free((void *)SIGARRAY);
        return FAIL;
    }
    loop->sig_handlers = calloc(SIGRTMAX, sizeof(*loop->sig_handlers));
    if (loop->sig_handlers == NULL)
    {
        wlip_err("Error allocating signal handler array");
        close(loop->epoll_fd);
        if (sigarray_is_empty())
            free((void *)SIGARRAY);
        return FAIL;
    }

    wl_list_init(&loop->timers);
    wl_list_init(&loop->sources);
    wl_list_init(&loop->prepares);

    return OK;
}

/*
 * Note that event loop should be fully stopped (all sources removed) before
 * calling this
 */
void
eventloop_uninit(struct eventloop *loop)
{
    if (!wl_list_empty(&loop->timers) || !wl_list_empty(&loop->sources))
        wlip_log("Event loop still has sources active");

    sigprocmask(SIG_SETMASK, &loop->sigmask, NULL);

    if (sigarray_is_empty())
        free((void *)SIGARRAY);
    free(loop->sig_handlers);
    close(loop->epoll_fd);
}

int
cmp_eventsource(const void *pa, const void *pb)
{
    const struct epoll_event *ea = pa;
    const struct epoll_event *eb = pb;
    const struct eventsource *a = ea->data.ptr;
    const struct eventsource *b = eb->data.ptr;

    return a->priority - b->priority;
}

static int
eventloop_poll(struct eventloop *loop)
{
#define MAX_EVENTS 10
    struct epoll_event events[MAX_EVENTS];

    if (wl_list_empty(&loop->timers) && wl_list_empty(&loop->sources))
        return DONE;

    struct eventprepare *prepare, *prepare_tmp;

    wl_list_for_each_safe(prepare, prepare_tmp, &loop->prepares, link)
    {
        prepare->callback(prepare->udata);
    }

    struct eventtimer *timer, *timer_tmp;
    int                timeout = -1;

    wl_list_for_each(timer, &loop->timers, link)
    {
        if (timeout == -1 || timeout > timer->remaining)
            timeout = timer->remaining;
    }

    int64_t start = get_time_ns(CLOCK_MONOTONIC) / 1000000, end;

    if (start == -1)
        return FAIL;

    int nfds = epoll_pwait(
        loop->epoll_fd, events, MAX_EVENTS, timeout, &loop->sigmask
    );

    if (nfds == -1)
    {
        if (errno == EINTR)
        {
            if (GOT_SIGNAL)
            {
                GOT_SIGNAL = false;

                for (int i = 0; i < SIGRTMAX; i++)
                {
                    struct signalinfo *info = SIGARRAY + i;
                    bool               was = info->active;

                    info->active = false;
                    if (was && loop->sig_handlers[i].callback != NULL)
                        loop->sig_handlers[i].callback(
                            i, loop->sig_handlers[i].udata
                        );
                }
            }
            goto check_timers;
        }
        wlip_err("Error polling event loop");
        return FAIL;
    }

    // Must sort "events" array from highest priority to lowest priority.
    qsort(events, nfds, sizeof(*events), cmp_eventsource);

    for (int i = 0; i < nfds; i++)
    {
        struct eventsource *source = events[i].data.ptr;

        source->callback(events[i].events, source->udata);
    }

check_timers:
    end = get_time_ns(CLOCK_MONOTONIC) / 1000000;

    if (end == -1)
        return FAIL;

    int64_t elapsed = end - start;

    wl_list_for_each_safe(timer, timer_tmp, &loop->timers, link)
    {
        timer->remaining -= elapsed;
        if (timer->remaining <= 0)
        {
            timer->remaining = timer->interval;
            timer->callback(timer->udata);
        }
    }

#undef MAX_EVENTS
    return OK;
}

/*
 * Start running the event loop until there are no more sources left or an error
 * occurs. This function is rentrant. Returns OK on success, DONE if event loop
 * should be stopped, and FAIL on failure.
 */
int
eventloop_run(struct eventloop *loop)
{
    int ret;

    while ((ret = eventloop_poll(loop)) == OK)
        ;

    return ret == DONE ? OK : FAIL;
}

void
eventloop_add_timer(struct eventloop *loop, struct eventtimer *timer)
{
    struct eventtimer *tmp;
    insert_list_priority(
        tmp, &loop->timers, timer, &timer->link, link, priority
    );
}

/*
 * Returns OK on success and FAIL on failure.
 */
int
eventloop_add_source(struct eventloop *loop, struct eventsource *source)
{
    struct epoll_event ev;

    ev.events = source->events;
    ev.data.ptr = source;

    if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, source->fd, &ev) == -1)
    {
        wlip_err("Error adding fd %d to epoll", source->fd);
        return FAIL;
    }

    source->loop = loop;

    struct eventsource *tmp;
    insert_list_priority(
        tmp, &loop->sources, source, &source->link, link, priority
    );

    return OK;
}

void
eventloop_add_prepare(struct eventloop *loop, struct eventprepare *prepare)
{
    struct eventprepare *tmp;
    insert_list_priority(
        tmp, &loop->prepares, prepare, &prepare->link, link, priority
    );
}

static void
signal_handler(int signo)
{
    GOT_SIGNAL = true;
    SIGARRAY[signo].active = true;
}

/*
 * Register a handler for the given signal, which will be blocked until the
 * event loop polls. Returns OK on success and FAIL on failure.
 */
int
eventloop_add_signal(
    struct eventloop *loop, int signo, signal_func callback, void *udata
)
{
    if (loop->sig_handlers[signo].callback != NULL)
    {
        wlip_log("Signal %d already has handler", signo);
        return FAIL;
    }

    sigset_t mask, orig;

    sigemptyset(&mask);
    sigaddset(&mask, signo);

    if (sigprocmask(SIG_BLOCK, &mask, &orig) == -1)
    {
        wlip_err("Error blocking signal %d", signo);
        return FAIL;
    }

    struct sigaction sa = {0};

    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(signo, &sa, NULL) == -1)
    {
        wlip_err("Error setting signal handler for %d", signo);
        sigprocmask(SIG_SETMASK, &orig, NULL);
        return FAIL;
    }

    loop->sig_handlers[signo].callback = callback;
    loop->sig_handlers[signo].udata = udata;

    return OK;
}

/*
 * Returns OK on success and FAIL on failure.
 */
int
eventloop_del_signal(struct eventloop *loop, int signo)
{
    if (loop->sig_handlers[signo].callback == NULL)
        return OK;
    loop->sig_handlers[signo].callback = NULL;

    if (--SIGARRAY[signo].refcount > 0)
        return OK;

    struct sigaction sa = {0};

    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);

    if (sigaction(signo, &sa, NULL) < 0)
    {
        wlip_err("Error setting signal %d to default handler", signo);
        return FAIL;
    }

    sigset_t unblock;

    sigemptyset(&unblock);
    sigaddset(&unblock, signo);

    if (sigprocmask(SIG_UNBLOCK, &unblock, NULL) < 0)
        wlip_err("Error unblocking signal %d", signo);
    return OK;
}

void
eventtimer_init(
    struct eventtimer *timer,
    int                priority,
    int                interval,
    eventtimer_func    callback,
    void              *udata
)
{
    timer->interval = timer->remaining = interval;
    timer->callback = callback;
    timer->udata = udata;
    timer->priority = priority;

    wl_list_init(&timer->link);
}

void
eventsource_init(
    struct eventsource *source,
    int                 priority,
    int                 fd,
    int                 events,
    eventsource_func    callback,
    void               *udata
)
{
    source->fd = fd;
    source->events = events;

    source->callback = callback;
    source->udata = udata;
    source->priority = priority;

    wl_list_init(&source->link);
}

void
eventprepare_init(
    struct eventprepare *prepare,
    int                  priority,
    eventprepare_func    callback,
    void                *udata
)
{
    prepare->callback = callback;
    prepare->udata = udata;
    prepare->priority = priority;
}

void
eventtimer_stop(struct eventtimer *timer)
{
    list_clear(&timer->link);
}

/*
 * Note that this does not close the file descriptor.
 */
void
eventsource_uninit(struct eventsource *source)
{
    if (wl_list_empty(&source->link))
        return;

    if (epoll_ctl(source->loop->epoll_fd, EPOLL_CTL_DEL, source->fd, NULL) ==
        -1)
        wlip_err("Error removing fd %d from epoll", source->fd);

    list_clear(&source->link);
}

void
eventprepare_uninit(struct eventprepare *prepare)
{
    list_clear(&prepare->link);
}

int
eventsource_modify(struct eventsource *source, int events)
{
    if (wl_list_empty(&source->link))
    {
        source->events = events;
        return OK;
    }

    struct epoll_event ev;

    ev.events = events;
    ev.data.ptr = source;

    if (epoll_ctl(source->loop->epoll_fd, EPOLL_CTL_MOD, source->fd, &ev) == -1)
    {
        wlip_err("Error modifying fd %d for epoll", source->fd);
        return FAIL;
    }
    return OK;
}
