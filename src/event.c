#include "event.h"
#include "log.h"
#include "util.h"
#include <errno.h> // IWYU pragma: keep
#include <poll.h>
#include <pthread.h>
#include <string.h> // IWYU pragma: keep

static _Thread_local volatile sig_atomic_t  GOT_SIGNAL = false;
static _Thread_local volatile sig_atomic_t *SIGACTIVE = NULL;
static _Thread_local int SIGCOUNT = 0; // Number of signals currently being
                                       // handled by event loops in this thread.
                                       // Used to free SIGACTIVE when no more
                                       // signals being handled.

/*
 * Because sigaction() applies to all threads, must keep a reference count per
 * signal type to determine when to remove a signal handler.
 */
static int            *SIG_REFCOUNT = NULL;
static pthread_mutex_t SIGREFCOUNT_MUT = PTHREAD_MUTEX_INITIALIZER;

/*
 * Initialize the event loop. Returns OK on success and FAIL on failure.
 */
int
eventloop_init(struct eventloop *loop)
{
    // Get current signal mask
    if (pthread_sigmask(SIG_BLOCK, NULL, &loop->sigmask) == -1)
    {
        log_errerror("Error getting signal mask");
        return FAIL;
    }

    bool alloced_sig_active = false;

    if (SIGACTIVE == NULL)
    {
        SIGACTIVE = calloc(SIGRTMAX, sizeof(*SIGACTIVE));
        if (SIGACTIVE == NULL)
        {
            log_errerror("Error allocating signal array");
            return FAIL;
        }
        alloced_sig_active = true;
    }

    pthread_mutex_lock(&SIGREFCOUNT_MUT);
    if (SIG_REFCOUNT == NULL)
    {
        SIG_REFCOUNT = calloc(SIGRTMAX, sizeof(*SIG_REFCOUNT));
        if (SIG_REFCOUNT == NULL)
        {
            pthread_mutex_unlock(&SIGREFCOUNT_MUT);
            log_errerror("Error allocating signal refcount array");
            if (alloced_sig_active)
            {
                free((void *)SIGACTIVE);
                SIGACTIVE = NULL;
            }
            return FAIL;
        }
    }
    pthread_mutex_unlock(&SIGREFCOUNT_MUT);

    loop->sig_handlers = calloc(SIGRTMAX, sizeof(*loop->sig_handlers));
    if (loop->sig_handlers == NULL)
    {
        log_errerror("Error allocating signal handler array");
        if (alloced_sig_active && SIGCOUNT == 0)
        {
            free((void *)SIGACTIVE);
            SIGACTIVE = NULL;
        }
        return FAIL;
    }

    wl_list_init(&loop->timers);
    wl_list_init(&loop->sources);
    wl_list_init(&loop->prepares);
    loop->run = 0;

    return OK;
}

/*
 * Note that event loop should be fully stopped (all sources removed) before
 * calling this
 */
void
eventloop_uninit(struct eventloop *loop)
{
    if (!wl_list_empty(&loop->timers) || !wl_list_empty(&loop->sources) ||
        !wl_list_empty(&loop->prepares))
        log_warn("Event loop still has sources active");

    pthread_sigmask(SIG_SETMASK, &loop->sigmask, NULL);

    if (SIGCOUNT == 0)
    {
        free((void *)SIGACTIVE);
        SIGACTIVE = NULL;
    }
    else
        log_warn("Event loop still has signals attached");

    free(loop->sig_handlers);
}

/*
 *  Returns OK on success, DONE if event loop should be stopped, and FAIL on
 *  failure.
 */
static int
eventloop_poll(struct eventloop *loop)
{
    struct eventprepare *prepare, *prepare_tmp;

    wl_list_for_each_safe(prepare, prepare_tmp, &loop->prepares, link)
    {
        prepare->callback(prepare->udata);
    }
    if (loop->run == 0)
        return DONE;

    struct eventtimer *timer, *timer_tmp;
    struct timespec    timeout;
    int64_t            timeout_ns = -1;

    wl_list_for_each(timer, &loop->timers, link)
    {
        if (timeout_ns == -1 || timeout_ns > timer->remaining)
            timeout_ns = timer->remaining;
    }

#define MAX_FDS 10
    struct pollfd       pfds[MAX_FDS];
    int                 pfds_len = 0;
    struct eventsource *source, *source_tmp;

    // Add any fd sources to the event loop
    wl_list_for_each(source, &loop->sources, link)
    {
        if (pfds_len >= MAX_FDS)
            source->pfd_idx = -1;
        else
        {
            pfds[pfds_len].fd = source->fd;
            pfds[pfds_len].events = source->events;
            source->pfd_idx = pfds_len++;
        }
    }

    int64_t start = get_time_ns(CLOCK_MONOTONIC), end;

    if (start == -1)
        return FAIL;

    if (timeout_ns != -1)
    {
        timeout.tv_sec = timeout_ns / 1000000000LL;
        timeout.tv_nsec = timeout_ns % 1000000000LL;
    }

    int ret = ppoll(
        pfds, pfds_len, timeout_ns == -1 ? NULL : &timeout, &loop->sigmask
    );

    if (ret == -1)
    {
        if (errno == EINTR)
        {
            if (GOT_SIGNAL)
            {
                GOT_SIGNAL = false;

                for (int i = 0; i < SIGRTMAX; i++)
                {
                    bool was = SIGACTIVE[i];

                    SIGACTIVE[i] = false;
                    if (was && loop->sig_handlers[i].callback != NULL)
                        loop->sig_handlers[i].callback(
                            i, loop->sig_handlers[i].udata
                        );
                }
                if (loop->run == 0)
                    return DONE;
            }
            goto check_timers;
        }
        log_errerror("Error polling event loop");
        return FAIL;
    }

    wl_list_for_each_safe(source, source_tmp, &loop->sources, link)
    {
        if (source->pfd_idx == -1)
            continue;

        int revents = pfds[source->pfd_idx].revents;

        if (revents == 0)
            continue;

        source->pfd_idx = -1;
        source->callback(revents, source->udata);
    }
    if (loop->run == 0)
        return DONE;

check_timers:
    end = get_time_ns(CLOCK_MONOTONIC);

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
    if (loop->run == 0)
        return DONE;

#undef MAX_FDS
    return OK;
}

/*
 * Start running the event loop until it is stopped. This function is reentrant
 * (is it? too lazy to check...). Returns OK on success and FAIL on failure.

 */
int
eventloop_run(struct eventloop *loop)
{
    int ret;

    loop->run++;

    while ((ret = eventloop_poll(loop)) == OK)
        ;

    return ret == DONE ? OK : FAIL;
}

void
eventloop_stop(struct eventloop *loop)
{
    if (loop->run > 0)
        loop->run--;
}

void
eventloop_add_timer(struct eventloop *loop, struct eventtimer *timer)
{
    struct eventtimer *p;

    if (!wl_list_empty(&timer->link))
        return;

    wl_list_for_each(p, &loop->timers, link)
    {
        if (p->priority > timer->priority)
            break;
    }
    wl_list_insert(p->link.prev, &timer->link);
}

void
eventloop_add_source(struct eventloop *loop, struct eventsource *source)
{
    struct eventsource *p;

    if (!wl_list_empty(&source->link))
        return;

    wl_list_for_each(p, &loop->sources, link)
    {
        if (p->priority > source->priority)
            break;
    }
    wl_list_insert(p->link.prev, &source->link);
}

void
eventloop_add_prepare(struct eventloop *loop, struct eventprepare *prepare)
{
    struct eventprepare *p;

    if (!wl_list_empty(&prepare->link))
        return;

    wl_list_for_each(p, &loop->prepares, link)
    {
        if (p->priority > prepare->priority)
            break;
    }
    wl_list_insert(p->link.prev, &prepare->link);
}

/*
 * Runs on the stack of whichever thread the signal was delivered to. Only
 * ever touches that thread's own thread-local GOT_SIGNAL/SIGACTIVE, so no
 * locking is needed and this stays async-signal-safe.
 */
static void
signal_handler(int signo)
{
    GOT_SIGNAL = true;
    if (SIGACTIVE != NULL)
        SIGACTIVE[signo] = true;
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
        log_warn("Signal %d already has handler", signo);
        return FAIL;
    }

    sigset_t mask, orig;

    sigemptyset(&mask);
    sigaddset(&mask, signo);

    if (pthread_sigmask(SIG_BLOCK, &mask, &orig) == -1)
    {
        log_errwarn("Error blocking signal %d", signo);
        return FAIL;
    }

    struct sigaction sa = {0};

    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(signo, &sa, NULL) == -1)
    {
        log_errwarn("Error setting signal handler for %d", signo);
        pthread_sigmask(SIG_SETMASK, &orig, NULL);
        return FAIL;
    }

    // Make sure that signal is unblocked when calling ppoll()
    sigdelset(&loop->sigmask, signo);
    SIGCOUNT++;

    loop->sig_handlers[signo].callback = callback;
    loop->sig_handlers[signo].udata = udata;

    pthread_mutex_lock(&SIGREFCOUNT_MUT);
    SIG_REFCOUNT[signo]++;
    pthread_mutex_unlock(&SIGREFCOUNT_MUT);

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
    SIGCOUNT--;

    pthread_mutex_lock(&SIGREFCOUNT_MUT);
    bool last_ref = SIG_REFCOUNT[signo] > 0 && --SIG_REFCOUNT[signo] == 0;
    pthread_mutex_unlock(&SIGREFCOUNT_MUT);

    if (!last_ref)
        return OK;

    struct sigaction sa = {0};

    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);

    if (sigaction(signo, &sa, NULL) < 0)
    {
        log_errwarn("Error setting signal %d to default handler", signo);
        return FAIL;
    }

    sigset_t unblock;

    sigemptyset(&unblock);
    sigaddset(&unblock, signo);

    if (pthread_sigmask(SIG_UNBLOCK, &unblock, NULL) < 0)
        log_errwarn("Error unblocking signal %d", signo);
    return OK;
}

void
eventtimer_init(
    struct eventtimer *timer,
    int                priority,
    int                interval, // In milliseconds
    eventtimer_func    callback,
    void              *udata
)
{
    timer->interval = timer->remaining = interval * 1000000;
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
    source->pfd_idx = -1;

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

    wl_list_init(&prepare->link);
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
    list_clear(&source->link);
}

void
eventprepare_uninit(struct eventprepare *prepare)
{
    list_clear(&prepare->link);
}

/*
 * Used to ignore a signal
 */
void
ignore_signal(int signo UNUSED, void *udata UNUSED)
{
}
