#pragma once

#include <signal.h> // IWYU pragma: keep
#include <wayland-util.h>

struct eventloop;

typedef void (*eventtimer_func)(void *udata);
struct eventtimer
{
    int     priority;
    int64_t interval;  // In nanoseconds
    int64_t remaining; // In nanoseconds

    eventtimer_func callback;
    void           *udata;

    struct wl_list link;
};

typedef void (*eventsource_func)(int revents, void *udata);
struct eventsource
{
    int priority;
    int fd;
    int events;
    int pfd_idx;

    eventsource_func callback;
    void            *udata;

    struct wl_list link;
};

typedef void (*eventprepare_func)(void *udata);
struct eventprepare
{
    int               priority;
    eventprepare_func callback;
    void             *udata;

    struct wl_list link;
};

typedef void (*signal_func)(int signo, void *data);
struct signal_handler
{
    int         priority;
    signal_func callback;
    void       *udata;

    struct wl_list link;
};

struct eventloop
{
    sigset_t sigmask;

    // If > 0, then keep running the event loop
    int run;

    // First element in list has the highest priority
    struct wl_list timers;
    struct wl_list sources;
    struct wl_list prepares;

    struct signal_handler *sig_handlers;
};

// clang-format off
int eventloop_init(struct eventloop *loop);
void eventloop_uninit(struct eventloop *loop);
int eventloop_run(struct eventloop *loop);
void eventloop_stop(struct eventloop *loop);

void eventloop_add_timer(struct eventloop *loop, struct eventtimer *timer);
void eventloop_add_source(struct eventloop *loop, struct eventsource *source);
void eventloop_add_prepare(struct eventloop *loop, struct eventprepare *prepare);

int eventloop_add_signal(struct eventloop *loop, int signo, signal_func callback, void *udata);
int eventloop_del_signal(struct eventloop *loop, int signo);

// Smaller values indicate higher priority
void eventtimer_init(struct eventtimer *timer, int priority, int interval, eventtimer_func callback, void *udata);
void eventsource_init(struct eventsource *source, int priority, int fd, int events, eventsource_func callback, void *udata);
void eventprepare_init(struct eventprepare *prepare, int priority, eventprepare_func callback, void *udata);

void eventtimer_stop(struct eventtimer *timer);
void eventsource_uninit(struct eventsource *source);
void eventprepare_uninit(struct eventprepare *prepare);

void ignore_signal(int signo, void *udata);
// clang-format on
