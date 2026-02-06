#pragma once

#include <poll.h>
#include <stdbool.h>
#include <stdint.h>

typedef enum
{
    EVENTSOURCE_TYPE_FD,
    EVENTSOURCE_TYPE_TIMER,
    EVENTSOURCE_TYPE_WLCHECK
} eventsource_type_T;

typedef struct eventsource_S eventsource_T;

// Called when an event source is triggered.
typedef void (*eventsource_func_T)(eventsource_T *source);
// Base event source struct type
struct eventsource_S
{
    eventsource_type_T type;

    eventsource_func_T func;
    void *udata;

    eventsource_T *next;
    eventsource_T *prev;
};

// Event source for a file descriptor
typedef struct
{
    eventsource_T base;

    int fd;
    int events;
    int revents;
} eventfd_T;

typedef struct
{
    eventsource_T base;

    // In milliseconds
    int interval;
    int remaining;
} eventtimer_T;

// Called after Wayland events are read and dispatched in the event cycle.
typedef struct
{
    eventsource_T base;
} eventwlcheck_T;

void event_run(void);
void event_remove(eventsource_T *source);
void eventsource_set_removed(eventsource_T *source);

void event_add_fd(
    eventfd_T *fdsource, int fd, int events, eventsource_func_T func,
    void *udata
);
void event_add_timer(
    eventtimer_T *timer, int interval, eventsource_func_T func, void *udata
);
void
event_add_wlcheck(eventwlcheck_T *check, eventsource_func_T func, void *udata);
