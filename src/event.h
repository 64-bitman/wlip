#pragma once

#include <poll.h>
#include <stdbool.h>
#include <stdint.h>

// Called before polling the file descriptors. If true is removed, then the
// source is removed from the event loop. Note that this is not guaranteed to be
// called with the "check" callback after, specifically when a signal interrupts
// ppoll().
typedef bool (*eventprepare_func_T)(int fd, void *udata);

// Called after polling the file descriptors. If true is removed, then the
// source is removed from the event loop
typedef bool (*eventcheck_func_T)(int fd, int revents, void *udata);

// Called when the timer is triggered. If true is removed, then the timer is
// removed from the event loop
typedef bool (*eventtimer_func_T)(void *udata);

void event_run();
void event_stop(void);

void event_add_fd(
    int fd, int events, int priority, eventprepare_func_T prepare,
    eventcheck_func_T check, void *udata
);
void event_remove_fd(int fd);
int event_add_timer(int interval, eventtimer_func_T func, void *udata);
bool event_remove_timer(uint32_t id);
