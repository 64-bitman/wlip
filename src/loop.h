#pragma once

#include <poll.h>
#include <stdbool.h>

// Called when a timer is triggered. Should return true if timer should be
// removed.
typedef bool (*timer_func_T)(void *user_data);

// Note that returning true from check or prepare func does not close the file
// descriptor.

// Called before polling all the file descriptors. Should return true if fd
// should be removed from the event loop. "timeout" is the timeout that should
// be passed to ppoll(), it is -1 by default. Note that it is not reset per loop
// and the previous value is used.
typedef bool (*fdprepare_func_T)(struct pollfd *pfd, int *timeout, void *udata);
// Called after polling all the file descriptors. Should return true if fd
// should be removed from the event loop.
typedef bool (*fdcheck_func_T)(struct pollfd *pfd, void *user_Data);

int loop_run(void);
void loop_reset(void);

int loop_add_timer(int interval, timer_func_T func, void *user_data);
bool loop_timer_active(int id);
bool loop_timer_stop(int id);

void loop_add_fd(
    int fd, int events, fdprepare_func_T prepare, fdcheck_func_T check,
    void *user_data
);

// vim: ts=4 sw=4 sts=4 et
