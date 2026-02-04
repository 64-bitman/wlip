#include "util.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wayland-server.h>

#define ASSERT(cond)                                                           \
    do                                                                         \
    {                                                                          \
        if (!(cond))                                                           \
        {                                                                      \
            fprintf(                                                           \
                stderr, "%s:%d fail: %s", __FILE__, __LINE__, strerror(errno)  \
            );                                                                 \
            abort();                                                           \
        }                                                                      \
    } while (false)

// Simple compositor used for testing. Only supports ext-data-control-v1
// protocol.
static struct
{
    pthread_t thread;

    int notify_fd;
    struct wl_event_source *notify_source;

    struct wl_display *display;
} COMPOSITOR;

/*
 * Called to wake up event loop. Write a value of 1 to stop the event loop,
 * otherwise write 2.
 */
int
notify_cb(int fd, uint32_t mask, void *data UNUSED)
{
    uint64_t i;

    if (mask == 0)
        return 0;
    else if (mask & WL_EVENT_READABLE)
    {
        ASSERT(read(fd, &i, sizeof(i)) != -1);

        if (i == 1)
        {
            wl_display_terminate(COMPOSITOR.display);
            return 0;
        }
        ASSERT(i == 2);
    }
    return 0;
}

static void *
event_loop(void *udata UNUSED)
{


    wl_display_run(COMPOSITOR.display);

    return NULL;
}

/*
 * Start running the compositor in a separate thread. Returns a file descriptor
 * for the client to connect to. Returns -1 on failure.
 */
int
compositor_run(void)
{
    int fds[2];

    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    COMPOSITOR.display = wl_display_create();

    COMPOSITOR.notify_fd = eventfd(0, EFD_CLOEXEC);
    ASSERT(COMPOSITOR.notify_fd != -1);

    struct wl_event_loop *eloop = wl_display_get_event_loop(COMPOSITOR.display);

    COMPOSITOR.notify_source = wl_event_loop_add_fd(
        eloop, COMPOSITOR.notify_fd, WL_EVENT_READABLE, notify_cb, NULL
    );

    ASSERT(wl_client_create(COMPOSITOR.display, fds[1]) != NULL);
    ASSERT(pthread_create(&COMPOSITOR.thread, NULL, event_loop, NULL) == 0);

    return fds[0];
}

/*
 * Stop running the compositor
 */
void
compositor_stop(void)
{
    uint64_t i = 1;

    ASSERT(write(COMPOSITOR.notify_fd, &i, sizeof(i)) != -1);
    pthread_join(COMPOSITOR.thread, NULL);

    wl_event_source_remove(COMPOSITOR.notify_source);
    wl_display_destroy_clients(COMPOSITOR.display);
    wl_display_destroy(COMPOSITOR.display);
}
