#include "event.h"
#include "ipc_client.h"
#include "log.h"
#include "util.h"
#include "wayland.h"
#include <stdlib.h>

static void
signal_handler(int signo UNUSED, void *udata)
{
    struct eventloop *loop = udata;

    log_info("Exiting...");
    eventloop_stop(loop);
}

int
main(int argc UNUSED, char **argv UNUSED)
{
    struct eventloop  loop;
    struct ipc_client client;
    struct wayland    wayland;

    log_init(NULL);
    // Temporary
    log_set_level(LOG_DEBUG);

    if (eventloop_init(&loop) == FAIL)
        return EXIT_FAILURE;

    if (eventloop_add_signal(&loop, SIGTERM, signal_handler, &loop) == FAIL ||
        eventloop_add_signal(&loop, SIGINT, signal_handler, &loop) == FAIL ||
        eventloop_add_signal(&loop, SIGPIPE, ignore_signal, &loop) == FAIL)
        goto exit;

    if (ipc_client_init(&client, &loop, NULL, NULL) == FAIL)
        goto exit;

    if (wayland_init(&wayland, &loop) == FAIL)
    {
        ipc_client_uninit(&client);
        goto exit;
    }

    eventloop_run(&loop);

    wayland_uninit(&wayland);
    ipc_client_uninit(&client);

exit:
    eventloop_del_signal(&loop, SIGTERM);
    eventloop_del_signal(&loop, SIGINT);
    eventloop_del_signal(&loop, SIGPIPE);
    eventloop_uninit(&loop);

    return EXIT_SUCCESS;
}
