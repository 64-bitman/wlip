#include "event.h"
#include "log.h"
#include "util.h"
#include "wlipgui.h"
#include <getopt.h>
#include <stdlib.h>

static void
signal_handler(int signo UNUSED, void *udata)
{
    struct eventloop *loop = udata;

    log_info("Exiting...");
    eventloop_stop(loop);
}

int
main(int argc, char **argv)
{
    static const struct option options[] = {{NULL, 0, 0, 0}};

    int c;
    int idx;

    log_init(NULL);
    log_set_level(LOG_DEBUG);

    while ((c = getopt_long(argc, argv, "", options, &idx)) != -1)
    {
        switch (c)
        {
        default:
            return EXIT_FAILURE;
        }
    }

    struct wlipgui   wlipg;
    struct eventloop loop;
    int              ret = FAIL;

    if (eventloop_init(&loop) == FAIL)
        return EXIT_FAILURE;

    if (eventloop_add_signal(&loop, SIGTERM, signal_handler, &loop) == FAIL ||
        eventloop_add_signal(&loop, SIGINT, signal_handler, &loop) == FAIL ||
        eventloop_add_signal(&loop, SIGPIPE, ignore_signal, &loop) == FAIL)
        goto exit;

    ret = eventloop_run(&loop);

exit:
    eventloop_del_signal(&loop, SIGTERM);
    eventloop_del_signal(&loop, SIGINT);
    eventloop_del_signal(&loop, SIGPIPE);
    eventloop_uninit(&loop);
    return ret == OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
