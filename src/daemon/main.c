#include "log.h"
#include "util.h"
#include "wlip.h"
#include <errno.h> // IWYU pragma: keep
#include <getopt.h>
#include <stdio.h> // IWYU pragma: keep
#include <stdlib.h>
#include <string.h>

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
    static const struct option options[] = {
        {"config", required_argument, 0, 'c'},
        {"data", required_argument, 0, 'd'},
        {NULL, 0, 0, 0}
    };

    int c;
    int idx;

    char *config_dir = NULL;
    char *database_dir = NULL;

    log_init(NULL);

    while ((c = getopt_long(argc, argv, "", options, &idx)) != -1)
    {
        switch (c)
        {
        case 'c':
            free(config_dir);
            config_dir = strdup(optarg);
            break;
        case 'd':
            free(database_dir);
            database_dir = strdup(optarg);
            break;
        case 'v':
            log_set_level(LOG_DEBUG);
            break;
        default:
            return EXIT_FAILURE;
        }
    }

    struct wlip      wlip;
    struct eventloop loop;
    int              ret = FAIL;

    if (eventloop_init(&loop) == FAIL)
    {
        free(config_dir);
        free(database_dir);
        return EXIT_FAILURE;
    }

    if (eventloop_add_signal(&loop, SIGTERM, signal_handler, &loop) == FAIL ||
        eventloop_add_signal(&loop, SIGINT, signal_handler, &loop) == FAIL ||
        eventloop_add_signal(&loop, SIGPIPE, ignore_signal, &loop) == FAIL ||
        wlip_init(&wlip, &loop, config_dir, database_dir) == FAIL)
    {
        free(config_dir);
        free(database_dir);
        goto exit;
    }

    ret = eventloop_run(&loop);
    wlip_uninit(&wlip);
exit:
    eventloop_del_signal(&loop, SIGTERM);
    eventloop_del_signal(&loop, SIGINT);
    eventloop_del_signal(&loop, SIGPIPE);
    eventloop_uninit(&loop);
    return ret == OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
