#include "errors.h"
#include "loop.h"
#include "util.h"
#include "version.h"
#include "wayland.h"
#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

static struct option OPTIONS[] = {
    {"version", no_argument, 0, 'v'},
    {"help", no_argument, 0, 'h'},
    {"debug", no_argument, 0, 'd'},
};

static void
help(void)
{
    printf("Usage: wlip [OPTION?] - clipboard manager\n");
    printf("\n");
    printf("Options:\n");
    printf("-v, --version   Show version\n");
    printf("-h, --help      Show this message\n");
    printf("-d, --debug     Enable debug logging\n");
    printf("\n");
}

int
main(int argc, char *argv[])
{
    int c;
    int opt_index;

    while ((c = getopt_long(argc, argv, "vhd", OPTIONS, &opt_index)) != -1)
    {
        switch (c)
        {
        case 'v':
            printf(PROJECT_VERSION "\n");
            return EXIT_SUCCESS;
        case 'h':
            help();
            return EXIT_SUCCESS;
        case 'd':
            wlip_set_debug(true);
            break;
        case '?':
            break;
        default:
            printf("getopt returned character code 0x%x ??\n", c);
        }
    }

    error_T error;

    if (wayland_init(NULL, &error) == FAIL)
    {
        wayland_uninit();

        wlip_log("%s", error.msg);
        return EXIT_FAILURE;
    }

    int ret = loop_run();

    wayland_uninit();

    return ret == OK ? EXIT_SUCCESS : EXIT_FAILURE;
}

// vim: ts=4 sw=4 sts=4 et
