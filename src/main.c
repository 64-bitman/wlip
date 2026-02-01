#include "clipboard.h"
#include "database.h"
#include "event.h"
#include "lua/script.h"
#include "server.h"
#include "version.h"
#include "wayland.h"
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

    if (getenv("WAYLAND_DISPLAY") == NULL)
    {
        wlip_error("$WAYLAND_DISPLAY is not set");
        return FAIL;
    }

    init_clipboards();
    if (wayland_init() == FAIL || server_init() == FAIL || lua_init() == FAIL)
        return EXIT_FAILURE;

    event_run();

    lua_uninit();
    free_clipboards(); // Must be done before wayland_uninit() (which frees all
                       // proxies), since free_clipboards() may also free seat
                       // proxies.
    wayland_uninit();
    database_uninit();
    server_uninit();

    return EXIT_SUCCESS;
}

// vim: ts=4 sw=4 sts=4 et
