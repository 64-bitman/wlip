#include "util.h"
#include "wlip.h"
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

static const struct option OPTIONS[] = {
    {"config", required_argument, 0, 'c'},
    {"data", required_argument, 0, 'd'},
    {NULL, 0, 0, 0}
};

int
main(int argc, char **argv)
{
    int c;
    int idx;

    char *config_dir = NULL;
    char *database_dir = NULL;

    while ((c = getopt_long(argc, argv, "", OPTIONS, &idx)) != -1)
    {
        switch (c)
        {
        case 'c':
            config_dir = strdup(optarg);
            break;
        case 'd':
            database_dir = strdup(optarg);
            break;
        default:
            return EXIT_FAILURE;
        }
    }

    struct wlip wlip;

    if (wlip_init(&wlip, config_dir, database_dir) == FAIL)
        return EXIT_FAILURE;

    int ret = wlip_run(&wlip);

    wlip_uninit(&wlip);

    return ret == OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
