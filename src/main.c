#include "util.h"
#include "wlip.h"
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

static const struct option OPTIONS[] = {
    {"config", required_argument, 0, 'c'},
    {"data", required_argument, 0, 'd'},
    {"log", required_argument, 0, 'l'},
    {NULL, 0, 0, 0}
};

int
main(int argc, char **argv)
{
    int c;
    int idx;

    while ((c = getopt_long(argc, argv, "", OPTIONS, &idx)) != -1)
    {
        switch (c)
        {
        case 'c':
            WLIP.config_dir = strdup(optarg);
            break;
        case 'd':
            WLIP.database_dir = strdup(optarg);
            break;
        case 'l':
            WLIP.log_fp = fopen(optarg, "r");
            break;
        default:
            return EXIT_FAILURE;
        }
    }

    if (WLIP.log_fp == NULL)
        // Use stderr
        WLIP.log_fp = stderr;

    if (wlip_init() == FAIL)
        return EXIT_FAILURE;

    int ret = wlip_run();

    wlip_uninit();

    return ret == OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
