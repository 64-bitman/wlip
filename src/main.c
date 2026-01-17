#include "alloc.h"
#include "util.h"
#include "version.h"
#include <getopt.h>
#include <stdlib.h>
#include <uv.h>

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
    printf("-v, --version   Show version:\n");
    printf("-h, --help      Show this message:\n");
    printf("-d, --debug     Enable debug logging:\n");
    printf("\n");
}

int
main(int argc, char *argv[])
{
    // Replace libuv allocator with ours
    uv_replace_allocator(wlip_malloc, wlip_realloc, wlip_calloc, wlip_free);

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

    uv_loop_t loop;

    uv_loop_init(&loop);

    uv_run(&loop, UV_RUN_DEFAULT);

    uv_loop_close(&loop);

    return EXIT_SUCCESS;
}

// vim: ts=4 sw=4 sts=4 et
