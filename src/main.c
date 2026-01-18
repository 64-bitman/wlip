#include "alloc.h"
#include "errors.h"
#include "util.h"
#include "version.h"
#include "wayland.h"
#include <assert.h>
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
    printf("-v, --version   Show version\n");
    printf("-h, --help      Show this message\n");
    printf("-d, --debug     Enable debug logging\n");
    printf("\n");
}

void
signal_cb(uv_signal_t *handle, int signum UNUSED)
{
    wlip_debug("Exiting...");

    // Close all open handles so the event loop stops
    uv_close((uv_handle_t *)handle, NULL);
    wayland_uninit();
}

static void
handle_walk_cb(uv_handle_t *handle, void *udata UNUSED)
{
    printf("Open handle: %s\n", uv_handle_type_name(handle->type));
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
    uv_signal_t signal;
    error_T error;

    uv_loop_init(&loop);

    if (wayland_init(&loop, NULL, &error) == FAIL)
    {
        wayland_uninit();

        wlip_log("%s", error.msg);
        assert(uv_loop_close(&loop) == 0);
        return EXIT_FAILURE;
    }

    uv_signal_init(&loop, &signal);
    uv_signal_start_oneshot(&signal, signal_cb, SIGINT);

    // Used for debugging memory leaks
    uv_run(&loop, UV_RUN_DEFAULT);

    uv_walk(&loop, handle_walk_cb, NULL);
    assert(uv_loop_close(&loop) == 0);

    return EXIT_SUCCESS;
}

// vim: ts=4 sw=4 sts=4 et
