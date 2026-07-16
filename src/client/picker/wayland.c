#include "wayland.h"
#include "event.h"
#include "util.h"
#include <string.h>
#include <sys/mman.h>

// clang-format off
// clang-format on

/*
 * Run wayland client. Returns OK on success and FAIL on failure.
 */
int
wayland_init(struct wayland *wayland, struct eventloop *loop)
{
    memset(wayland, 0, sizeof(struct wayland));

    if (wayland_base_init(&wayland->base, NULL, loop) == FAIL)
        return FAIL;

    wl_list_init(&wayland->seats);

    return OK;
}

void
wayland_uninit(struct wayland *wayland)
{
    wayland_base_uninit(&wayland->base);
    close(wayland->buffd);
}
