#include "wayland.h"
#include "event.h"
#include "util.h"

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
    wl_list_init(&wayland->outputs);

    return OK;
}

void
wayland_uninit(struct wayland *wayland)
{
    wayland_base_uninit(&wayland->base);
}

struct wayland_output *
wayland_find_output(struct wayland *wayland, const char *name)
{
    struct wayland_output *output;

    wl_list_for_each(output, &wayland->outputs, link)
    {
        if (output->name != NULL && strcmp(output->name, name) == 0)
            return output;
    }
    return NULL;
}
