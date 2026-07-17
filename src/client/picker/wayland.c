#include "wayland.h"
#include "event.h"
#include "util.h"

// clang-format off
static void registry_event_global(void *udata, struct wl_registry *proxy, uint32_t name, const char *interface, uint32_t version);
static void registry_event_global_remove(void *udata, struct wl_registry *proxy, uint32_t name);

static const struct wl_registry_listener registry_listener = {
    .global = registry_event_global,
    .global_remove = registry_event_global_remove,
};
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

    wl_registry_add_listener(
        wayland->base.registry, &registry_listener, wayland
    );

    // Get initial globals and outputs
    wl_display_roundtrip(wayland->base.display);

    surface_init(&wayland->surf, wayland, 500, 500, NULL);

    return OK;
}

void
wayland_uninit(struct wayland *wayland)
{
    surface_uninit(&wayland->surf);

    wl_compositor_destroy(wayland->compositor);
    wl_shm_destroy(wayland->shm);
    zwlr_layer_shell_v1_destroy(wayland->layer_shell);
    if (wayland->frac_mgr != NULL)
        wp_fractional_scale_manager_v1_destroy(wayland->frac_mgr);
    wp_viewporter_destroy(wayland->vporter);

    wayland_base_uninit(&wayland->base);
}

static void
registry_event_global(
    void               *udata,
    struct wl_registry *proxy,
    uint32_t            name,
    const char         *interface,
    uint32_t version    UNUSED
)
{
    struct wayland *wayland = udata;

    // TODO: handle versions
    if (strcmp(interface, wl_compositor_interface.name) == 0)
    {
        wayland->compositor =
            wl_registry_bind(proxy, name, &wl_compositor_interface, 4);
    }
    else if (strcmp(interface, wl_shm_interface.name) == 0)
    {
        wayland->shm = wl_registry_bind(proxy, name, &wl_shm_interface, 1);
    }
    else if (strcmp(interface, wl_seat_interface.name) == 0)
    {
        // TODO
    }
    else if (strcmp(interface, wl_output_interface.name) == 0)
    {
        // TODO
    }
    else if (strcmp(interface, zwlr_layer_shell_v1_interface.name) == 0)
    {
        wayland->layer_shell =
            wl_registry_bind(proxy, name, &zwlr_layer_shell_v1_interface, 2);
    }
    else if (strcmp(interface, wp_fractional_scale_manager_v1_interface.name) ==
             0)
    {
        wayland->frac_mgr = wl_registry_bind(
            proxy, name, &wp_fractional_scale_manager_v1_interface, 1
        );
    }
    else if (strcmp(interface, wp_viewporter_interface.name) == 0)
    {
        wayland->vporter =
            wl_registry_bind(proxy, name, &wp_viewporter_interface, 1);
    }
}

static void
registry_event_global_remove(
    void *udata, struct wl_registry *proxy, uint32_t name
)
{
}

/*
 * Find the output with the given name. Returns NULL if not found.
 */
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
