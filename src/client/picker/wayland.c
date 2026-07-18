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

static void wayland_seat_new(struct wayland *wayland, struct wl_seat *proxy, uint32_t id);
static void wayland_seat_free(struct wayland_seat *seat);

static void seat_event_name(void *udata, struct wl_seat *proxy, const char *name);
static void seat_event_capabilities(void *udata, struct wl_seat *proxy, uint32_t capabilities);
static const struct wl_seat_listener seat_listener = {
    .name = seat_event_name,
    .capabilities = seat_event_capabilities
};

static void wayland_output_new(struct wayland *wayland, struct wl_output *proxy, uint32_t id);
static void wayland_output_free(struct wayland_output *output);

static void output_event_scale(void *udata, struct wl_output *proxy, int32_t factor);
static void output_event_name(void *udata, struct wl_output *proxy, const char *name);

static const struct wl_output_listener output_listener = {
    .geometry = wayland_event_noop,
    .mode = wayland_event_noop,
    .done = wayland_event_noop,
    .scale = output_event_scale,
    .name = output_event_name,
    .description = wayland_event_noop,
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
    struct wayland_seat *seat, *seat_tmp;

    wl_list_for_each_safe(seat, seat_tmp, &wayland->seats, link)
    {
        wayland_seat_free(seat);
    }

    struct wayland_output *output, *output_tmp;

    wl_list_for_each_safe(output, output_tmp, &wayland->outputs, link)
    {
        wayland_output_free(output);
    }

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
        struct wl_seat *seat_proxy =
            wl_registry_bind(proxy, name, &wl_seat_interface, 2);
        wayland_seat_new(wayland, seat_proxy, name);
    }
    else if (strcmp(interface, wl_output_interface.name) == 0)
    {
        struct wl_output *output_proxy =
            wl_registry_bind(proxy, name, &wl_output_interface, 4);
        wayland_output_new(wayland, output_proxy, name);
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
    void *udata, struct wl_registry *proxy UNUSED, uint32_t name
)
{
    struct wayland *wayland = udata;

    struct wayland_seat *seat, *seat_tmp;

    wl_list_for_each_safe(seat, seat_tmp, &wayland->seats, link)
    {
        if (seat->id == name)
        {
            wayland_seat_free(seat);
            return;
        }
    }

    struct wayland_output *output, *output_tmp;

    wl_list_for_each_safe(output, output_tmp, &wayland->outputs, link)
    {
        if (output->id == name)
        {
            wayland_output_free(output);
            return;
        }
    }
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

void
wayland_event_noop()
{
}

static void
wayland_seat_new(struct wayland *wayland, struct wl_seat *proxy, uint32_t id)
{
    struct wayland_seat *seat = calloc(1, sizeof(*seat));

    if (seat == NULL)
        return;

    seat->wayland = wayland;
    seat->proxy = proxy;
    seat->id = id;

    wl_seat_add_listener(proxy, &seat_listener, seat);

    wl_list_insert(&wayland->seats, &seat->link);

    return;
}

static void
wayland_seat_free(struct wayland_seat *seat)
{
    wl_seat_destroy(seat->proxy);
    free(seat->name);

    if (seat->keyboard != NULL)
        wl_keyboard_destroy(seat->keyboard);
    if (seat->pointer != NULL)
        wl_pointer_destroy(seat->pointer);
    if (seat->touch != NULL)
        wl_touch_destroy(seat->touch);

    wl_list_remove(&seat->link);
    free(seat);
}

static void
seat_event_name(void *udata, struct wl_seat *proxy UNUSED, const char *name)
{
    struct wayland_seat *seat = udata;

    free(seat->name);
    seat->name = strdup(name);
}

static void
seat_event_capabilities(
    void *udata, struct wl_seat *proxy, uint32_t capabilities
)
{
    struct wayland_seat *seat = udata;

    if (capabilities & WL_SEAT_CAPABILITY_KEYBOARD)
    {
        if (seat->keyboard == NULL)
            seat->keyboard = wl_seat_get_keyboard(proxy);
    }
}

static void
wayland_output_new(
    struct wayland *wayland, struct wl_output *proxy, uint32_t id
)
{
    struct wayland_output *output = calloc(1, sizeof(*output));

    if (output == NULL)
        return;

    output->wayland = wayland;
    output->proxy = proxy;
    output->id = id;

    output->subpixel = WL_OUTPUT_SUBPIXEL_UNKNOWN;
    output->scale = 1;

    wl_output_add_listener(proxy, &output_listener, output);

    wl_list_insert(&wayland->outputs, &output->link);
}

static void
wayland_output_free(struct wayland_output *output)
{
    wl_output_destroy(output->proxy);
    free(output->name);

    if (output->wayland->surf.output == output)
        output->wayland->surf.output = NULL;

    wl_list_remove(&output->link);
    free(output);
}

static void
output_event_scale(void *udata, struct wl_output *proxy UNUSED, int32_t factor)
{
    struct wayland_output *output = udata;

    output->scale = factor;
}

static void
output_event_name(void *udata, struct wl_output *proxy UNUSED, const char *name)
{
    struct wayland_output *output = udata;

    free(output->name);
    output->name = strdup(name);
}
