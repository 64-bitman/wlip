#include "surface.h"
#include "util.h"

// clang-format off
static void surf_event_enter(void *udata, struct wl_surface *proxy, struct wl_output *out);
static void surf_event_leave(void *udata, struct wl_surface *proxy, struct wl_output *out);
static void surf_event_preferred_buffer_scale(void *udata, struct wl_surface *proxy, int32_t factor);
static void surf_event_preferred_buffer_transform(void *udata, struct wl_surface *proxy, uint32_t transform);

static const struct wl_surface_listener surf_listener = {
    .enter = surf_event_enter,
    .leave = surf_event_leave,
    .preferred_buffer_scale = surf_event_preferred_buffer_scale,
    .preferred_buffer_transform = surf_event_preferred_buffer_transform,
};

static void lsurf_event_configure(void *udata, struct zwlr_layer_surface_v1 *proxy, uint32_t serial, uint32_t w, uint32_t h);
static void lsurf_event_closed(void *udata, struct zwlr_layer_surface_v1 *proxy);

static const struct zwlr_layer_surface_v1_listener lsurf_listener = {
    .configure = lsurf_event_configure,
    .closed = lsurf_event_closed
};

static void frac_event_preferred_scale(void *udata, struct wp_fractional_scale_v1 *proxy, uint32_t scale);

static const struct wp_fractional_scale_v1_listener frac_listener = {
    .preferred_scale = frac_event_preferred_scale
};
// clang-format on

int
surface_init(
    struct surface *surf, struct wayland *wayland, const char *output_name
)
{
    struct wayland_output *output = wayland_find_output(wayland, output_name);

    surf->surf = wl_compositor_create_surface(wayland->compositor);

    wl_surface_add_listener(surf->surf, &surf_listener, surf);

    surf->lsurf = zwlr_layer_shell_v1_get_layer_surface(
        wayland->layer_shell,
        surf->surf,
        output->proxy,
        ZWLR_LAYER_SHELL_V1_LAYER_OVERLAY,
        "wlippicker"
    );

    zwlr_layer_surface_v1_add_listener(surf->lsurf, &lsurf_listener, surf);

    if (wayland->frac_mgr != NULL)
    {
        surf->frac = wp_fractional_scale_manager_v1_get_fractional_scale(
            wayland->frac_mgr, surf->surf
        );
        wp_fractional_scale_v1_add_listener(surf->frac, &frac_listener, surf);
    }

    surf->vport = wp_viewporter_get_viewport(wayland->vporter, surf->surf);
    surf->scale = 1.0;

    return OK;
}

void
surface_uninit(struct surface *surf)
{
    wp_viewport_destroy(surf->vport);
    if (surf->frac != NULL)
        wp_fractional_scale_v1_destroy(surf->frac);
    zwlr_layer_surface_v1_destroy(surf->lsurf);
    wl_surface_destroy(surf->surf);

    buffer_pool_uninit(&surf->pool);
}

static void
surf_event_enter(
    void *udata, struct wl_surface *proxy UNUSED, struct wl_output *out
)
{
    struct surface        *surf = udata;
    struct wayland_output *output = wl_output_get_user_data(out);
}

static void
surf_event_leave(
    void *udata, struct wl_surface *proxy UNUSED, struct wl_output *out
)
{
    struct surface        *surf = udata;
    struct wayland_output *output = wl_output_get_user_data(out);
}

static void
surf_event_preferred_buffer_scale(
    void *udata, struct wl_surface *proxy, int32_t factor
)
{
}

static void
surf_event_preferred_buffer_transform(
    void *udata, struct wl_surface *proxy, uint32_t transform
)
{
}

static void
lsurf_event_configure(
    void                         *udata,
    struct zwlr_layer_surface_v1 *proxy,
    uint32_t                      serial,
    uint32_t                      w,
    uint32_t                      h
)
{
}

static void
lsurf_event_closed(void *udata, struct zwlr_layer_surface_v1 *proxy)
{
}

static void
frac_event_preferred_scale(
    void *udata, struct wp_fractional_scale_v1 *proxy, uint32_t scale
)
{
}
