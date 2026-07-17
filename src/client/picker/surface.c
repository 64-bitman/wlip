#include "surface.h"
#include "log.h"
#include "util.h"
#include "wayland.h"

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

/*
 * Initialize the surface for the given output. If "output_name" is NULL, then
 * let the compositor decide which output to use.
 */
int
surface_init(
    struct surface *surf,
    struct wayland *wayland,
    uint32_t        w,
    uint32_t        h,
    const char     *output_name
)
{
    struct wayland_output *output = NULL;

    if (output_name != NULL)
    {
        output = wayland_find_output(wayland, output_name);

        if (output == NULL)
            return FAIL;
    }

    surf->surf = wl_compositor_create_surface(wayland->compositor);

    wl_surface_add_listener(surf->surf, &surf_listener, surf);

    surf->lsurf = zwlr_layer_shell_v1_get_layer_surface(
        wayland->layer_shell,
        surf->surf,
        output == NULL ? NULL : output->proxy,
        ZWLR_LAYER_SHELL_V1_LAYER_OVERLAY,
        "wlippicker"
    );

    zwlr_layer_surface_v1_set_size(surf->lsurf, w, h);
    zwlr_layer_surface_v1_set_keyboard_interactivity(
        surf->lsurf, ZWLR_LAYER_SURFACE_V1_KEYBOARD_INTERACTIVITY_EXCLUSIVE
    );

    wl_surface_commit(surf->surf);

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
    surf->width = w;
    surf->height = h;
    surf->wayland = wayland;
    surf->dirty = true;

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

    for (int i = 0; i < 2; i++)
        buffer_uninit(surf->buffers + i);

    memset(surf, 0, sizeof(*surf));
}

static void
surface_redraw(struct surface *surf, uint32_t w, uint32_t h, double scale)
{
    if (!surf->dirty && surf->width == w && surf->height == h &&
        fabs(scale - surf->scale) < 0.01)
        return;

    surf->width = w;
    surf->height = h;
    surf->scale = scale;

    surf->cur_buffer = buffer_get_next(
        surf->buffers, surf->wayland->shm, w * scale, h * scale
    );
    if (surf->cur_buffer == NULL)
        return;

    zwlr_layer_surface_v1_set_size(surf->lsurf, w, h);

    struct buffer *buffer = surf->cur_buffer;

    cairo_scale(buffer->cr, scale, scale);

    cairo_set_source_rgb(buffer->cr, 1.0, 0.0, 0.0);
    cairo_paint(buffer->cr);
    cairo_surface_flush(buffer->csurf);

    if (surf->frac != NULL)
    {
        wl_surface_set_buffer_scale(surf->surf, 1);
        wp_viewport_set_destination(surf->vport, surf->width, surf->height);
    }
    else
    {
        wl_surface_set_buffer_scale(surf->surf, (int32_t)surf->scale);
        wp_viewport_set_destination(surf->vport, -1, -1);
    }

    wl_surface_attach(surf->surf, buffer->buffer, 0, 0);
    wl_surface_damage_buffer(surf->surf, 0, 0, w * scale, h * scale);
    wl_surface_commit(surf->surf);
    buffer->busy = true;
    surf->dirty = false;
}

static void
surf_event_enter(
    void *udata              UNUSED,
    struct wl_surface *proxy UNUSED,
    struct wl_output *out    UNUSED
)
{
}

static void
surf_event_leave(
    void *udata              UNUSED,
    struct wl_surface *proxy UNUSED,
    struct wl_output *out    UNUSED
)
{
}

static void
surf_event_preferred_buffer_scale(
    void *udata, struct wl_surface *proxy UNUSED, int32_t factor
)
{
    struct surface *surf = udata;

    if (surf->frac == NULL)
    {
        log_debug("New buffer scale: %d", factor);
        surface_redraw(surf, surf->width, surf->height, (double)factor);
    }
}

static void
surf_event_preferred_buffer_transform(
    void *udata UNUSED, struct wl_surface *proxy, uint32_t transform UNUSED
)
{
    wl_surface_set_buffer_transform(proxy, WL_OUTPUT_TRANSFORM_NORMAL);
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
    struct surface *surf = udata;

    zwlr_layer_surface_v1_ack_configure(proxy, serial);

    surface_redraw(surf, w, h, surf->scale);
}

static void
lsurf_event_closed(void *udata, struct zwlr_layer_surface_v1 *proxy UNUSED)
{
    struct surface *surf = udata;

    log_info("Surface closed");
    surface_uninit(surf);
}

static void
frac_event_preferred_scale(
    void *udata, struct wp_fractional_scale_v1 *proxy UNUSED, uint32_t scale
)
{
    struct surface *surf = udata;
    double          factor = (double)scale / 120;

    log_debug("New surface scale: %u/120 = %lf", scale, factor);
    surface_redraw(surf, surf->width, surf->height, factor);
}
