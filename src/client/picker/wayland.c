#include "wayland.h"
#include "alloc.h"
#include "event.h"
#include "log.h"
#include "util.h"
#include <string.h>
#include <sys/mman.h>

// clang-format off
static void registry_event_global(void *udata, struct wl_registry *proxy, uint32_t name, const char *interface, uint32_t version);
static void registry_event_global_remove(void *udata, struct wl_registry *proxy, uint32_t name);

static const struct wl_registry_listener registry_listener = {
    .global = registry_event_global,
    .global_remove = registry_event_global_remove
};

static void wayland_seat_new(struct wayland *wayland, struct wl_seat *proxy, uint32_t id);
static void wayland_seat_free(struct wayland_seat *seat);

static void seat_event_name(void *udata, struct wl_seat *proxy, const char *name);
static void seat_event_capabilities(void *udata, struct wl_seat *proxy, uint32_t capabilities);

static const struct wl_seat_listener seat_listener = {
    .name = seat_event_name,
    .capabilities = seat_event_capabilities
};

static void shm_event_format(void *udata, struct wl_shm *shm, uint32_t format);

static const struct wl_shm_listener shm_listener = {
    .format = shm_event_format
};

static void frac_event_preferred_scale(void *udata, struct wp_fractional_scale_v1 *frac, uint32_t numer);

static const struct wp_fractional_scale_v1_listener frac_listener = {
    .preferred_scale = frac_event_preferred_scale
};

static void surf_event_enter(void *udata, struct wl_surface *surf, struct wl_output *output);
static void surf_event_leave(void *udata, struct wl_surface *surf, struct wl_output *output);
static void surf_event_preferred_buffer_scale(void *udata, struct wl_surface *surf, int32_t factor);
static void surf_event_preferred_buffer_transform(void *udata, struct wl_surface *surf, uint32_t transform);

static const struct wl_surface_listener surf_listener = {
    .enter = surf_event_enter,
    .leave = surf_event_leave,
    .preferred_buffer_scale = surf_event_preferred_buffer_scale,
    .preferred_buffer_transform = surf_event_preferred_buffer_transform,
};

static void layer_surf_event_configure(void *udata, struct zwlr_layer_surface_v1 *lsurf, uint32_t serial, uint32_t w, uint32_t h);
static void layer_surf_event_closed(void *udata, struct zwlr_layer_surface_v1 *lsurf);

static const struct zwlr_layer_surface_v1_listener layer_surf_listener = {
    .configure = layer_surf_event_configure,
    .closed = layer_surf_event_closed
};
// clang-format on

/*
 * Run wayland client. Returns OK on success and FAIL on failure.
 */
int
wayland_init(struct wayland *wayland, struct eventloop *loop)
{
    memset(wayland, 0, sizeof(struct wayland));

    wayland->buffd = memfd_create("wlippicker", MFD_CLOEXEC);

    if (wayland->buffd == -1)
    {
        log_errerror("Error creating memfd");
        return FAIL;
    }

    if (wayland_base_init(&wayland->base, NULL, loop) == FAIL)
        return FAIL;

    wl_list_init(&wayland->seats);

    struct wl_registry *registry = wayland->base.registry;

    wl_registry_add_listener(registry, &registry_listener, wayland);

    // Bind initial globals
    wl_display_roundtrip(wayland->base.display);

    if (wayland->compositor == NULL || wayland->shm == NULL ||
        wayland->layer_shell == NULL)
        // TODO add error message
        goto fail;

    struct wl_surface *surf = wl_compositor_create_surface(wayland->compositor);
    struct zwlr_layer_surface_v1 *lsurf = zwlr_layer_shell_v1_get_layer_surface(
        wayland->layer_shell,
        surf,
        NULL,
        ZWLR_LAYER_SHELL_V1_LAYER_OVERLAY,
        "wlippicker"
    );

    zwlr_layer_surface_v1_set_size(lsurf, 500, 600);
    zwlr_layer_surface_v1_set_anchor(lsurf, 0); // Center
    zwlr_layer_surface_v1_set_keyboard_interactivity(
        lsurf, ZWLR_LAYER_SURFACE_V1_KEYBOARD_INTERACTIVITY_EXCLUSIVE
    );

    wl_surface_commit(surf);
    wl_surface_add_listener(surf, &surf_listener, wayland);
    zwlr_layer_surface_v1_add_listener(lsurf, &layer_surf_listener, wayland);

    if (wayland->frac_mgr != NULL)
    {
        wayland->frac = wp_fractional_scale_manager_v1_get_fractional_scale(
            wayland->frac_mgr, surf
        );

        wp_fractional_scale_v1_add_listener(
            wayland->frac, &frac_listener, wayland
        );
    }

    wayland->surf = surf;
    wayland->lsurf = lsurf;

    return OK;
fail:
    wayland_uninit(wayland);
    return FAIL;
}

void
wayland_uninit(struct wayland *wayland)
{
    struct wayland_seat *seat, *tmp;

    wl_list_for_each_safe(seat, tmp, &wayland->seats, link)
    {
        wayland_seat_free(seat);
    }

    if (wayland->compositor != NULL)
        wl_compositor_destroy(wayland->compositor);
    if (wayland->shm != NULL)
        wl_shm_destroy(wayland->shm);
    if (wayland->layer_shell != NULL)
        zwlr_layer_shell_v1_destroy(wayland->layer_shell);
    if (wayland->frac_mgr != NULL)
        wp_fractional_scale_manager_v1_destroy(wayland->frac_mgr);
    if (wayland->surf != NULL)
        wl_surface_destroy(wayland->surf);
    if (wayland->lsurf != NULL)
        zwlr_layer_surface_v1_destroy(wayland->lsurf);
    if (wayland->frac != NULL)
        wp_fractional_scale_v1_destroy(wayland->frac);

    if (wayland->csurf != NULL)
        cairo_surface_destroy(wayland->csurf);
    if (wayland->cr != NULL)
        cairo_destroy(wayland->cr);

    wayland_base_uninit(&wayland->base);
    close(wayland->buffd);
}

static void
registry_event_global(
    void               *udata,
    struct wl_registry *registry,
    uint32_t            name,
    const char         *interface,
    uint32_t            version
)
{
    struct wayland *wayland = udata;

    // TODO check global interface versions and maybe error
    if (strcmp(interface, wl_compositor_interface.name) == 0)
    {
        wayland->compositor =
            wl_registry_bind(registry, name, &wl_compositor_interface, version);
    }
    else if (strcmp(interface, wl_shm_interface.name) == 0)
    {
        wayland->shm = wl_registry_bind(registry, name, &wl_shm_interface, 1);
        wl_shm_add_listener(wayland->shm, &shm_listener, NULL);
    }
    else if (strcmp(interface, wl_seat_interface.name) == 0)
    {
        struct wl_seat *proxy =
            wl_registry_bind(registry, name, &wl_seat_interface, 5);

        wayland_seat_new(wayland, proxy, name);
    }
    else if (strcmp(interface, zwlr_layer_shell_v1_interface.name) == 0)
    {
        wayland->layer_shell =
            wl_registry_bind(registry, name, &zwlr_layer_shell_v1_interface, 1);
    }
    else if (strcmp(interface, wp_fractional_scale_manager_v1_interface.name) ==
             0)
    {
        wayland->frac_mgr = wl_registry_bind(
            registry, name, &wp_fractional_scale_manager_v1_interface, 1
        );
    }
}

static void
registry_event_global_remove(
    void *udata UNUSED, struct wl_registry *proxy UNUSED, uint32_t name
)
{
    struct wayland *wayland = udata;

    struct wayland_seat *seat, *tmp;

    wl_list_for_each_safe(seat, tmp, &wayland->seats, link)
    {
        if (seat->id == name)
        {
            log_debug("Seat \"%s\" removed", seat->name);
            wayland_seat_free(seat);
            break;
        }
    }
}

static void
wayland_seat_new(struct wayland *wayland, struct wl_seat *proxy, uint32_t id)
{
    struct wayland_seat *seat = do_calloc(1, sizeof(*seat));

    seat->proxy = proxy;
    seat->id = id;

    wl_seat_add_listener(proxy, &seat_listener, seat);

    wl_list_insert(&wayland->seats, &seat->link);
}

static void
wayland_seat_free(struct wayland_seat *seat)
{
    wl_seat_destroy(seat->proxy);

    if (seat->pointer != NULL)
        wl_pointer_destroy(seat->pointer);
    if (seat->keyboard != NULL)
        wl_keyboard_destroy(seat->keyboard);
    if (seat->touch != NULL)
        wl_touch_destroy(seat->touch);

    do_free(seat->name);
    do_free(seat);

    wl_list_remove(&seat->link);
}

static void
seat_event_name(void *udata, struct wl_seat *proxy UNUSED, const char *name)
{
    struct wayland_seat *seat = udata;

    do_free(seat->name);
    seat->name = do_strdup(name);
}

static void
seat_event_capabilities(
    void *udata, struct wl_seat *proxy, uint32_t capabilities
)
{
    struct wayland_seat *seat = udata;

    if (capabilities & WL_SEAT_CAPABILITY_POINTER)
    {
        if (seat->pointer == NULL)
        {
            seat->pointer = wl_seat_get_pointer(proxy);
            // TODO listen
        }
    }
    else if (seat->pointer != NULL)
    {
        wl_pointer_destroy(seat->pointer);
        seat->pointer = NULL;
    }

    if (capabilities & WL_SEAT_CAPABILITY_KEYBOARD)
    {
        if (seat->keyboard == NULL)
        {
            seat->keyboard = wl_seat_get_keyboard(proxy);
            // TODO listen
        }
    }
    else if (seat->keyboard != NULL)
    {
        wl_keyboard_destroy(seat->keyboard);
        seat->keyboard = NULL;
    }

    if (capabilities & WL_SEAT_CAPABILITY_TOUCH)
    {
        if (seat->touch == NULL)
        {
            seat->touch = wl_seat_get_touch(proxy);
            // TODO listen
        }
    }
    else if (seat->touch != NULL)
    {
        wl_touch_destroy(seat->touch);
        seat->touch = NULL;
    }
}

/*
 * Unused because we always use ARGB32
 */
static void
shm_event_format(
    void *udata UNUSED, struct wl_shm *shm UNUSED, uint32_t format UNUSED
)
{
}

static void
frac_event_preferred_scale(
    void *udata, struct wp_fractional_scale_v1 *frac UNUSED, uint32_t numer
)
{
    struct wayland *wayland = udata;

    wayland->scale = (double)numer / 120.0;
}

static void
surf_event_enter(void *udata, struct wl_surface *surf, struct wl_output *output)
{
}

static void
surf_event_leave(void *udata, struct wl_surface *surf, struct wl_output *output)
{
}

static void
surf_event_preferred_buffer_scale(
    void *udata, struct wl_surface *surf, int32_t factor
)
{
    struct wayland *wayland = udata;

    if (wayland->frac == NULL)
        wayland->scale = (double)factor;
}

static void
surf_event_preferred_buffer_transform(
    void *udata, struct wl_surface *surf, uint32_t transform
)
{
    struct wayland *wayland = udata;

    wl_surface_set_buffer_transform(wayland->surf, transform);
    wl_surface_commit(surf);
}

static void
layer_surf_event_configure(
    void                         *udata,
    struct zwlr_layer_surface_v1 *lsurf,
    uint32_t                      serial,
    uint32_t                      w,
    uint32_t                      h
)
{
    struct wayland *wayland = udata;

    zwlr_layer_surface_v1_ack_configure(lsurf, serial);

    uint32_t stride = w * 4;
    uint32_t sz = stride * h;

    if (ftruncate(wayland->buffd, sz) == -1)
    {
        log_errwarn("Error setting memfd size");
        return;
    }

    void *data =
        mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, wayland->buffd, 0);

    if (data == MAP_FAILED)
    {
        log_errwarn("Error setting mapping memfd");
        return;
    }

    struct wl_shm_pool *pool =
        wl_shm_create_pool(wayland->shm, wayland->buffd, sz);
    struct wl_buffer *buf = wl_shm_pool_create_buffer(
        pool, 0, w, h, stride, WL_SHM_FORMAT_ARGB8888
    );

    wl_shm_pool_destroy(pool);

    wayland->csurf = cairo_image_surface_create_for_data(
        data, CAIRO_FORMAT_ARGB32, w, h, stride
    );

    cairo_t *cr = cairo_create(wayland->csurf);

    cairo_scale(cr, wayland->scale, wayland->scale);
    cairo_set_source_rgba(cr, 1.0, 0.0, 0.0, 1.0);
    cairo_paint(cr);
    cairo_surface_flush(wayland->csurf);

    wayland->cr = cr;

    wl_surface_attach(wayland->surf, buf, 0, 0);
    wl_surface_damage_buffer(wayland->surf, 0, 0, w, h);
    wl_surface_commit(wayland->surf);
}

static void
layer_surf_event_closed(void *udata, struct zwlr_layer_surface_v1 *lsurf)
{
    struct wayland *wayland = udata;

    log_info("Layer surface destroyed");
    eventloop_stop(wayland->base.loop);
}
