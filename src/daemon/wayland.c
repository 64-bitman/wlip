#include "wayland.h"
#include "config.h"
#include "wlip.h"
#include <errno.h> // IWYU pragma: keep
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wayland-client.h>

static void registry_event_global(
    void               *udata,
    struct wl_registry *proxy,
    uint32_t            name,
    const char         *interface,
    uint32_t version    UNUSED
);
static void registry_event_global_remove(
    void *udata, struct wl_registry *proxy, uint32_t name
);
static const struct wl_registry_listener registry_listener = {
    .global = registry_event_global,
    .global_remove = registry_event_global_remove
};

static int
wayland_seat_new(struct wayland *wayland, struct wl_seat *proxy, uint32_t id);
static void wayland_seat_free(struct wayland_seat *seat);
static int  wayland_seat_start(struct wayland_seat *seat);

static void
seat_event_name(void *udata, struct wl_seat *proxy, const char *name);
static void seat_event_capabilities(
    void *udata, struct wl_seat *proxy, uint32_t capabilities
);
static const struct wl_seat_listener seat_listener = {
    .name = seat_event_name, .capabilities = seat_event_capabilities
};

static void data_device_event_data_offer(
    void                              *udata,
    struct ext_data_control_device_v1 *proxy,
    struct ext_data_control_offer_v1  *offer_proxy
);
static void data_device_event_selection(
    void                              *udata,
    struct ext_data_control_device_v1 *proxy,
    struct ext_data_control_offer_v1  *offer_proxy
);
static void data_device_event_primary_selection(
    void                              *udata,
    struct ext_data_control_device_v1 *proxy,
    struct ext_data_control_offer_v1  *offer_proxy
);
static void data_device_event_finished(
    void *udata, struct ext_data_control_device_v1 *proxy
);
static const struct ext_data_control_device_v1_listener data_device_listener = {
    .data_offer = data_device_event_data_offer,
    .selection = data_device_event_selection,
    .primary_selection = data_device_event_primary_selection,
    .finished = data_device_event_finished
};

static void data_offer_event_offer(
    void *udata, struct ext_data_control_offer_v1 *proxy, const char *mime_type
);
static const struct ext_data_control_offer_v1_listener data_offer_listener = {
    .offer = data_offer_event_offer
};

static void selection_event_handler(
    struct wayland_seat              *seat,
    struct ext_data_control_offer_v1 *offer,
    enum wayland_selection_type       seltype
);

static void wayland_selection_own(struct wayland_selection *sel);

static void data_source_event_send(
    void                              *udata,
    struct ext_data_control_source_v1 *proxy,
    const char                        *mime_type,
    int32_t                            fd
);
static void data_source_event_cancelled(
    void *udata, struct ext_data_control_source_v1 *proxy
);
static const struct ext_data_control_source_v1_listener data_source_listener = {
    .send = data_source_event_send, .cancelled = data_source_event_cancelled
};

/*
 * Connect to Wayland compositor and starting serving the clipboard. Returns OK
 * on success and FAIL on failure.
 */
int
wayland_init(struct wayland *wayland, struct config *config, struct wlip *wlip)
{
    const char *display_name = config->display_name;

    if (display_name == NULL)
        display_name = getenv("WAYLAND_DISPLAY");
    if (display_name == NULL)
    {
        wlip_log("$WAYLAND_DISPLAY not set");
        return FAIL;
    }

    wayland->config = config;
    wayland->wlip = wlip;
    wl_list_init(&wayland->seats);

    wayland->display = wl_display_connect(display_name);
    if (wayland->display == NULL)
    {
        wlip_err("Error connecting to display '%s'", display_name);
        return FAIL;
    }

    wayland->registry = wl_display_get_registry(wayland->display);
    if (wayland->registry == NULL)
    {
        wlip_err("Error creating registry");
        wl_display_disconnect(wayland->display);
        return FAIL;
    }

    wl_list_init(&wayland->seats);

    wl_registry_add_listener(wayland->registry, &registry_listener, wayland);

    // We will handle events when we return to the event loop

    return OK;
}

void
wayland_uninit(struct wayland *wayland)
{
    struct wayland_seat *seat, *tmp;

    wl_list_for_each_safe(seat, tmp, &wayland->seats, link)
    {
        wayland_seat_free(seat);
    }

    if (wayland->data_manager != NULL)
        ext_data_control_manager_v1_destroy(wayland->data_manager);

    wl_registry_destroy(wayland->registry);
    wl_display_disconnect(wayland->display);
}

/*
 * Sync all selections to entry "id".
 */
void
wayland_set_selection(struct wayland *wayland, int64_t id)
{
    struct wayland_seat *seat;

    wayland->entry_id = id;

    wl_list_for_each(seat, &wayland->seats, link)
    {
        if (!seat->active)
            continue;

        if (seat->sel_regular.enabled)
            wayland_selection_own(&seat->sel_regular);
        if (seat->sel_primary.enabled)
            wayland_selection_own(&seat->sel_primary);
    }
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

    if (strcmp(interface, ext_data_control_manager_v1_interface.name) == 0)
    {
        wayland->data_manager = wl_registry_bind(
            proxy, name, &ext_data_control_manager_v1_interface, 1
        );

        // We may have binded to seats before this data manager global
        struct wayland_seat *seat, *tmp;

        wl_list_for_each_safe(seat, tmp, &wayland->seats, link)
        {
            if (!seat->active && wayland_seat_start(seat) == FAIL)
                wayland_seat_free(seat);
        }
    }
    else if (strcmp(interface, wl_seat_interface.name) == 0)
    {
        struct wl_seat *seat_proxy =
            wl_registry_bind(proxy, name, &wl_seat_interface, version);

        if (seat_proxy == NULL)
            wlip_err("Error binding to seat proxy");
        else if (wayland_seat_new(wayland, seat_proxy, name) == FAIL)
            wl_seat_destroy(seat_proxy);
    }
}

static void
registry_event_global_remove(
    void *udata UNUSED, struct wl_registry *proxy UNUSED, uint32_t name
)
{
    struct wayland *wayland = udata;

    // Only handle seats, since we can handle them properly
    struct wayland_seat *seat, *tmp;

    wl_list_for_each_safe(seat, tmp, &wayland->seats, link)
    {
        if (seat->id == name)
        {
            wayland_seat_free(seat);
            break;
        }
    }
}

static void
wayland_selection_init(struct wayland_selection *sel, struct wayland_seat *seat)
{
    sel->seat = seat;
    wlip_init_timer(&sel->null_timer);
}

static void
wayland_selection_clear(struct wayland_selection *sel)
{

    if (sel->data_offer != NULL)
        ext_data_control_offer_v1_destroy(sel->data_offer);
    if (sel->data_source != NULL)
        ext_data_control_source_v1_destroy(sel->data_source);

    wlip_stop_timer(&sel->null_timer);
}

/*
 * Add a new Wayland seat struct. Returns OK on success and FAIL on failure.
 */
static int
wayland_seat_new(struct wayland *wayland, struct wl_seat *proxy, uint32_t id)
{
    struct wayland_seat *seat = calloc(1, sizeof(*seat));

    if (seat == NULL)
    {
        wlip_err("Error allocating seat structure");
        return FAIL;
    }

    seat->active = false;
    seat->wayland = wayland;
    seat->id = id;
    seat->proxy = proxy;

    wl_list_insert(&wayland->seats, &seat->link);

    wl_array_init(&seat->mime_types);

    wayland_selection_init(&seat->sel_regular, seat);
    wayland_selection_init(&seat->sel_primary, seat);

    wl_seat_add_listener(proxy, &seat_listener, seat);

    return OK;
}

static void
wayland_seat_free(struct wayland_seat *seat)
{
    if (seat->data_device != NULL)
        ext_data_control_device_v1_destroy(seat->data_device);

    wayland_selection_clear(&seat->sel_regular);
    wayland_selection_clear(&seat->sel_primary);

    wl_seat_destroy(seat->proxy);
    wl_array_release(&seat->mime_types);

    wl_list_remove(&seat->link);
    free(seat->name);
    free(seat);
}

/*
 * Start listening to events from the seat. Should only be called when seat name
 * has been obtained and data device manager has been binded to. Returns OK on
 * success and FAIL on failure.
 */
static int
wayland_seat_start(struct wayland_seat *seat)
{
    // Check if seat is configured by user. If no seats configured, then assume
    // all seats are allowed.
    struct config *config = seat->wayland->config;

    if (config->configured_seats != NULL)
    {
        bool allowed = false;

        for (uint32_t i = 0; i < config->configured_seats_len; i++)
        {
            if (strcmp(config->configured_seats[i].name, seat->name) == 0)
            {
                seat->sel_regular.enabled = config->configured_seats[i].regular;
                seat->sel_primary.enabled = config->configured_seats[i].primary;

                allowed = true;
                break;
            }
        }

        if (!allowed)
            return FAIL;
    }

    seat->data_device = ext_data_control_manager_v1_get_data_device(
        seat->wayland->data_manager, seat->proxy
    );
    if (seat->data_device == NULL)
    {
        wlip_err("Error creating data device for seat '%s'", seat->name);
        return FAIL;
    }

    ext_data_control_device_v1_add_listener(
        seat->data_device, &data_device_listener, seat
    );

    // Set selection if an entry has been set already
    if (seat->wayland->entry_id != -1)
    {
        if (seat->sel_regular.enabled)
            wayland_selection_own(&seat->sel_regular);
        if (seat->sel_primary.enabled)
            wayland_selection_own(&seat->sel_primary);
    }

    seat->active = true;

    return OK;
}

static struct wayland_selection *
wayland_seat_get_selection(
    struct wayland_seat *seat, enum wayland_selection_type type
)
{
    if (type == SELECTION_REGULAR)
        return &seat->sel_regular;
    else if (type == SELECTION_PRIMARY)
        return &seat->sel_primary;
    else
        wlip_abort("Unknown selection type %d", type);
}

static void
seat_event_name(void *udata, struct wl_seat *proxy UNUSED, const char *name)
{
    struct wayland_seat *seat = udata;
    bool                 changed = false;

    if (seat->name != NULL)
    {
        free(seat->name);
        changed = true;
    }

    seat->name = strdup(name);
    if (seat->name == NULL)
    {
        wlip_err("Error allocating seat name");
        return;
    }

    // Only start seat when first created, not when name is changed
    if (!changed && seat->wayland->data_manager != NULL &&
        wayland_seat_start(seat) == FAIL)
        wayland_seat_free(seat);
}

/*
 * Dummy function
 */
static void
seat_event_capabilities(
    void *udata           UNUSED,
    struct wl_seat *proxy UNUSED,
    uint32_t capabilities UNUSED
)
{
}

static void
data_device_event_data_offer(
    void                                    *udata,
    struct ext_data_control_device_v1 *proxy UNUSED,
    struct ext_data_control_offer_v1        *offer_proxy
)
{
    struct wayland_seat *seat = udata;

    array_clear(&seat->mime_types);

    if (ext_data_control_offer_v1_add_listener(
            offer_proxy, &data_offer_listener, seat
        ) == -1)
    {
        wlip_err("Error listening to offer proxy");
        ext_data_control_offer_v1_destroy(offer_proxy);
    }
}

static void
data_device_event_selection(
    void                                    *udata,
    struct ext_data_control_device_v1 *proxy UNUSED,
    struct ext_data_control_offer_v1        *offer_proxy
)
{
    selection_event_handler(udata, offer_proxy, SELECTION_REGULAR);
}

static void
data_device_event_primary_selection(
    void                                    *udata,
    struct ext_data_control_device_v1 *proxy UNUSED,
    struct ext_data_control_offer_v1        *offer_proxy
)
{
    selection_event_handler(udata, offer_proxy, SELECTION_PRIMARY);
}

static void
data_device_event_finished(
    void *udata, struct ext_data_control_device_v1 *proxy UNUSED
)
{
    struct wayland_seat *seat = udata;

    wlip_log("Seat data device finished, removing seat...");
    wayland_seat_free(seat);
}

static void
data_offer_event_offer(
    void                                   *udata,
    struct ext_data_control_offer_v1 *proxy UNUSED,
    const char                             *mime_type
)
{
    struct wayland_seat *seat = udata;

    char *ptr = wl_array_add(&seat->mime_types, strlen(mime_type) + 1);

    if (ptr == NULL)
        wlip_err("Error allocating mime types");
    else
        sprintf(ptr, "%s", mime_type);
}

static void
null_selection_callback(void *udata)
{
    struct wayland_selection *sel = udata;

    if (sel->data_offer == NULL)
    {
        // NULL selection event is valid, become the source client
        wayland_selection_own(sel);
    }
}

/*
 * Generic handler for selection event. Takes ownership of "offer".
 */
static void
selection_event_handler(
    struct wayland_seat              *seat,
    struct ext_data_control_offer_v1 *offer,
    enum wayland_selection_type       seltype
)
{
    struct wayland_selection *sel = wayland_seat_get_selection(seat, seltype);

    if (!sel->enabled)
    {
        if (offer != NULL)
            ext_data_control_offer_v1_destroy(offer);
        return;
    }

    if (sel->data_offer != NULL)
        ext_data_control_offer_v1_destroy(sel->data_offer);

    if (sel->data_source != NULL)
    {
        // Currently source client, ignore
        if (offer != NULL)
            ext_data_control_offer_v1_destroy(offer);
        sel->data_offer = NULL;
        return;
    }

    sel->data_offer = offer;

    if (offer == NULL)
    {
        if (sel->seat->wayland->entry_id == -1)
            // Prevent recursive loop
            return;

        // Selection has been cleared, try becoming the source client. Add a
        // delay in case it is followed up by an actual selection event.
        wlip_start_timer(
            sel->seat->wayland->wlip,
            &sel->null_timer,
            1,
            null_selection_callback,
            sel
        );
        return;
    }

    sel->seat->wayland->entry_id =
        wlip_new_selection(seat->wayland->wlip, offer, &seat->mime_types);

    array_clear(&seat->mime_types);
}

/*
 * Become the source client for the given selection. If there are no mime types,
 * then clear the selection.
 */
static void
wayland_selection_own(struct wayland_selection *sel)
{
    struct ext_data_control_source_v1 *source = NULL;

    if (sel->seat->wayland->entry_id != -1)
    {
        source = ext_data_control_manager_v1_create_data_source(
            sel->seat->wayland->data_manager
        );

        if (source == NULL)
        {
            wlip_err("Error creating data source");
            return;
        }

        database_offer_mime_types(
            &sel->seat->wayland->wlip->database,
            sel->seat->wayland->entry_id,
            source
        );

        ext_data_control_source_v1_add_listener(
            source, &data_source_listener, sel
        );
    }

    if (sel->data_source != NULL)
        ext_data_control_source_v1_destroy(sel->data_source);

    sel->data_source = source;

    if (sel->type == SELECTION_REGULAR)
        ext_data_control_device_v1_set_selection(
            sel->seat->data_device, source
        );
    else if (sel->type == SELECTION_PRIMARY)
        ext_data_control_device_v1_set_primary_selection(
            sel->seat->data_device, source
        );
    else
        wlip_abort("Unknown selection type %d", sel->type);
}

static void
data_source_event_send(
    void                                    *udata,
    struct ext_data_control_source_v1 *proxy UNUSED,
    const char                              *mime_type,
    int32_t                                  fd
)
{
    struct wayland_selection *sel = udata;

    if (sel->seat->wayland->entry_id == -1)
    {
        // Shouldn't happen?
        wlip_log("Entry id is -1?");
        return;
    }

    sqlite3_stmt *stmt = database_deserialize_mime_type_data(
        &sel->seat->wayland->wlip->database,
        sel->seat->wayland->entry_id,
        mime_type
    );

    if (stmt == NULL)
        goto exit;

    const uint8_t *data = sqlite3_column_blob(stmt, 0);
    int            len = sqlite3_column_bytes(stmt, 0);

    if (data != NULL && write_data(fd, data, len) == FAIL)
        wlip_err("Error writing data");

    sqlite3_reset(stmt);

exit:
    close(fd);
}

static void
data_source_event_cancelled(
    void *udata, struct ext_data_control_source_v1 *proxy
)
{
    struct wayland_selection *sel = udata;

    if (sel->data_source == proxy)
        sel->data_source = NULL;
    ext_data_control_source_v1_destroy(proxy);
}
