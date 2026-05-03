#include "wayland.h"
#include "config.h"
#include "event.h"
#include "log.h"
#include "util.h"
#include "wayland_base.h"
#include "wlip.h"
#include <errno.h> // IWYU pragma: keep
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wayland-client.h>

struct send_context
{
    sqlite3_stmt  *stmt;
    int            remaining;
    const uint8_t *data;

    struct eventsource source;

    struct wl_list link;
};

// clang-format off
static void registry_event_global(void *udata, struct wl_registry *proxy, uint32_t name, const char *interface, uint32_t version);
static void registry_event_global_remove(void *udata, struct wl_registry *proxy, uint32_t name);

static const struct wl_registry_listener registry_listener = {
    .global = registry_event_global,
    .global_remove = registry_event_global_remove
};

static int wayland_seat_new(struct wayland *wayland, struct wl_seat *proxy, uint32_t id);
static void wayland_seat_free(struct wayland_seat *seat);
static int wayland_seat_start(struct wayland_seat *seat);

static void seat_event_name(void *udata, struct wl_seat *proxy, const char *name);
static void seat_event_capabilities(void *udata, struct wl_seat *proxy, uint32_t capabilities);

static const struct wl_seat_listener seat_listener = {
    .name = seat_event_name,
    .capabilities = seat_event_capabilities
};

static void data_device_event_data_offer(void *udata, struct ext_data_control_device_v1 *proxy, struct ext_data_control_offer_v1 *offer_proxy);
static void data_device_event_selection(void *udata, struct ext_data_control_device_v1 *proxy, struct ext_data_control_offer_v1 *offer_proxy);
static void data_device_event_primary_selection(void *udata, struct ext_data_control_device_v1 *proxy, struct ext_data_control_offer_v1 *offer_proxy);
static void data_device_event_finished(void *udata, struct ext_data_control_device_v1 *proxy);

static const struct ext_data_control_device_v1_listener data_device_listener = {
    .data_offer = data_device_event_data_offer,
    .selection = data_device_event_selection,
    .primary_selection = data_device_event_primary_selection,
    .finished = data_device_event_finished
};

static void data_offer_event_offer(void *udata, struct ext_data_control_offer_v1 *proxy, const char *mime_type);

static const struct ext_data_control_offer_v1_listener data_offer_listener = {
    .offer = data_offer_event_offer
};

static void null_selection_callback(void *udata);
static void selection_event_handler(struct wayland_seat *seat, struct ext_data_control_offer_v1 *offer, enum wayland_selection_type seltype);

static void wayland_selection_own(struct wayland_selection *sel);

static void send_context_free(struct send_context *ctx);
static void data_source_event_send(void *udata, struct ext_data_control_source_v1 *proxy, const char *mime_type, int32_t fd);
static void data_source_event_cancelled(void *udata, struct ext_data_control_source_v1 *proxy);

static const struct ext_data_control_source_v1_listener data_source_listener = {
    .send = data_source_event_send,
    .cancelled = data_source_event_cancelled
};
// clang-format on

/*
 * Connect to Wayland compositor and starting serving the clipboard. Returns OK
 * on success and FAIL on failure.
 */
int
wayland_init(struct wayland *wayland, struct wlip *wlip)
{
    const char *display_name = wlip->config.display_name;

    if (wayland_base_init(&wayland->base, display_name, wlip->loop) == FAIL)
        return FAIL;

    wl_registry_add_listener(
        wayland->base.registry, &registry_listener, wayland
    );

    wayland->wlip = wlip;
    wayland->data_manager = NULL;
    wl_list_init(&wayland->seats);
    wayland->entry_id = -1;

    // Get initial globals
    if (wl_display_roundtrip(wayland->base.display) == -1)
    {
        log_errerror("Error doing initial display roundtrip");
        goto fail;
    }

    if (wayland->data_manager == NULL)
    {
        log_error("ext-data-control-v1 protocol not supported by compositor");
        goto fail;
    }

    return OK;
fail:
    wayland_base_uninit(&wayland->base);
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

    if (wayland->data_manager != NULL)
        ext_data_control_manager_v1_destroy(wayland->data_manager);

    wayland_base_uninit(&wayland->base);
}

/*
 * Sync all selections to entry "id", an id of -1 clears all selections.
 */
void
wayland_set_selection(struct wayland *wayland, int64_t id)
{
    struct wayland_seat *seat;

    wayland->entry_id = id;
    database_save_int_setting(&wayland->wlip->database, "Last_entry", id);
    ipc_emit_event(&wayland->wlip->ipc, IPC_EVENT_SELECTION, id);

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
    uint32_t            version
)
{
    struct wayland *wayland = udata;

    if (strcmp(interface, ext_data_control_manager_v1_interface.name) == 0)
    {
        wayland->data_manager = wl_registry_bind(
            proxy, name, &ext_data_control_manager_v1_interface, 1
        );

        // We may have binded to seats (and got seat name event) before the data
        // manager global.
        struct wayland_seat *seat, *tmp;

        wl_list_for_each_safe(seat, tmp, &wayland->seats, link)
        {
            if (!seat->active && seat->name != NULL &&
                wayland_seat_start(seat) == FAIL)
                wayland_seat_free(seat);
        }
    }
    else if (strcmp(interface, wl_seat_interface.name) == 0)
    {
        if (version < WL_SEAT_NAME_SINCE_VERSION)
        {
            log_error(
                "wl_seat global version is below %d", WL_SEAT_NAME_SINCE_VERSION
            );
            return;
        }
        struct wl_seat *seat_proxy = wl_registry_bind(
            proxy, name, &wl_seat_interface, WL_SEAT_NAME_SINCE_VERSION
        );

        if (seat_proxy == NULL)
            log_errwarn("Error binding to seat proxy");
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
    eventtimer_init(&sel->null_timer, 0, 1, null_selection_callback, sel);
    wl_list_init(&sel->send_contexts);
}

static void
wayland_selection_clear(struct wayland_selection *sel)
{
    struct send_context *ctx, *tmp;

    wl_list_for_each_safe(ctx, tmp, &sel->send_contexts, link)
    {
        send_context_free(ctx);
    }

    if (sel->data_offer != NULL)
        ext_data_control_offer_v1_destroy(sel->data_offer);
    if (sel->data_source != NULL)
        ext_data_control_source_v1_destroy(sel->data_source);

    eventtimer_stop(&sel->null_timer);
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
        log_errwarn("Error allocating seat structure");
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
    struct config *config = &seat->wayland->wlip->config;

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
        log_errwarn("Error creating data device for seat '%s'", seat->name);
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
        log_abort("Unknown selection type %d", type);
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
        log_errwarn("Error allocating seat name");
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
        log_errwarn("Error listening to offer proxy");
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

    log_debug("Seat data device finished, removing seat...");
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

    // Do not save entry if mime type is configured to be blocked.
    if (seat->wayland->wlip->config.blocked_mime_types.data != NULL &&
        match_regex_array(
            seat->wayland->wlip->config.blocked_mime_types.data,
            seat->wayland->wlip->config.blocked_mime_types.size /
                sizeof(regex_t),
            mime_type
        ))
    {
        seat->ignore_next = true;
        return;
    }

    // Check if mime type is allowed to be saved
    if (seat->wayland->wlip->config.allowed_mime_types.data != NULL &&
        !match_regex_array(
            seat->wayland->wlip->config.allowed_mime_types.data,
            seat->wayland->wlip->config.allowed_mime_types.size /
                sizeof(regex_t),
            mime_type
        ))
        return;

    char *ptr = wl_array_add(&seat->mime_types, strlen(mime_type) + 1);

    if (ptr == NULL)
        log_errwarn("Error allocating mime types");
    else
        sprintf(ptr, "%s", mime_type);
}

static void
null_selection_callback(void *udata)
{
    struct wayland_selection *sel = udata;

    if (sel->data_offer == NULL)
        // NULL selection event is valid, become the source client
        wayland_selection_own(sel);
    eventtimer_stop(&sel->null_timer);
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

    if (seat->ignore_next)
    {
        if (offer != NULL)
            ext_data_control_offer_v1_destroy(offer);
        sel->data_offer = NULL;
        return;
    }

    sel->data_offer = offer;

    if (offer == NULL)
    {
        if (sel->seat->wayland->entry_id == -1)
            return;

        // Selection has been cleared, try becoming the source client. Add a
        // delay in case it is followed up by an actual selection event.
        eventloop_add_timer(sel->seat->wayland->wlip->loop, &sel->null_timer);
        return;
    }

    int64_t id =
        wlip_new_selection(seat->wayland->wlip, offer, &seat->mime_types);

    if (id != -1)
    {
        database_save_int_setting(
            &seat->wayland->wlip->database,
            "Last_entry",
            sel->seat->wayland->entry_id
        );
        sel->seat->wayland->entry_id = id;
    }
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
            log_errwarn("Error creating data source");
            return;
        }

        if (database_offer_mime_types(
                &sel->seat->wayland->wlip->database,
                sel->seat->wayland->entry_id,
                source
            ) == FAIL)
        {
            ext_data_control_source_v1_destroy(source);
            return;
        }

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
        log_abort("Unknown selection type %d", sel->type);
}

static void
send_context_free(struct send_context *ctx)
{
    wl_list_remove(&ctx->link);
    eventsource_uninit(&ctx->source);
    close(ctx->source.fd);
    free(ctx);
}

static void
send_callback(int revents, void *udata)
{
    struct send_context *ctx = udata;

    if (!(revents & POLLOUT))
        goto stop;

    ssize_t w = write(ctx->source.fd, ctx->data, ctx->remaining);

    if (w == -1)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        log_errwarn("Error writing data");
        goto stop;
    }
    else if (w == 0)
        return;

    ctx->remaining -= w;
    ctx->data += w;

    if (ctx->remaining == 0)
        goto stop;

    return;
stop:
    eventsource_uninit(&ctx->source);

    sqlite3_reset(ctx->stmt);
    close(ctx->source.fd);

    wl_list_remove(&ctx->link);
    free(ctx);
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
        log_warn("Entry id is -1?");
        goto fail;
    }

    if (set_fd_nonblocking(fd) == FAIL)
    {
        log_errwarn("Error making fd non blocking");
        goto fail;
    }

    struct send_context *ctx = malloc(sizeof(*ctx));

    if (ctx == NULL)
    {
        log_errwarn("Error allocating send context");
        goto fail;
    }

    sqlite3_stmt *stmt = database_deserialize_mime_type_data(
        &sel->seat->wayland->wlip->database,
        sel->seat->wayland->entry_id,
        mime_type
    );

    if (stmt == NULL)
    {
        free(ctx);
        goto fail;
    }

    ctx->stmt = stmt;
    ctx->data = sqlite3_column_blob(stmt, 0);
    ctx->remaining = sqlite3_column_bytes(stmt, 0);
    if (ctx->data == NULL || ctx->remaining == 0)
    {
        // May happen if Data_id row in Mime_types table is NULL.
        free(ctx);
        sqlite3_reset(stmt);
        goto fail;
    }

    wl_list_insert(&sel->send_contexts, &ctx->link);

    // Send the data asynchronously
    eventsource_init(&ctx->source, 0, fd, POLLOUT, send_callback, ctx);
    eventloop_add_source(sel->seat->wayland->wlip->loop, &ctx->source);

    return;
fail:
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
