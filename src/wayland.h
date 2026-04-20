#pragma once

#include "config.h"
#include "ext-data-control-v1.h"
#include "sha256.h"
#include "util.h"
#include <stdbool.h>
#include <wayland-client.h>

struct wlip;
struct wlip_mimetype;
struct wayland;
struct wayland_seat;

enum wayland_selection_type
{
    SELECTION_REGULAR,
    SELECTION_PRIMARY
};

struct wayland_selection
{
    enum wayland_selection_type type;
    struct wayland_seat        *seat;
    bool                        enabled;

    struct ext_data_control_offer_v1  *data_offer;
    struct ext_data_control_source_v1 *data_source;

    // Timer used to check if NULL selection event is valid
    struct timer null_timer;
};

/*
 * Created per Wayland seat
 */
struct wayland_seat
{
    struct wayland *wayland;

    bool            active;
    struct wl_seat *proxy;
    char           *name;
    uint32_t        id; // Used to match with global_remove event

    struct ext_data_control_device_v1 *data_device;
    struct wayland_selection           sel_regular;
    struct wayland_selection           sel_primary;

    // Temporary array used when receiving data offer events. Note that "->data"
    // may still be NULL if data offer has no mime types.
    struct wl_array mime_types;

    struct wl_list link;
};

struct wayland
{
    struct wlip   *wlip;
    struct config *config;

    struct wl_display  *display;
    struct wl_registry *registry;

    struct ext_data_control_manager_v1 *data_manager;
    struct wl_list                      seats;

    int64_t entry_id; // Id of current entry in database that all selections are
                      // synced to. If -1, then all selections are cleared.
};

int
wayland_init(struct wayland *wayland, struct config *config, struct wlip *wlip);
void wayland_uninit(struct wayland *wayland);

void wayland_set_selection(struct wayland *wayland, int64_t id);
