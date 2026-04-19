#pragma once

#include "ext-data-control-v1.h"
#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <wayland-client.h>

struct wlip_selection
{
    struct ext_data_control_offer_v1  *offer;
    struct ext_data_control_source_v1 *source;

    // Creation time of current clipboard entry. If -1, then clipboard is
    // cleared.
    int64_t         creation_time;
    struct wl_array mime_types; // Inline array of mime types for current offer
};

/*
 * Created per Wayland seat
 */
struct wlip_seat
{
    char           *name; // If NULL, then seat should not be used
    struct wl_seat *proxy;
    uint32_t        id; // Used to identify seat from "global_remove" event

    struct ext_data_control_device_v1 *device;

    struct wlip_selection sel_regular;
    struct wlip_selection sel_primary;

    struct wl_list link;
};

struct wlip
{
    char *config_dir;   // May be NULL
    char *database_dir; // May be NULL
    FILE *log_fp;       // May be NULL

    char               *display_name;
    struct wl_display  *display;
    struct wl_registry *registry;

    struct ext_data_control_manager_v1 *manager;
    struct wl_list                      seats;

    // Inline array of allowed mime types to save.
    struct wl_array allowed_mime_types;
};

extern struct wlip WLIP;

int  wlip_init(void);
void wlip_uninit(void);
int  wlip_run(void);
