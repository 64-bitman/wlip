#pragma once

#include "config.h"
#include "database.h"
#include "ipc.h"
#include "wayland.h"
#include <sqlite3.h>
#include <stdbool.h>
#include <wayland-client.h>

struct wlip
{
    char *config_directory;
    char *database_directory;

    struct config   config;
    struct wayland  wayland;
    struct database database;
    struct ipc      ipc;

    // Hash of last/most recent selection event. Used to check if a new
    // selection event is the same in terms of mime types and data.
    uint8_t selection_hash[SHA256_BLOCK_SIZE];
    bool    selection_hash_init; // If "selection_hash" is initialized

    // Used in event loop
    struct wl_list timers;
    struct wl_list sources;
};

int  wlip_init(struct wlip *wlip, char *config_dir, char *database_dir);
void wlip_uninit(struct wlip *wlip);
int  wlip_run(struct wlip *wlip);

void wlip_init_timer(struct timer *timer);
void wlip_start_timer(
    struct wlip  *wlip,
    struct timer *timer,
    int           delay,
    timer_func    callback,
    void         *udata
);
void wlip_stop_timer(struct timer *timer);

void wlip_init_source(struct fdsource *source);
void wlip_start_source(
    struct wlip     *wlip,
    struct fdsource *source,
    int              fd,
    int              events,
    fdsource_func    callback,
    void            *udata
);
void wlip_stop_source(struct fdsource *source);

int64_t wlip_new_selection(
    struct wlip                      *wlip,
    struct ext_data_control_offer_v1 *offer,
    const struct wl_array            *mime_types
);
