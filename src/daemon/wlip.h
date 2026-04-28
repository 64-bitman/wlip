#pragma once

#include "config.h"
#include "database.h"
#include "event.h"
#include "ipc.h"
#include "sha256.h"
#include "wayland.h"
#include <signal.h> // IWYU pragma: keep
#include <sqlite3.h>
#include <stdbool.h>
#include <wayland-client.h>

struct wlip
{
    char *config_directory;
    char *database_directory;

    struct eventloop *loop;
    struct config     config;
    struct wayland    wayland;
    struct database   database;
    struct ipc        ipc;

    struct signal_handler sigterm;
    struct signal_handler sigint;

    // Hash of last/most recent selection event. Used to check if a new
    // selection event is the same in terms of mime types and data.
    uint8_t selection_hash[SHA256_BLOCK_SIZE];
    bool    selection_hash_init; // If "selection_hash" is initialized
};

// clang-format off
int  wlip_init(struct wlip *wlip, struct eventloop *loop, char *config_dir, char *database_dir);
void wlip_uninit(struct wlip *wlip);

int64_t wlip_new_selection(struct wlip *wlip, struct ext_data_control_offer_v1 *offer, const struct wl_array *mime_types);
// clang-format on
