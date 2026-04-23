#pragma once

#include <stdbool.h>
#include <wayland-util.h>

struct wlip;

struct config_seat
{
    char *name;
    bool  regular;
    bool  primary;
};

struct config
{
    // Display name of Wayland compositor to connect to
    char *display_name;

    // Maximum number of entries to store in database, must be > 0
    int64_t max_entries;

    // Enable persistent history
    bool persist;

    // Array of seats that the user has configured.
    struct config_seat *configured_seats;
    uint32_t            configured_seats_len;

    // Inline array of strings of mime types that are allowed to be saved
    struct wl_array allowed_mime_types;
};

int  config_init(struct config *config, const char *cfgdir);
void config_uninit(struct config *config);
