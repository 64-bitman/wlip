#pragma once

#include <regex.h>
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

    // Maximum size of the data from a mime type that will be saved. If bigger,
    // then the mime type will be ignored. In bytes
    int64_t max_size;

    // Array of seats that the user has configured.
    struct config_seat *configured_seats;
    uint32_t            configured_seats_len;

    // Array of regex_t of mime types that are allowed to be saved. If NULL,
    // then assume all mime types.
    struct wl_array allowed_mime_types;

    // Array of regex_t of mime types that will make the entry be ignored if
    // found. If NULL, then no mime types are blocked.
    struct wl_array blocked_mime_types;
};

int  config_init(struct config *config, const char *cfgdir);
void config_uninit(struct config *config);
