#pragma once

#include "clipboard.h"
#include "errors.h"
#include <stdbool.h>
#include <wayland-client.h>

typedef enum
{
    WLSELECTION_TYPE_REGULAR,
    WLSELECTION_TYPE_PRIMARY
} wlselection_type_T;

typedef struct wlseat_S wlseat_T;

int wayland_init(const char *display, error_T *error);
int wayland_get_fd(void);
struct wl_display *wayland_get_display(void);
void wayland_uninit();

wlseat_T *wayland_get_seat(const char *name);
void wayland_attach_selection(
    wlseat_T *seat, wlselection_type_T type, clipboard_T *cb
);
