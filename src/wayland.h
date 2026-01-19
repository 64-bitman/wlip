#pragma once

#include <stdbool.h>
#include <wayland-client.h>

typedef enum
{
    WLSELECTION_TYPE_REGULAR,
    WLSELECTION_TYPE_PRIMARY
} wlselection_type_T;

typedef struct wlselection_S wlselection_T;
typedef struct wlseat_S wlseat_T;
typedef struct clipboard_S clipboard_T;

int wayland_init(const char *display);
void wayland_uninit();

wlseat_T *wayland_get_seat(const char *name);
void wayland_attach_selection(
    wlseat_T *seat, wlselection_type_T type, clipboard_T *cb
);

wlselection_T *wlselection_ref(wlselection_T *sel);
void wlselection_unref(wlselection_T *sel);

void
wlselection_update(wlselection_T *sel);
int
wlselection_get_fd(wlselection_T *sel, const char *mime_type);
bool wlselection_is_valid(wlselection_T *sel);
