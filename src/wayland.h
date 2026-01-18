#pragma once

#include "errors.h"
#include <stdbool.h>
#include <uv.h>
#include <wayland-client.h>

int wayland_init(uv_loop_t *loop, const char *display, error_T *error);
void wayland_uninit();
