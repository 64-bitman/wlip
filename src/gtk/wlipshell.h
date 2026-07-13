#pragma once

#include "wlipdaemon.h"
#include <glib-object.h>

#define WLIP_TYPE_SHELL (wlip_shell_get_type())
G_DECLARE_FINAL_TYPE(WlipShell, wlip_shell, WLIP, SHELL, GObject)

// clang-format off
WlipShell *wlip_shell_new(WlipDaemon *daemon);
// clang-format on
