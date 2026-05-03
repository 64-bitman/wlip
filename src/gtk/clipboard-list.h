#pragma once

#include "ipc-handle.h"
#include <glib-object.h>
#include <glib.h>

#define CLIPBOARD_TYPE_LIST (clipboard_list_get_type())
G_DECLARE_FINAL_TYPE(ClipboardList, clipboard_list, CLIPBOARD, LIST, GObject)

// clang-format off
ClipboardList *clipboard_list_new(IPCHandle *ipc_handle);
// clang-format on
