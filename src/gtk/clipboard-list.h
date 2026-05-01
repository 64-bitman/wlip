#pragma once

#include "ipc.h"
#include <glib-object.h>

#define CLIPBOARD_TYPE_LIST (clipboard_list_get_type())
G_DECLARE_FINAL_TYPE(ClipboardList, clipboard_list, CLIPBOARD, LIST, GObject)

// clang-format off
ClipboardList *clipboard_list_new(struct ipc *ipc);
// clang-format on
