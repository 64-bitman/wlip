#pragma once

#include "wlipdaemon.h"
#include <gio/gio.h>
#include <glib-object.h>

#define WLIP_TYPE_LIST_ENTRY (wlip_list_entry_get_type())
G_DECLARE_FINAL_TYPE(WlipListEntry, wlip_list_entry, WLIP, LIST_ENTRY, GObject);

#define WLIP_TYPE_LIST (wlip_list_get_type())
G_DECLARE_FINAL_TYPE(WlipList, wlip_list, WLIP, LIST, GObject);

// clang-format off
WlipList *wlip_list_new(WlipDaemon *daemon);
// clang-format on
