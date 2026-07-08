#pragma once

#include "wlipdaemon.h"
#include <gio/gio.h>
#include <glib-object.h>

/*
 * First content type that matches is prioritized! Make sure to update
 * CONTENT_MAP[] as well
 */
typedef enum
{
    WLIP_CONTENT_IMAGE,
    WLIP_CONTENT_TEXT,

    // Should always be last enum
    WLIP_CONTENT_UNKNOWN // e.g. binary data
} WlipContentType;

#define WLIP_TYPE_LIST_ENTRY (wlip_list_entry_get_type())
G_DECLARE_FINAL_TYPE(WlipListEntry, wlip_list_entry, WLIP, LIST_ENTRY, GObject);

#define WLIP_TYPE_LIST (wlip_list_get_type())
G_DECLARE_FINAL_TYPE(WlipList, wlip_list, WLIP, LIST, GObject);

// clang-format off
WlipList *wlip_list_new(WlipDaemon *daemon);
// clang-format on
