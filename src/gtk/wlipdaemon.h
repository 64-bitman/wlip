#pragma once

#include <gio/gio.h>
#include <glib-object.h>
#include <glib.h>
#include <json-glib/json-glib.h>

/*
 * Content enums defined first are prioritized over ones after.
 */
typedef enum
{
    WLIP_CONTENT_IMAGE,
    WLIP_CONTENT_TEXT,
    WLIP_CONTENT_BINARY,
    WLIP_CONTENT_UNKNOWN
} WlipContent;

#define WLIP_TYPE_CONTENT (wlip_content_get_type())
GType wlip_content_get_type(void);

#define WLIP_TYPE_ENTRY (wlip_entry_get_type())
G_DECLARE_FINAL_TYPE(WlipEntry, wlip_entry, WLIP, ENTRY, GObject)

#define WLIP_TYPE_DAEMON (wlip_daemon_get_type())
G_DECLARE_FINAL_TYPE(WlipDaemon, wlip_daemon, WLIP, DAEMON, GObject)

// clang-format off
WlipDaemon *wlip_daemon_new(const char *socket_path, GError **error);
guint wlip_daemon_get_history_size(WlipDaemon *self);
WlipEntry *wlip_daemon_get_entry(WlipDaemon *self, guint pos);
// clang-format on
