#pragma once

#include <gio/gio.h>
#include <glib-object.h>
#include <glib.h>
#include <json-glib/json-glib.h>

typedef enum
{
    WLIP_DAEMON_REQUEST_ENTRY,
} WlipDaemonRequest;

#define WLIP_TYPE_DAEMON (wlip_daemon_get_type())
G_DECLARE_FINAL_TYPE(WlipDaemon, wlip_daemon, WLIP, DAEMON, GObject);

// clang-format off
WlipDaemon *wlip_daemon_new(const char *socket_path, GError **error);
void wlip_daemon_stop(WlipDaemon *self);
void wlip_daemon_request_async(WlipDaemon *self, WlipDaemonRequest req, int io_priority, GCancellable *cancellable, GAsyncReadyCallback callback, void *udata, ...);
JsonObject *wlip_daemon_request_finish(WlipDaemon *self, GAsyncResult *result, GError **error);
// clang-format on
