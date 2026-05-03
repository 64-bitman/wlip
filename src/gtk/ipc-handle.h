#pragma once

#include <gio/gio.h>
#include <glib-object.h>
#include <glib.h>
#include <json.h>

typedef enum
{
    IPC_REQUEST_TYPE_ENTRY,
    IPC_REQUEST_TYPE_MIMETYPE,
    IPC_REQUEST_TYPE_SET,
    IPC_REQUEST_TYPE_DELETE,
    IPC_REQUEST_TYPE_SUBSCRIBE,
    IPC_REQUEST_TYPE_HISTORY_SIZE,
} IPCRequestType;

typedef enum
{
    IPC_EVENT_TYPE_SELECTION,
    IPC_EVENT_TYPE_CHANGE
} IPCEventType;

#define IPC_TYPE_HANDLE (ipc_handle_get_type())
G_DECLARE_FINAL_TYPE(IPCHandle, ipc_handle, IPC, HANDLE, GObject);

// clang-format off
IPCHandle *ipc_handle_new(void);

void put_json_object(struct json_object *obj);

void ipc_handle_request_async(IPCHandle *handle, IPCRequestType type, GCancellable *cancellable, GAsyncReadyCallback callback, void *udata, ...);
struct json_object *ipc_handle_request_finish(IPCHandle *self, GAsyncResult *result, GError **error);
// clang-format on

typedef struct json_object JsonObj;
#define JSON_TYPE_OBJ (json_obj_get_type())
GType json_obj_get_type(void);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(JsonObj, put_json_object)
