#pragma once

#include "ipc_client.h"
#include <glib-object.h>
#include <glib.h>
#include <json.h>

// Reference counted using the json_object
typedef struct
{
    const char         *event_type;
    struct json_object *event;
    void               *ptr; // Internal
} IPCEvent;

#define IPC_TYPE_HANDLE (ipc_handle_get_type())
G_DECLARE_FINAL_TYPE(IPCHandle, ipc_handle, IPC, HANDLE, GObject);

// clang-format off
IPCHandle *ipc_handle_new(void);
void ipc_handle_queue_request(IPCHandle *self, const char *type, struct json_object *req, request_callback callback, void *udata);
void ipc_handle_subscribe(IPCHandle *self, const char *event);
// clang-format on
