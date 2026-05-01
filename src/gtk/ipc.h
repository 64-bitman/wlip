#pragma once

#include "ipc_client.h"
#include <glib.h>

struct ipc
{
    GAsyncQueue *request_queue;
    GThread     *thread;

    int efd; // Used to wakeup IPC thread
    int run; // Used by main and IPC thread

    event_callback event_cb;
    void          *event_udata;
};

// clang-format off
int ipc_init(struct ipc *ipc, event_callback event_cb, void *udata);
void ipc_uninit(struct ipc *ipc);

void ipc_queue_request(struct ipc *ipc, const char *type, struct json_object *req,request_callback callback, void *udata);
// clang-format on
