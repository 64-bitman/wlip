#pragma once

#include "config.h"
#include "event.h"
#include <json.h>
#include <poll.h>
#include <wayland-util.h>

struct ipc;
struct wlip;

enum ipc_event
{
    IPC_EVENT_NONE = 0,
    IPC_EVENT_SELECTION = 1 << 0,
    IPC_EVENT_CHANGE = 1 << 1
};

#define IPC_EVENT_SELECTION_STR "selection"
#define IPC_EVENT_CHANGE_STR "change"

struct ipc_message
{
    struct json_object *resp;
    const char         *data;
    size_t              remaining;

    struct wl_list link;
};

struct ipc_connection
{
    struct ipc          *ipc;
    struct json_tokener *tokener;

    struct wl_list write_queue;

    // Events this connection has subscribed to
    int subbed_events;

    struct eventsource source;
    struct wl_list     link;
};

struct ipc
{
    char *path;
    char *lock_path;

    int fd;
    int lock_fd;

    struct eventsource source;

    struct wlip   *wlip;
    struct wl_list connections;
};

// clang-format off
int ipc_init(struct ipc *ipc, const char *socket_path, struct config *config, struct wlip *wlip);
void ipc_uninit(struct ipc *ipc);

void ipc_emit_event(struct ipc *ipc, enum ipc_event type, struct json_object *args);
void ipc_emit_event_selection(struct ipc *ipc, int64_t id);
void ipc_emit_event_change(struct ipc *ipc, int64_t id, const char *change);
int ipc_set_pfds(struct ipc *ipc, struct pollfd *pfds, int max);
void ipc_check_pfds(struct ipc *ipc, struct pollfd *pfds);
// clang-format on
