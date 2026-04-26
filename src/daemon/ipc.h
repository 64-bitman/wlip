#pragma once

#include "config.h"
#include "util.h"
#include <json.h>
#include <poll.h>
#include <wayland-util.h>

struct ipc;
struct wlip;

enum ipc_event
{
    IPC_EVENT_NONE = 0,
    IPC_EVENT_SELECTION = 1 << 0,
    IPC_EVENT_ENTRY_CHANGED = 1 << 1
};

/*
 * Each request has its own serial, which is sent back in toe follow up
 * response. Currently this is not necessary (everyting is sent and received
 * sequentially), but may as well keep it fora ny future changes.
 */
struct ipc_response
{
    struct json_object *resp;
    const char         *data;
    size_t              remaining;

    struct ipc_response *next;
};

struct ipc_connection
{
    struct ipc          *ipc;
    struct json_tokener *tokener;

    struct ipc_response *write_queue;
    struct ipc_response *write_queue_end;

    // Events this connection has subscribed to
    enum ipc_event subbed_events;

    struct fdsource source;
    struct wl_list  link;
};

struct ipc
{
    char *path;
    char *lock_path;

    int fd;
    int lock_fd;

    struct wlip   *wlip;
    struct wl_list connections;
};

// clang-format off
int ipc_init(struct ipc *ipc, const char *socket_path, struct config *config, struct wlip *wlip);
void ipc_uninit(struct ipc *ipc);

void ipc_accept(struct ipc *ipc);
void ipc_emit_event(struct ipc *ipc, enum ipc_event type, struct json_object *args, struct ipc_connection *ignore);
void ipc_emit_event_selection(struct ipc *ipc, int64_t id);
void ipc_emit_event_entry_changed(struct ipc *ipc, int64_t id, const char *change);
int ipc_set_pfds(struct ipc *ipc, struct pollfd *pfds, int max);
void ipc_check_pfds(struct ipc *ipc, struct pollfd *pfds);
// clang-format on
