#pragma once

#include "config.h"
#include "event.h"
#include <json.h>
#include <poll.h>
#include <wayland-util.h>

#define IPC_ID "id"
#define IPC_POS "pos"

#define IPC_UPDATE_TIME "update_time"
#define IPC_STARRED "starred"

/*
 * Emitted when new entry is added to to start of history to become the most
 * recent entry. Arguments:
 * "id": int64_t
 * ID of entry that was added
 */
#define IPC_EVENT_ADD "entry_added"

/*
 * Emitted when new entry is added to to start of history to become the most
 * recent entry. Arguments:
 * "id": int64_t
 * ID of entry that was deleted
 * "pos": int64_t
 * Position in history of entry before deletion
 */
#define IPC_EVENT_DELETE "entry_deleted"

/*
 * Emitted when entry is updated. Arguments:
 * "id": int64_t
 * ID of entry that was changed
 * ?"update_time": int64_t
 * New update time
 * ?"starred": boolean
 * New starred state
 * ?"curretn": boolean
 * If entry is now the current entry or not
 *
 * Either may be excluded (if it was not changed), but at least one argument
 * will be present.
 */
#define IPC_EVENT_UPDATE "entry_updated"

struct ipc;
struct wlip;

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

    bool events; // If connection should receive events.

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

void ipc_emit_event(struct ipc *ipc, const char *event, const char *fmt, ...);
int ipc_set_pfds(struct ipc *ipc, struct pollfd *pfds, int max);
void ipc_check_pfds(struct ipc *ipc, struct pollfd *pfds);
// clang-format on
