#pragma once

#include "config.h"
#include <json.h>
#include <poll.h>
#include <wayland-util.h>

struct ipc;
struct wlip;

struct ipc_connection
{
    int fd;
    int pfd_idx; // -1 if not set

    struct ipc          *ipc;
    struct json_tokener *tokener;

    struct wl_list link;
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

int ipc_init(
    struct ipc    *ipc,
    const char    *socket_path,
    struct config *config,
    struct wlip   *wlip
);
void ipc_uninit(struct ipc *ipc);

void ipc_accept(struct ipc *ipc);
int  ipc_set_pfds(struct ipc *ipc, struct pollfd *pfds, int max);
void ipc_check_pfds(struct ipc *ipc, struct pollfd *pfds);
