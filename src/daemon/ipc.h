#pragma once

#include "config.h"
#include "util.h"
#include <json.h>
#include <poll.h>
#include <wayland-util.h>

struct ipc;
struct wlip;

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
