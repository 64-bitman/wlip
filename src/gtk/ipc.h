#pragma once

#include "ipc_client.h"
#include <glib.h>
#include <stdbool.h>

struct gui;

struct ipc
{
    bool              running;
    struct ipc_client client;
    struct gui       *gui;

    GSource *source;
    void    *fd_tag;
};

// clang-format off
int ipc_init(struct ipc *ipc, struct gui *gui);
void ipc_uninit(struct ipc *ipc);
// clang-format on
