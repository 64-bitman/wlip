#include "ipc.h"
#include "gui.h"
#include "util.h"
#include <glib-unix.h>
#include <glib.h>

#define BASE_EVENTS (G_IO_HUP | G_IO_ERR | G_IO_NVAL)

struct ipc_source
{
    GSource     parent;
    struct ipc *ipc;
};

// clang-format off
static gboolean source_prepare(GSource *self, int *timeout_);
static gboolean source_check(GSource *self);
static gboolean source_dispatch(GSource *self, GSourceFunc callback, void *user_data);
static void source_finalize(GSource *self);

static GSourceFuncs SOURCE_FUNCS = {
    .prepare = source_prepare,
    .check = source_check,
    .dispatch = source_dispatch,
    .finalize = source_finalize
};
// clang-format on

/*
 * Connect to daemon and start requesting entries in a separate thread. Return
 * OK on sucess and FAIL on failure.
 */
int
ipc_init(struct ipc *ipc, struct gui *gui)
{
    if (ipc_client_init(&ipc->client) == FAIL)
        return FAIL;
    ipc->gui = gui;

    // Install fd to main context
    ipc->source = g_source_new(&SOURCE_FUNCS, sizeof(struct ipc_source));
    ipc->fd_tag = g_source_add_unix_fd(
        ipc->source, ipc->client.fd, G_IO_IN | BASE_EVENTS
    );

    struct ipc_source *source = (struct ipc_source *)ipc->source;

    source->ipc = ipc;

    g_source_attach(ipc->source, NULL);
    ipc->running = true;

    return OK;
}

void
ipc_uninit(struct ipc *ipc)
{
    if (!ipc->running)
        return;
    g_source_destroy(ipc->source);
    g_source_unref(ipc->source);

    ipc_client_uninit(&ipc->client);
    ipc->running = false;
}

static gboolean
source_prepare(GSource *self, int *timeout_)
{
    struct ipc_source *source = (struct ipc_source *)self;

    struct pollfd pfd;

    ipc_client_prepare(&source->ipc->client, &pfd);

    int flags = G_IO_IN | BASE_EVENTS;

    if (pfd.events & POLLOUT)
        flags |= G_IO_OUT;

    g_source_modify_unix_fd(self, source->ipc->fd_tag, flags);
    *timeout_ = -1;
    return FALSE;
}

static gboolean
source_check(GSource *self UNUSED)
{
    struct ipc_source *source = (struct ipc_source *)self;
    GIOCondition revents = g_source_query_unix_fd(self, source->ipc->fd_tag);
    return revents != 0;
}

static gboolean
source_dispatch(GSource *self, GSourceFunc callback UNUSED, void *udata UNUSED)
{
    struct ipc_source *source = (struct ipc_source *)self;
    GIOCondition revents = g_source_query_unix_fd(self, source->ipc->fd_tag);

    if (revents == 0)
        return G_SOURCE_CONTINUE;

    int actual = 0;

    if (revents & G_IO_IN)
        actual |= POLLIN;
    if (revents & G_IO_OUT)
        actual |= POLLOUT;

    if (revents & G_IO_ERR)
        actual |= POLLERR;
    if (revents & G_IO_HUP)
        actual |= POLLHUP;
    if (revents & G_IO_NVAL)
        actual |= POLLNVAL;

    if (ipc_client_check(&source->ipc->client, actual) == FAIL)
    {
        g_main_loop_quit(source->ipc->gui->loop);
        ipc_uninit(source->ipc);
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}

static void
source_finalize(GSource *self UNUSED)
{
}
