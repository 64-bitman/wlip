#include "wlip.h"
#include "config.h"
#include "database.h"
#include "ipc.h"
#include "sha256.h"
#include "util.h"
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t SIGCOUNT = 0;

/*
 * Initialize program state structure and connect to compositor. Note that
 * ownership of "config_dir" and "database_dir" is taken. Returns OK on success
 * and FAIL on failure.
 */
int
wlip_init(struct wlip *wlip, char *config_dir, char *database_dir)
{
    wl_list_init(&wlip->timers);

    if (config_init(&wlip->config, config_dir) == FAIL)
        return FAIL;
    if (wayland_init(&wlip->wayland, &wlip->config, wlip) == FAIL)
    {
        config_uninit(&wlip->config);
        return FAIL;
    }
    if (database_init(&wlip->database, database_dir, &wlip->config) == FAIL)
    {
        config_uninit(&wlip->config);
        wayland_uninit(&wlip->wayland);
        return FAIL;
    }
    if (ipc_init(&wlip->ipc, getenv("WLIP_SOCK"), &wlip->config, wlip) == FAIL)
    {
        config_uninit(&wlip->config);
        wayland_uninit(&wlip->wayland);
        database_uninit(&wlip->database);
        return FAIL;
    }

    if (database_get_selection_hash(&wlip->database, wlip->selection_hash) ==
        OK)
        wlip->selection_hash_init = true;
    else
        wlip->selection_hash_init = false;

    wlip->config_directory = config_dir;
    wlip->database_directory = database_dir;

    struct database_entry entry = {0};
    int64_t               id = -1;

    // Load entry from database if any
    if (database_get_int_setting(&wlip->database, "Last_entry", &id) == FAIL)
        // Use most recent entry
        if (database_deserialize_entry(&wlip->database, 0, &entry) == OK)
        {
            id = entry.id;
            database_save_int_setting(&wlip->database, "Last_entry", id);
        }

    wayland_set_selection(&wlip->wayland, id);

    return OK;
}

void
wlip_uninit(struct wlip *wlip)
{
    config_uninit(&wlip->config);
    wayland_uninit(&wlip->wayland);
    database_uninit(&wlip->database);
    ipc_uninit(&wlip->ipc);

    free(wlip->config_directory);
    free(wlip->database_directory);
}

static void
signal_handler(int signo UNUSED)
{
    SIGCOUNT++;
}

/*
 * Run the event loop. Returns OK on success and FAIL on failure
 */
int
wlip_run(struct wlip *wlip)
{
    sigset_t orig, block;

    sigemptyset(&block);

    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);

    sigprocmask(SIG_BLOCK, &block, &orig);

    struct sigaction sa = {0};

    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // Ignore SIGPIPE signal
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

#define MAX_IPC_CONNECTIONS 10
    struct pollfd pfds[2 + MAX_IPC_CONNECTIONS];

    pfds[0].fd = wl_display_get_fd(wlip->wayland.display);
    pfds[0].events = POLLIN;
    pfds[1].fd = wlip->ipc.fd;
    pfds[1].events = POLLIN;

    while (SIGCOUNT == 0)
    {
        // Find minimum timeout to use in nanoseconds
        int64_t       timeout_ns = -1;
        struct timer *timer, *tmp;

        wl_list_for_each(timer, &wlip->timers, link)
        {
            if (timeout_ns == -1 || timeout_ns > timer->remaining)
                timeout_ns = timer->remaining;
        }

        while (wl_display_prepare_read(wlip->wayland.display) == -1)
            wl_display_dispatch_pending(wlip->wayland.display);

        if (wl_display_flush(wlip->wayland.display) == -1)
        {
            wlip_err("Error flushing display");
            return FAIL;
        }

        struct timespec timeout;

        if (timeout_ns != -1)
        {
            timeout.tv_sec = timeout_ns / 1000000000LL;
            timeout.tv_nsec = timeout_ns % 1000000000LL;
        }

        int64_t start = get_time_ns(CLOCK_MONOTONIC), end;
        if (start == -1)
            return FAIL;

        int pfds_len = 2;

        pfds_len += ipc_set_pfds(&wlip->ipc, pfds + 2, MAX_IPC_CONNECTIONS);

#undef MAX_IPC_CONNECTIONS

        int ret =
            ppoll(pfds, pfds_len, timeout_ns == -1 ? NULL : &timeout, &orig);

        if (ret == -1)
        {
            if (errno == EINTR)
                continue;
            wlip_err("Error polling display");
            return FAIL;
        }

        if (pfds[0].revents & (POLLHUP | POLLERR | POLLNVAL))
        {
            wl_display_cancel_read(wlip->wayland.display);
            break;
        }

        if (wl_display_read_events(wlip->wayland.display) == -1 ||
            wl_display_dispatch_pending(wlip->wayland.display) == -1)
        {
            wlip_err("Display connection lost");
            return FAIL;
        }

        end = get_time_ns(CLOCK_MONOTONIC);

        if (end != -1)
        {
            int64_t elapsed = end - start;

            wl_list_for_each_safe(timer, tmp, &wlip->timers, link)
            {
                timer->remaining -= elapsed;

                if (timer->remaining <= 0)
                {
                    timer_func func = timer->callback;

                    wl_list_remove(&timer->link);
                    timer->callback = NULL;
                    func(timer->udata);
                }
            }
        }

        ipc_check_pfds(&wlip->ipc, pfds + 2);

        if (pfds[1].revents & (POLLHUP | POLLERR | POLLNVAL))
        {
            wlip_log("IPC server lost");
            return FAIL;
        }
        else if (pfds[1].revents & POLLIN)
            ipc_accept(&wlip->ipc);
    }

    return OK;
}

/*
 * Initialize timer
 */
void
wlip_init_timer(struct timer *timer)
{
    timer->callback = NULL;
    wl_list_init(&timer->link);
}

/*
 * Start running the timer for "delay" milliseconds.
 */
void
wlip_start_timer(
    struct wlip  *wlip,
    struct timer *timer,
    int           delay,
    timer_func    callback,
    void         *udata
)
{
    timer->remaining = delay * 1000000;
    timer->callback = callback;
    timer->udata = udata;

    wl_list_insert(&wlip->timers, &timer->link);
}

/*
 * Stop running timer if it is currently running.
 */
void
wlip_stop_timer(struct timer *timer)
{
    if (timer->callback == NULL)
        return;
    timer->callback = NULL;
    wl_list_remove(&timer->link);
}

/*
 * Should be called when there is a new selection from any seat. Returns ID of
 * entry on success and -1 on failure.
 */
int64_t
wlip_new_selection(
    struct wlip                      *wlip,
    struct ext_data_control_offer_v1 *offer,
    const struct wl_array            *mime_types
)
{
    const char *mime_type = mime_types->data;
    bool        did_something = false;

    if (database_do_transaction(&wlip->database, TRANSACTION_IMMEDIATE) == FAIL)
        return -1;

    SHA256_CTX sha_hash;
    int64_t    id = database_serialize_entry(&wlip->database, NULL);

    if (id == -1)
        goto fail;

    sha256_init(&sha_hash);

    while (mime_type != NULL)
    {
        int fds[2];

        if (pipe(fds) == -1)
        {
            wlip_err("Error creating pipe");
            goto next;
        }

        struct wl_array content;

        wl_array_init(&content);

        ext_data_control_offer_v1_receive(offer, mime_type, fds[1]);
        // Close our write-end because we don't need it
        close(fds[1]);

        if (wl_display_flush(wlip->wayland.display) == -1)
        {
            wlip_err("Error flushing display");
            goto fail;
        }

#define BUFSIZE 4096
        static char    buf[BUFSIZE];
        static uint8_t data_id[SHA256_BLOCK_SIZE];
        SHA256_CTX     sha_ctx;

        sha256_init(&sha_ctx);

        while (true)
        {
            ssize_t r = read(fds[0], buf, BUFSIZE);

            if (r == -1)
            {
                // Assume fatal
                wlip_err("Error reading data");
                wl_array_release(&content);
                goto fail;
            }
            else if (r > 0)
            {
                uint8_t *ptr = wl_array_add(&content, r);

                if (ptr == NULL)
                {
                    wlip_err("Error allocating array");
                    wl_array_release(&content);
                    goto fail;
                }
                sha256_update(&sha_ctx, (BYTE *)buf, r);
                memcpy(ptr, buf, r);
            }
            else
                // EOF received
                break;
        }
#undef BUFSIZE

        // Check if data is bigger than configured max size
        if (content.size > (size_t)wlip->config.max_size)
            goto fail;

        sha256_final(&sha_ctx, data_id);

        sha256_update(&sha_hash, (BYTE *)mime_type, strlen(mime_type));
        sha256_update(&sha_hash, data_id, SHA256_BLOCK_SIZE);

        if (database_serialize_mime_type(
                &wlip->database,
                id,
                mime_type,
                data_id,
                content.data,
                content.size
            ) == FAIL)
            goto fail;

        did_something = true;

fail:
        close(fds[0]);
        wl_array_release(&content);
next:
        mime_type += strlen(mime_type) + 1;
        if ((size_t)(mime_type - (char *)mime_types->data) >= mime_types->size)
            break;
    }

    if (did_something)
    {
        // Check if selection event is the same as the prior selection event. If
        // so, then ignore it.
        static uint8_t sel_hash[SHA256_BLOCK_SIZE];

        sha256_final(&sha_hash, sel_hash);

        if (wlip->selection_hash_init &&
            memcmp(sel_hash, wlip->selection_hash, SHA256_BLOCK_SIZE) == 0)
            did_something = false;
        else
        {
            memcpy(wlip->selection_hash, sel_hash, SHA256_BLOCK_SIZE);
            database_save_selection_hash(&wlip->database, sel_hash);
            wlip->selection_hash_init = true;
        }
    }

    if (database_do_transaction(
            &wlip->database,
            did_something ? TRANSACTION_COMMIT : TRANSACTION_ROLLBACK
        ) == FAIL)
        return -1;

    return did_something ? id : -1;
}
