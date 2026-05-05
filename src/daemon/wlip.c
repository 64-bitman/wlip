#include "wlip.h"
#include "config.h"
#include "database.h"
#include "ipc.h"
#include "log.h"
#include "sha256.h"
#include "util.h"
#include <errno.h> // IWYU pragma: keep
#include <stdlib.h>
#include <string.h>

/*
 * Initialize program state structure and connect to compositor. Note that
 * ownership of "config_dir" and "database_dir" is taken. Returns OK on success
 * and FAIL on failure.
 */
int
wlip_init(
    struct wlip      *wlip,
    struct eventloop *loop,
    char             *config_dir,
    char             *database_dir
)
{
    wlip->loop = loop;

    if (config_init(&wlip->config, config_dir) == FAIL)
        return FAIL;
    if (wayland_init(&wlip->wayland, wlip) == FAIL)
    {
        config_uninit(&wlip->config);
        return FAIL;
    }
    if (database_init(&wlip->database, database_dir, wlip) == FAIL)
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

    // Load entry from database if any. "Last_entry" may be -1, if selection was
    // cleared.
    if (database_get_int_setting(&wlip->database, "Last_entry", &id) == FAIL ||
        id == -1)
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
    int64_t    id = database_serialize_entry(&wlip->database, NULL, true);

    if (id == -1)
        goto exit;

    sha256_init(&sha_hash);

    while (mime_type != NULL)
    {
        int fds[2];

        if (pipe(fds) == -1)
        {
            log_errwarn("Error creating pipe");
            goto next;
        }

        struct wl_array content;

        wl_array_init(&content);

        ext_data_control_offer_v1_receive(offer, mime_type, fds[1]);
        // Close our write-end because we don't need it
        close(fds[1]);

        if (wl_display_flush(wlip->wayland.base.display) == -1)
        {
            log_errwarn("Error flushing display");
            goto fail;
        }

#define BUFSIZE 4096
        static char    buf[BUFSIZE];
        static uint8_t data_id[SHA256_BLOCK_SIZE];
        SHA256_CTX     sha_ctx;

        sha256_init(&sha_ctx);

        // Maybe make reading the data asynchronous (do it in the event loop)?
        // Not sure if the extra complexity is worth it...
        while (true)
        {
            ssize_t r = read(fds[0], buf, BUFSIZE);

            if (r == -1)
            {
                // Assume fatal
                log_errwarn("Error reading data");
                wl_array_release(&content);
                goto fail;
            }
            else if (r > 0)
            {
                uint8_t *ptr = wl_array_add(&content, r);

                if (ptr == NULL)
                {
                    log_errwarn("Error allocating array");
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

exit:
    if (database_do_transaction(
            &wlip->database,
            did_something ? TRANSACTION_COMMIT : TRANSACTION_ROLLBACK
        ) == FAIL)
        return -1;

    if (did_something)
    {
        ipc_emit_event(&wlip->ipc, IPC_EVENT_SELECTION, id);
        ipc_emit_event(&wlip->ipc, IPC_EVENT_CHANGE, id, 0, "new");
    }

    return did_something ? id : -1;
}
