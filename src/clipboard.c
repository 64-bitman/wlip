#include "clipboard.h"
#include "alloc.h"
#include "database.h"
#include "event.h"
#include "lua/api/api_clipboard.h"
#include "lua/script.h"
#include "util.h"
#include "wayland.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Table that holds all defined clipboards.
static hashtable_T CLIPBOARDS;

// Table of all currently loaded entries
static hashtable_T ENTRIES;

// Table of all data objects that have been exported
static hashtable_T DATA;

void
init_clipboards(void)
{
    hashtable_init(&CLIPBOARDS, 0);
    hashtable_init(&ENTRIES, SHA256_BLOCK_SIZE);
    hashtable_init(&DATA, SHA256_BLOCK_SIZE);
}

/*
 * Allocate a new clipboard named "name" and add it to the global table. If the
 * name is invalid or clipboard with same name already exists, then NULL is
 * returned.
 */
clipboard_T *
clipboard_new(const char *name)
{
    assert(name != NULL);

    uint32_t name_len = STRLEN(name);
    hash_T hash = hash_get(name);
    hashbucket_T *b = hashtable_lookup(&CLIPBOARDS, name, hash);

    // Check if clipboard already exists
    if (!HB_ISEMPTY(b))
    {
        wlip_warn("Clipboard '%s' already exists", name);
        return NULL;
    }

    static const char *valid_chars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";

    if (name_len == 0)
    {
        wlip_warn("Clipboard name has length of zero");
        return NULL;
    }

    for (uint32_t i = 0; i < name_len; i++)
        if (strchr(valid_chars, name[i]) == NULL)
        {
            wlip_warn(
                "Clipboard name '%s' has invalid char '%c'", name, name[i]
            );
            return NULL;
        }

    clipboard_T *cb = wlip_malloc(sizeof(clipboard_T) + name_len);

    sprintf(cb->name, "%s", name);
    cb->name_len = name_len;

    cb->entry = NULL;
    cb->recv_ctx = NULL;
    cb->no_database = false;
    cb->selections_len = 0;

    array_init(&cb->event_cb.selection_start, sizeof(int), 4);
    array_init(&cb->event_cb.selection_end, sizeof(int), 4);

    hashtable_add(&CLIPBOARDS, b, cb->name, hash);

    wlip_debug("New clipboard '%s'", name);

    return cb;
}

static void
lua_func_unref(void *ptr)
{
    if (WLUA_L != NULL)
        luaL_unref(WLUA_L, LUA_REGISTRYINDEX, *(int *)ptr);
}

static void free_receive_context(clipboard_receivectx_T *ctx);

void
clipboard_free(clipboard_T *cb)
{
    assert(cb != NULL);

    if (cb->entry != NULL)
        clipentry_unref(cb->entry);

    for (uint32_t i = 0; i < cb->selections_len; i++)
        wlselection_unref(cb->selections[i]);

    if (cb->recv_ctx != NULL)
        free_receive_context(cb->recv_ctx);

    array_clear_func(&cb->event_cb.selection_start, lua_func_unref);
    array_clear_func(&cb->event_cb.selection_end, lua_func_unref);

    wlip_free(cb);
}

/*
 * Free all clipboards in the global table.
 */
void
free_clipboards(void)
{
    hashtable_clear_func(
        &CLIPBOARDS, (hb_freefunc_T)clipboard_free, offsetof(clipboard_T, name)
    );
    hashtable_clear(&ENTRIES);
    hashtable_clear(&DATA);
}

static bool
delete_check_clipboard(clipboard_T *cb, uint8_t id[SHA256_BLOCK_SIZE])
{
    if (cb->entry != NULL && memcmp(id, cb->entry->id, SHA256_BLOCK_SIZE) == 0)
    {
        if (cb->no_database)
            clipboard_set(cb, NULL);
        else
            clipboard_load(cb, 0);
        clipboard_sync(cb, NULL);
        return true;
    }
    return false;
}

/*
 * Delete the nth entry in the clipboard from history. If there is no nth entry,
 * then nothing is done. If the entry deleted is loaded in the clipboard, then
 * the entry before it is used. Returns OK on success and FAIL on failure.
 */
int
clipboard_delete_entry(clipboard_T *cb, int64_t n)
{
    assert(cb != NULL);
    assert(n >= 0);

    if (cb->no_database)
    {
        if (n == 0 && cb->entry != NULL)
        {
            clipboard_set(cb, NULL);
            clipboard_sync(cb, NULL);
        }
        return OK;
    }

    uint8_t id[SHA256_BLOCK_SIZE];
    int ret = database_delete_idx(cb, n, id);

    if (ret == FAIL)
        return FAIL;
    else if (ret == NOERROR)
        return OK;

    // Check if the entry we deleted is same as the one loaded in clipboard.
    delete_check_clipboard(cb, id);

    return OK;
}

/*
 * Delete the entry with the given id. Returns OK on success (even if ID doesn't
 * exist), and FAIL on failure. Clipboard is updated if entry is same as one
 * loaded in clipboard.
 */
int
clipboard_delete_id(uint8_t id[SHA256_BLOCK_SIZE])
{
    assert(id != NULL);

    clipentry_T *deleted;
    int ret = database_delete_id(id, &deleted);

    if (ret == NOERROR)
        // Clipboards may not have a database backend, so check if its loaded.
        deleted = clipentry_get(id);

    if (ret != FAIL && deleted != NULL)
    {
        delete_check_clipboard(deleted->clipboard, deleted->id);
        clipentry_unref(deleted);
    }
    else
        return FAIL;

    return OK;
}

/*
 * Add the selection to the clipboard so it is synced with it. Note that this
 * does not immediately sync the selection. Returns true if selection was added.
 */
bool
clipboard_add_selection(clipboard_T *cb, wlselection_T *sel)
{
    assert(cb != NULL);
    assert(sel != NULL);

    if (cb->selections_len >= MAX_SELECTIONS)
    {
        wlip_warn(
            "Cannot add more than %u selections per clipboard", MAX_SELECTIONS
        );
        return false;
    }

    // Check if selection is already added
    for (uint32_t i = 0; i < cb->selections_len; i++)
        if (cb->selections[i] == sel)
            return false;

    cb->selections[cb->selections_len++] = wlselection_ref(sel);
    return true;
}

/*
 * Set the clipboard to the entry, which may be NULL to clear the clipboard.
 * Does not add a new reference to "entry".
 */
void
clipboard_set(clipboard_T *cb, clipentry_T *entry)
{
    assert(cb != NULL);

    if (cb->entry != NULL)
        clipentry_unref(cb->entry);

    cb->entry = entry;
}

/*
 * Sync all attached selections to the clipboard. If "source" is not NULL, then
 * it will not be synced with the clipboard.
 */
void
clipboard_sync(clipboard_T *cb, wlselection_T *source)
{
    assert(cb != NULL);

    wlip_debug("Syncing selection for clipboard '%s'", cb->name);

    for (uint32_t i = 0; i < cb->selections_len; i++)
    {
        wlselection_T *sel = cb->selections[i];

        if (sel == source)
            continue;

        if (wlselection_is_valid(sel))
            wlselection_update(sel);
        else
            // Remove from array
            cb->selections[i] = cb->selections[--cb->selections_len];
    }
}

/*
 * Load the entry at the index into the clipboard. Does not sync the clipboard.
 * Returns true if an entry was loaded. Caller must ensure "idx" is >= zero.
 */
bool
clipboard_load(clipboard_T *cb, int64_t idx)
{
    assert(cb != NULL);
    assert(idx >= 0);

    if (cb->no_database)
        return false;

    clipentry_T *entry = database_deserialize_index(idx, cb);

    if (entry != NULL)
        clipboard_set(cb, entry);
    return entry != NULL;
}

/*
 * Add the given reference to the Lua callback to the clipboard for the
 * specified event.
 */
void
clipboard_watch_event(clipboard_T *cb, const char *event, int ref)
{
    assert(cb != NULL);
    assert(event != NULL);

    array_T *arr;

    if (strcmp(event, "selection.start") == 0)
        arr = &cb->event_cb.selection_start;
    else if (strcmp(event, "selection.end") == 0)
        arr = &cb->event_cb.selection_end;
    else
    {
        wlip_warn("Event '%s' does not exist for clipboard", event);
        return;
    }

    array_grow(arr, 1);
    ((int *)arr->data)[arr->len++] = ref;
}

/*
 * Remove the reference to the Lua callback from the clipboard. Returns true if
 * it was removed.
 */
bool
clipboard_unwatch_event(clipboard_T *cb, int ref)
{
    assert(cb != NULL);

    array_T *arrays[] = {
        &cb->event_cb.selection_start, &cb->event_cb.selection_end
    };

    for (int i = 0; i < ARRAY_SIZE(arrays); i++)
    {
        int *refs = arrays[i]->data;

        for (uint32_t i = 0; i < arrays[i]->len; i++)
        {
            if (refs[i] == ref)
            {
                refs[i] = refs[--arrays[i]->len];
                return true;
            }
        }
    }
    return false;
}

/*
 * Set the clipboard to the given entry and sync all selections. Takes ownership
 * of "entry". If "entry" is NULL, then all selections are cleared. "source"
 * should be the selection that caused a selection event, otherwise NULL.
 */
static void
set_entry(clipentry_T *entry, wlselection_T *source)
{
    assert(entry != NULL);

    clipboard_T *cb = entry->clipboard;

    if (!wlua_clipboard_emit_selection_end(cb, entry))
    {
        clipentry_unref(entry);
        return;
    }

    clipboard_set(cb, entry);

    if (!cb->no_database)
    {
        // Add entry to database
        if (database_serialize(entry) == FAIL)
            wlip_warn(
                "Failed serializing entry '%s'",
                sha256_digest2hex(entry->id, NULL)
            );
    }

    clipboard_sync(cb, source);
}

/*
 * Get the next mime type to receive its contents from and return the file
 * descriptor. Returns -1 if at the end.
 */
static int
get_next_mimetype(wlselection_T *sel, hashtableiter_T *iter)
{
    assert(sel != NULL);
    assert(iter != NULL);

    char *mime_type;

    while ((mime_type = hashtableiter_next(iter, 0)) != NULL)
    {
        int fd = wlselection_get_fd(sel, mime_type);

        if (fd == -2)
            return -1;
        else if (fd != -1)
        {
            wlip_debug("Receiving mime type '%s'", mime_type);
            return fd;
        }
    }
    return -1;
}

static void
free_receive_context(clipboard_receivectx_T *ctx)
{
    assert(ctx != NULL);

    if (ctx->entry->clipboard->recv_ctx == ctx)
        ctx->entry->clipboard->recv_ctx = NULL;

    event_remove((eventsource_T *)&ctx->fdsource);
    wlselection_unref(ctx->sel);
    clipentry_unref(ctx->entry);
    hashtable_clear_all(&ctx->mime_types, 0);
    if (ctx->data != NULL)
        clipdata_unref(ctx->data);
    close(ctx->fd);
    wlip_free(ctx);
}

static void
receive_check_cb(eventsource_T *source)
{
    eventfd_T *fdsource = (eventfd_T *)source;
    clipboard_receivectx_T *ctx = source->udata;

    // Check if we have been cancelled
    if (ctx->cancelled)
    {
        wlip_debug("Cancelling previous selection event");
        goto exit;
    }

    // POLLHUP only indicates that the sender has closed their end, not that
    // there is no data in the pipe.
    if (fdsource->revents & (POLLIN | POLLHUP))
    {
        char *mime_type = hashtableiter_current(&ctx->iter, 0);

        // Create clipdata_T if we haven't
        if (ctx->data == NULL)
            ctx->data = clipdata_new();
        if (!array_grow(&ctx->data->content, 512))
        {
            // Mime type content is too large, abort the operation
            wlip_warn(
                "Aborting mime type receive operation, contents are too large"
            );
            goto exit;
        }

        ssize_t r = read(
            fdsource->fd,
            (uint8_t *)ctx->data->content.data + ctx->data->content.len, 512
        );

        if (r == -1)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
        }
        else if (r == 0)
        {
            // EOF received, go onto next mime type if any.
            hash_T hash = hash_get(mime_type);
            hashbucket_T *b =
                hashtable_lookup(&ctx->entry->mime_types, mime_type, hash);

            uint8_t id[SHA256_BLOCK_SIZE];
            sha256_final(&ctx->sha, id);
            clipdata_T *loaded = clipdata_get(id);

            // Check if data is already exported
            if (likely(loaded != NULL))
            {
                clipdata_unref(ctx->data);
                ctx->data = loaded;
            }
            else
            {
                ctx->data->state = DATA_STATE_LOADED;
                memcpy(ctx->data->id, id, SHA256_BLOCK_SIZE);
                clipdata_export(ctx->data);
            }

            mimetype_T *mt;

            // We may have duplicate mime types. In this case just update the
            // mime type (only if data is different).
            if (!HB_ISEMPTY(b))
            {
                mt = HB_GET(b, mimetype_T, name);

                if (mt->data != ctx->data)
                {
                    clipdata_unref(mt->data);
                    mt->data = ctx->data; // Transfer ownership
                }
            }
            else
            {
                mt = mimetype_new(mime_type, ctx->data);
                hashtable_add(&ctx->entry->mime_types, b, mt->name, hash);
            }

            ctx->data = NULL;
            event_remove((eventsource_T *)fdsource);
            close(fdsource->fd);

            int next_fd = get_next_mimetype(ctx->sel, &ctx->iter);

            if (next_fd == -1 || next_fd == -2)
            {
                if (ctx->entry->clipboard->recv_ctx == ctx)
                    ctx->entry->clipboard->recv_ctx = NULL;

                // Finished receiving all mime types, set the entry
                set_entry(ctx->entry, ctx->sel);

                wlselection_unref(ctx->sel);
                hashtable_clear_all(&ctx->mime_types, 0);
                wlip_free(ctx);
            }
            else
            {
                ctx->fd = next_fd;
                sha256_init(&ctx->sha);
                event_add_fd(
                    fdsource, next_fd, POLLIN, receive_check_cb, ctx
                );
            }
            return;
        }
        else
        {
            sha256_update(
                &ctx->sha, ctx->data->content.data + ctx->data->content.len, r
            );
            ctx->data->content.len += r;
            return;
        }
    }
    else if (fdsource->revents & (POLLERR | POLLNVAL))
        wlip_warn("Error occured while receiving mime type contents");
    else
        // Nothing happened
        return;

exit:
    free_receive_context(ctx);
}

/*
 * Push a selection event to the clipboard with the given mime types. Ownership
 * of "mime_types" is taken.
 */
void
clipboard_push_selection(
    clipboard_T *cb, wlselection_T *sel, hashtable_T mime_types
)
{
    assert(cb != NULL);
    assert(sel != NULL);

    // If we are still receiving data for a previous selection, cancel it.
    if (cb->recv_ctx != NULL)
        cb->recv_ctx->cancelled = true;

    clipentry_T *entry = clipentry_new(NULL, cb);

    wlua_clipboard_emit_selection_start(cb, &mime_types);

    if (mime_types.buckets != NULL && mime_types.len > 0)
    {
        clipboard_receivectx_T *ctx =
            wlip_calloc(1, sizeof(clipboard_receivectx_T));

        ctx->mime_types = mime_types;
        hashtableiter_init(&ctx->iter, &ctx->mime_types);

        // Receive first mime type
        int fd = get_next_mimetype(sel, &ctx->iter);

        if (fd != -1)
        {
            ctx->fd = fd;
            ctx->entry = entry;
            ctx->mime_types = mime_types;
            ctx->sel = wlselection_ref(sel);
            ctx->cancelled = false;
            sha256_init(&ctx->sha);

            cb->recv_ctx = ctx;
            event_add_fd(
                &ctx->fdsource, fd, POLLIN, receive_check_cb, ctx
            );
            return;
        }
        wlip_free(ctx);
    }

    // No mime types offered, still let the entry pass through, user may
    // ignore it via scripting (TODO).
    hashtable_clear_all(&mime_types, 0);
    set_entry(entry, sel);
}

/*
 * Same as database_deserialize(), but if the clipboard has no database (no
 * history), then the currently stored entry is returned. Returns OK on success
 * and FAIL on failure. Note that the mime type data may not be loaded.
 */
int
clipboard_get_entries(
    clipboard_T *cb, int64_t start, int64_t num, deserialize_func_T func,
    void *udata
)
{
    assert(cb != NULL);

    if (start < 0 || num <= 0)
        return FAIL;

    if (cb->no_database)
    {
        if (cb->entry != NULL)
            func(clipentry_ref(cb->entry), udata);
        return OK;
    }

    return database_deserialize(start, num, cb, func, udata);
}

/*
 * Same as clipboard_get_entries(), but returns the nth entry. If the entry is
 * already loaded, then a new reference to it is returned. Returns OK on success
 * and FAIL on failure.
 */
int
clipboard_get_entry(clipboard_T *cb, int64_t n, clipentry_T **store)
{
    assert(cb != NULL);
    assert(store != NULL);

    if (n < 0)
        return FAIL;

    if (cb->no_database && n == 0)
    {
        *store = cb->entry == NULL ? NULL : clipentry_ref(cb->entry);
        return OK;
    }

    // database_deserialize_index() checks if the entry is loaded already
    clipentry_T *entry = database_deserialize_index(n, cb);

    if (entry == NULL)
        return FAIL;

    *store = entry;
    return OK;
}

/*
 * Same as clipboard_get_entry(), but use an ID instead. If the entry is already
 * loaded, then a new reference to it is returned.
 */
int
clipboard_get_id(uint8_t id[SHA256_BLOCK_SIZE], clipentry_T **store)
{
    assert(id != NULL);
    assert(store != NULL);

    // Check if entry is already loaded
    clipentry_T *entry = clipentry_get(id);

    if (entry != NULL)
        return OK;

    entry = database_deserialize_id(id);

    if (entry == NULL)
        return FAIL;

    *store = entry;
    return OK;
}

/*
 * Return the clipboard with the given name if it exists, otherwise return NULL.
 */
clipboard_T *
find_clipboard(const char *name)
{
    assert(name != NULL);

    hashbucket_T *b = hashtable_lookup(&CLIPBOARDS, name, hash_get(name));

    if (HB_ISEMPTY(b))
        return NULL;

    return HB_GET(b, clipboard_T, name);
}

/*
 * Return the table that contains all clipboards
 */
hashtable_T *
get_clipboards(void)
{
    return &CLIPBOARDS;
}

/*
 * Allocate a new entry with the given ID and associate it with "cb". If "id" is
 * NULL, then the ID and creation time is automatically generated.
 */
clipentry_T *
clipentry_new(const uint8_t id[SHA256_BLOCK_SIZE], clipboard_T *cb)
{
    assert(cb != NULL);

    clipentry_T *entry = wlip_calloc(1, sizeof(clipentry_T));

    if (id == NULL)
    {
        SHA256_CTX ctx;
        int64_t time = get_realtime_us();

        // ID is just the clipboard name and the current time hashed together.
        sha256_init(&ctx);
        sha256_update(&ctx, (uint8_t *)cb->name, cb->name_len);
        sha256_update(&ctx, (uint8_t *)&time, sizeof(time));
        sha256_final(&ctx, entry->id);
        entry->creation_time = time;
    }
    else
        memcpy(entry->id, id, SHA256_BLOCK_SIZE);

    entry->clipboard = cb;
    entry->refcount = 1;

    hashtable_init(&entry->attributes, 0);
    hashtable_init(&entry->mime_types, 0);

    // Add it to global table
    hash_T hash = hash_get_len(entry->id, SHA256_BLOCK_SIZE);
    hashbucket_T *b = hashtable_lookup_bin(&ENTRIES, entry->id, hash);

    if (HB_ISEMPTY(b))
        hashtable_add_bin(&ENTRIES, b, entry->id, hash);
    else
        // Shouldn't happen, always check if entry is loaded before creating a
        // new one.
        wlip_warn("Entry with same id is already loaded");
    entry->hash = hash;

    return entry;
}

/*
 * Should be called when entry is modified, will serialize the entry into the
 * database if allowed to. If the clipboard is currently set to the entry, then
 * the clipboard is synced and updated. Returns OK on success and FAIL on
 * failure.
 */
int
clipentry_update(clipentry_T *entry)
{
    assert(entry != NULL);

    int res = OK;

    if (!entry->clipboard->no_database)
        res = database_serialize(entry);

    if (entry->clipboard->entry == entry)
        clipboard_sync(entry->clipboard, NULL);
    return res;
}

/*
 * Return an entry with the same ID that is already loaded, else NULL. Returns
 * a new reference.
 */
clipentry_T *
clipentry_get(const uint8_t id[SHA256_BLOCK_SIZE])
{
    assert(id != NULL);

    hash_T hash = hash_get_len(id, SHA256_BLOCK_SIZE);
    hashbucket_T *b = hashtable_lookup_bin(&ENTRIES, id, hash);

    if (HB_ISEMPTY(b))
        return NULL;
    return clipentry_ref(HB_GET(b, clipentry_T, id));
}

static void
clipentry_free(clipentry_T *entry)
{
    assert(entry != NULL);

    hashbucket_T *b = hashtable_lookup_bin(&ENTRIES, entry->id, entry->hash);
    if (!HB_ISEMPTY(b))
        hashtable_remove_bucket(&ENTRIES, b);
    else
        wlip_warn("Entry isn't in global table?");

    hashtable_clear_func(
        &entry->attributes, (hb_freefunc_T)attribute_free,
        offsetof(attribute_T, name)
    );
    hashtable_clear_func(
        &entry->mime_types, (hb_freefunc_T)mimetype_free,
        offsetof(mimetype_T, name)
    );
    wlip_free(entry);
}

clipentry_T *
clipentry_ref(clipentry_T *entry)
{
    assert(entry != NULL);

    entry->refcount++;
    return entry;
}

void
clipentry_unref(clipentry_T *entry)
{
    assert(entry != NULL);

    if (--entry->refcount == 0)
        clipentry_free(entry);
}

/*
 * Allocate a new attribute with the given name. The type and value of the
 * attribute must be set manually after.
 */
attribute_T *
attribute_new(const char *name)
{
    assert(name != NULL);

    attribute_T *attr = wlip_calloc(1, sizeof(attribute_T) + STRLEN(name));

    sprintf(attr->name, "%s", name);

    return attr;
}

void
attribute_free(attribute_T *attr)
{
    if (attr->type == ATTRIBUTE_TYPE_STRING)
        wlip_free(attr->val.str);
    wlip_free(attr);
}

/*
 * Allocate a new clipdata_T struct that is initially unloaded.
 */
clipdata_T *
clipdata_new(void)
{
    clipdata_T *data = wlip_malloc(sizeof(clipdata_T));

    array_init(&data->content, 1, 512);
    data->state = DATA_STATE_UNLOADED;
    data->exported = false;
    data->refcount = 1;
    return data;
}

/*
 * Return a clipdata_T with the same ID that is already exported, else NULL.
 * Returns a new reference.
 */
clipdata_T *
clipdata_get(const uint8_t id[SHA256_BLOCK_SIZE])
{
    assert(id != NULL);

    hash_T hash = hash_get_len(id, SHA256_BLOCK_SIZE);
    hashbucket_T *b = hashtable_lookup_bin(&DATA, id, hash);

    if (HB_ISEMPTY(b))
        return NULL;
    return clipdata_ref(HB_GET(b, clipdata_T, id));
}

/*
 * Add the clipdata_T to the global table. "data->id" should already be set.
 */
void
clipdata_export(clipdata_T *data)
{
    assert(data != NULL);

    hash_T hash = hash_get_len(data->id, SHA256_BLOCK_SIZE);
    hashbucket_T *b = hashtable_lookup_bin(&DATA, data->id, hash);

    if (HB_ISEMPTY(b))
        hashtable_add_bin(&DATA, b, data->id, hash);
    else
        // Shouldn't happen, always check if data is loaded before creating a
        // new loaded one.
        wlip_warn("Data with same id is already exported");
    data->hash = hash;
    data->exported = true;
}

/*
 * If the data isn't loaded, then load it. Returns OK on success and FAIL on
 * failure.
 */
int
clipdata_load(clipdata_T *data)
{
    assert(data != NULL);

    if (data->state == DATA_STATE_LOADED)
        return OK;

    assert(data->content.data == NULL);

    return database_load_data(data);
}

static void
clipdata_free(clipdata_T *data)
{
    assert(data != NULL);

    if (data->exported)
    {
        hashbucket_T *b = hashtable_lookup_bin(&DATA, data->id, data->hash);
        if (!HB_ISEMPTY(b))
            hashtable_remove_bucket(&DATA, b);
        else
            wlip_warn("Data object isn't in global table?");
    }

    array_clear(&data->content);
    wlip_free(data);
}

clipdata_T *
clipdata_ref(clipdata_T *data)
{
    assert(data != NULL);

    data->refcount++;
    return data;
}

void
clipdata_unref(clipdata_T *data)
{
    assert(data != NULL);

    if (--data->refcount == 0)
        clipdata_free(data);
}

/*
 * Allocate a new mime type with the given data. It is initially unloaded and
 * has no ID. Does not add a new reference to "data".
 */
mimetype_T *
mimetype_new(const char *mime_type, clipdata_T *data)
{
    assert(mime_type != NULL);
    assert(data != NULL);

    mimetype_T *mime = wlip_malloc(sizeof(mimetype_T) + STRLEN(mime_type));

    sprintf(mime->name, "%s", mime_type);
    mime->data = data;

    return mime;
}

void
mimetype_free(mimetype_T *mime)
{
    assert(mime != NULL);

    if (mime->data != NULL)
        clipdata_unref(mime->data);
    wlip_free(mime);
}
