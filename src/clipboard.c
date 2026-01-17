#include "clipboard.h"
#include "alloc.h"
#include "errors.h"
#include "util.h"
#include <assert.h>
#include <string.h>
#include <uv.h>

// Table that holds all defined clipboards.
static hashtable_T CLIPBOARDS;

/*
 * Allocate a new clipboard named "name". If the name is invalid or clipboard
 * with same name already exists, an NULL is returned and *error is set.
 */
clipboard_T *
clipboard_new(const char *name, uv_loop_t *loop, int *error)
{
    assert(name != NULL);
    assert(loop != NULL);
    assert(error != NULL);

    uint32_t name_len = STRLEN(name);
    hash_T hash = hash_get(name);
    hashbucket_T *b = hashtable_lookup(&CLIPBOARDS, name, hash);

    // Check if clipboard already exists
    if (!HB_ISEMPTY(b))
    {
        *error = WLIP_CLIPBOARD_ALREADY_EXISTS;
        return NULL;
    }

    static const char *valid_chars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";

    if (name_len >= CLIPBOARD_NAME_MAX_LEN || name_len == 0)
    {
        *error = WLIP_INVALID_CLIPBOARD_LEN;
        return NULL;
    }

    for (uint32_t i = 0; i < name_len; i++)
        if (strchr(valid_chars, name[i]) == NULL)
        {
            *error = WLIP_INVALID_CLIPBOARD_NAME;
            return NULL;
        }

    clipboard_T *cb = wlip_malloc(sizeof(clipboard_T));

    snprintf(cb->name, CLIPBOARD_NAME_MAX_LEN, "%s", name);

    cb->entry.flags = CLIPENTRY_FLAG_EMPTY;
    cb->no_database = false;
    cb->loop = loop;
    array_init(&cb->selections, sizeof(uint), 2);

    // Initialize global table if we haven't.
    if (CLIPBOARDS.buckets == NULL)
        hashtable_init(&CLIPBOARDS);

    hashtable_add(&CLIPBOARDS, b, cb->name, hash);

    return cb;
}

void
clipboard_free(clipboard_T *cb)
{
    assert(cb != NULL);

    if (cb->entry.flags & CLIPENTRY_FLAG_READY)
        clipentry_clear(&cb->entry);
    array_clear(&cb->selections);
    wlip_free(cb);
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
 * Initialize the entry with the given ID and associate it with "cb". If "id" is
 * NULL, then the ID is automatically generated.
 */
void
clipentry_init(clipentry_T *entry, char id[SHA256_BLOCK_SIZE], clipboard_T *cb)
{
    assert(entry != NULL);
    assert(cb != NULL);

    if (id == NULL)
    {
        SHA256_CTX ctx;
        int64_t time = get_realtime_us();

        // ID is just the clipboard name and the current time hashed together.
        sha256_init(&ctx);
        sha256_update(&ctx, (char_u *)cb->name, CLIPBOARD_NAME_MAX_LEN);
        sha256_update(&ctx, (char_u *)&time, sizeof(time));
        sha256_final(&ctx, entry->id);
    }
    else
        memcpy(entry->id, id, SHA256_BLOCK_SIZE);

    entry->flags = CLIPENTRY_FLAG_READY;
    entry->clipboard = cb;

    hashtable_init(&entry->attributes);
    hashtable_init(&entry->mime_types);
}

void
clipentry_clear(clipentry_T *entry)
{
    assert(entry != NULL);

    hashtable_clear_func(
        &entry->attributes, (hb_free_func)attribute_free,
        offsetof(attribute_T, name)
    );
    hashtable_clear_func(&entry->mime_types, NULL, offsetof(mimetype_T, name));
}

/*
 * Allocate a new attribute with the given name and type. The value of the
 * attribute must be set manually after.
 */
attribute_T *
attribute_new(const char *name, attribute_type_T type)
{
    assert(name != NULL);

    attribute_T *attr = wlip_malloc(sizeof(attribute_T) + STRLEN(name));

    attr->type = type;
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
 * Allocate a new mime type. It is initially unloaded and has no ID.
 */
mimetype_T *
mimetype_new(const char *mime_type)
{
    assert(mime_type != NULL);

    mimetype_T *mime = wlip_malloc(sizeof(mimetype_T) + STRLEN(mime_type));

    array_init(&mime->content, 1, 512);
    sprintf(mime->name, "%s", mime_type);
    mime->state = MIMETYPE_STATE_UNLOADED;
    mime->refcount = 1;

    return mime;
}

static void
mimetype_free(mimetype_T *mime)
{
    assert(mime != NULL);

    array_clear(&mime->content);
    wlip_free(mime);
}

mimetype_T *
mimetype_ref(mimetype_T *mime)
{
    assert(mime != NULL);

    mime->refcount++;
    return mime;
}

void
mimetype_unref(mimetype_T *mime)
{
    assert(mime != NULL);

    if (--mime->refcount == 0)
        mimetype_free(mime);
}

/*
 * Append data to the mime type, which must be in the unloaded state.
 */
void
mimetype_append(mimetype_T *mime, char_u *data, uint32_t len)
{
    assert(mime != NULL);
    assert(mime->state == MIMETYPE_STATE_UNLOADED);
    assert(data != NULL);

    array_add(&mime->content, data, len);
}

/*
 * Finialize the mime type, and set the state to loaded. This will also generate
 * the ID.
 */
void
mimetype_finalize(mimetype_T *mime)
{
    assert(mime != NULL);

    mime->state = MIMETYPE_STATE_LOADED;

    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, mime->content.data, mime->content.len);
    sha256_final(&ctx, mime->id);
}
