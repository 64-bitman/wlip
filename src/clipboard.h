#pragma once

#include "array.h"
#include "hashtable.h"
#include "sha256.h"
#include "util.h"
#include <uv.h>

#define CLIPBOARD_NAME_MAX_LEN 256

typedef enum
{
    MIMETYPE_STATE_UNLOADED, // Mime data is unloaded (contents not stored in
                             // memory).
    MIMETYPE_STATE_LOADED,   // Mime data is loaded (contents loaded in memory)
    MIMETYPE_STATE_REMOVED,  // Mime data has been removed. This is so we know
                             // we should remove this mime type from the
                             // database.
} mimetype_state_T;

// Holds the content of a mime type with a reference count. Each mime data has
// an ID like clipentry_T, however it is the hash of its contents. This is to
// prevent duplication of data, as mime datas with the same ID are simply
// combined together.
typedef struct
{
    uint refcount;
    char_u id[SHA256_BLOCK_SIZE];
    mimetype_state_T state;
    array_T content;

    char name[1]; // Actually longer (holds the mime type name).
} mimetype_T;

typedef enum
{
    ATTRIBUTE_TYPE_REMOVED,
    ATTRIBUTE_TYPE_BOOLEAN,
    ATTRIBUTE_TYPE_INTEGER,
    ATTRIBUTE_TYPE_FLOAT,
    ATTRIBUTE_TYPE_STRING,
    ATTRIBUTE_TYPE_STATIC_STRING,
} attribute_type_T;

// An attribute for an entry, which can either be a boolean, integer, float, or
// string.
typedef struct
{
    union
    {
        bool boolean;
        int64_t integer;
        double fl;
        char *str; // Must be freed
        const char *sstr;
    } val;
    attribute_type_T type;
    char name[1]; // Actually longer (holds the name of the attribute).
} attribute_T;

typedef enum
{
    CLIPENTRY_FLAG_EMPTY, // Entry is empty (equivalent to being NULL)
    CLIPENTRY_FLAG_READY  // Entry is valid for use
} clipentry_flag_T;

typedef struct clipboard_S clipboard_T;

// Clipboard entry, each entry has a globally unique identifier. An entry may
// contain attributes and have mime types.
typedef struct
{
    char_u id[SHA256_BLOCK_SIZE];
    char_u flags;

    hashtable_T attributes;
    hashtable_T mime_types;

    // Pointer to clipboard that this entry is associated with. If NULL, then
    // clipboard doesn't exist anymore.
    clipboard_T *clipboard;
} clipentry_T;

// Holds the state for a clipboard. New selections are pushed into the
// clipboard, which are then propogated to the other selections.
struct clipboard_S
{
    // May only contain alphanumeric characters and underscore.
    char name[CLIPBOARD_NAME_MAX_LEN];

    // The current entry that all selections are synced to. May be NULL if
    // clipboard is cleared.
    clipentry_T entry;

    // If clipboard is not backed by a database. In this case, entries are not
    // saved persistently, and a clipboard can only have one entry at a time in
    // its "history".
    bool no_database;

    // Array of Wayland selections that are synced to this clipboard. Each item
    // is a unique integer which identifies the selection.
    array_T selections;

    uv_loop_t *loop; // Libuv loop that this clipboard uses
};

clipboard_T *clipboard_new(const char *name, uv_loop_t *loop, int *error);
void clipboard_free(clipboard_T *cb);
clipboard_T *find_clipboard(const char *name);

void
clipentry_init(clipentry_T *entry, char id[SHA256_BLOCK_SIZE], clipboard_T *cb);
void clipentry_clear(clipentry_T *entry);

attribute_T *attribute_new(const char *name, attribute_type_T type);
void attribute_free(attribute_T *attr);

mimetype_T *mimetype_new(const char *mime_type);
mimetype_T *mimetype_ref(mimetype_T *mime);
void mimetype_unref(mimetype_T *mime);
void mimetype_append(mimetype_T *mime, char_u *data, uint32_t len);
void mimetype_finalize(mimetype_T *mime);
