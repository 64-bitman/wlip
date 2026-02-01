#pragma once

#include "array.h"
#include "database.h"
#include "hashtable.h"
#include "sha256.h"
#include "util.h"
#include "wayland.h"

typedef enum
{
    DATA_STATE_UNLOADED, // Data is unloaded (contents not stored in
                         // memory).
    DATA_STATE_LOADED,   // Data is loaded (contents loaded in memory)
} data_state_T;

// Reference counted storage class for a block of memory. "id" is the SHA-256
// hash of the contents.
typedef struct clipdata_S clipdata_T;
struct clipdata_S
{
    int refcount;
    hash_T hash; // Cached
    char_u id[SHA256_BLOCK_SIZE];
    array_T content;
    data_state_T state;
    bool exported;
};

// Holds the information for a mime type.
typedef struct
{
    clipdata_T *data; // May be NULL if mimetype is removed

    char name[1]; // Actually longer (holds the mime type name).
} mimetype_T;

typedef enum
{
    ATTRIBUTE_TYPE_REMOVED,
    ATTRIBUTE_TYPE_INTEGER,
    ATTRIBUTE_TYPE_NUMBER,
    ATTRIBUTE_TYPE_STRING,
} attribute_type_T;

// An attribute for an entry, which can either be a boolean, integer, float, or
// string.
typedef struct
{
    union
    {
        int64_t integer;
        double number;
        char *str; // Must be freed
    } val;
    // If type is changed to ATTRIBUTE_TYPE_REMOVED, then the allocated string
    // must be freed as well.
    attribute_type_T type;
    char name[1]; // Actually longer (holds the name of the attribute).
} attribute_T;

typedef struct clipboard_S clipboard_T;

// Clipboard entry, each entry has a globally unique identifier. An entry may
// contain attributes and have mime types.
typedef struct clipentry_S clipentry_T;
struct clipentry_S
{
    int refcount;

    char_u id[SHA256_BLOCK_SIZE];
    hash_T hash; // Cached

    int64_t creation_time; // In microseconds
    bool starred;          // If true, then entry will not be automatically
                           // removed from database.

    hashtable_T attributes;
    hashtable_T mime_types;

    // Pointer to clipboard that this entry is associated with. If NULL, then
    // clipboard doesn't exist anymore.
    clipboard_T *clipboard;
};

#define ID_ISEQUAL(a, b) (memcmp((a), (b), SHA256_BLOCK_SIZE) == 0)

// Internal context used when receiving mime types;
typedef struct
{
    int fd;
    hashtable_T mime_types;
    hashtableiter_T iter;
    clipentry_T *entry;
    clipdata_T *data;
    wlselection_T *sel;
    SHA256_CTX sha;
    bool cancelled;
} clipboard_receivectx_T;

// Max selections that can be synced per clipboard
#define MAX_SELECTIONS 8

// Holds the state for a clipboard. New selections are pushed into the
// clipboard, which are then propogated to the other selections.
struct clipboard_S
{
    // The current entry that all selections are synced to. May be NULL if
    // clipboard is cleared.
    clipentry_T *entry;

    // Current receive context, NULL if there are none going on.
    clipboard_receivectx_T *recv_ctx;

    // If clipboard is not backed by a database. In this case, entries are not
    // saved persistently, and a clipboard can only have one entry at a time in
    // its "history" (max_entries is ignored).
    bool no_database;

    // Maximum number of entries that may be stored in clipboard history. Must
    // be greater than zero.
    int64_t max_entries;

    // Array of Wayland selections that are synced to this clipboard.
    wlselection_T *selections[MAX_SELECTIONS];
    uint32_t selections_len;

    // Holds references to Lua callbacks for each event.
    struct
    {
        array_T selection_start; // 'selection.start' event
        array_T selection_end;   // 'selection.end' event
    } event_cb;

    uint32_t name_len;
    // May only contain alphanumeric characters and underscore.
    char name[1]; // Actually longer (clipboard name)
};

void init_clipboards(void);

clipboard_T *clipboard_new(const char *name);
void clipboard_free(clipboard_T *cb);
void free_clipboards(void);
int clipboard_delete_entry(clipboard_T *cb, int64_t n);
int clipboard_delete_id(uint8_t id[SHA256_BLOCK_SIZE]);
bool clipboard_add_selection(clipboard_T *cb, wlselection_T *sel);
void clipboard_set(clipboard_T *cb, clipentry_T *entry);
void clipboard_sync(clipboard_T *cb, wlselection_T *source);
bool clipboard_load(clipboard_T *cb, int64_t idx);
void clipboard_watch_event(clipboard_T *cb, const char *event, int ref);
bool clipboard_unwatch_event(clipboard_T *cb, int ref);
void clipboard_push_selection(
    clipboard_T *cb, wlselection_T *sel, hashtable_T mime_types
);
int clipboard_get_entries(
    clipboard_T *cb, int64_t start, int64_t num, deserialize_func_T func,
    void *udata
);
int
clipboard_get_entry(clipboard_T *cb, int64_t n, clipentry_T **store);
int
clipboard_get_id(uint8_t id[SHA256_BLOCK_SIZE], clipentry_T **store);
clipboard_T *find_clipboard(const char *name);
hashtable_T *get_clipboards(void);

clipentry_T *clipentry_new(const uint8_t id[SHA256_BLOCK_SIZE], clipboard_T *cb);
int clipentry_update(clipentry_T *entry);
clipentry_T *clipentry_get(const uint8_t id[SHA256_BLOCK_SIZE]);
clipentry_T *clipentry_ref(clipentry_T *entry);
void clipentry_unref(clipentry_T *entry);

attribute_T *attribute_new(const char *name);
void attribute_free(attribute_T *attr);

clipdata_T *clipdata_new(void);
clipdata_T *clipdata_get(const uint8_t id[SHA256_BLOCK_SIZE]);
void clipdata_export(clipdata_T *data);
int clipdata_load(clipdata_T *data);
clipdata_T *clipdata_ref(clipdata_T *data);
void clipdata_unref(clipdata_T *data);

mimetype_T *mimetype_new(const char *mime_type, clipdata_T *data);
void mimetype_free(mimetype_T *mime);
