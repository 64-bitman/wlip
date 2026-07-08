#include "wliplist.h"
#include "wlipdaemon.h"
#include <gio/gio.h>
#include <glib.h>
#include <json-glib/json-glib.h>

static void
free_entry_weak_ref(GWeakRef *entryref)
{
    g_weak_ref_clear(entryref);
    g_free(entryref);
}

/*
 * Represents an entry in the wlip daemon. Any operations/modifications done on
 * this entry is done through the parent list. This just represents an view of
 * the entry.
 */
struct _WlipListEntry
{
    GObject parent;

    int64_t id;

    int64_t creation_time;
    int64_t update_time;

    guint loaded : 1;
    guint starred : 1;
    guint current : 1;

    // Maps mime type string to GBytes (or NULL if not loaded).
    GHashTable *mime_types;
};

G_DEFINE_TYPE(WlipListEntry, wlip_list_entry, G_TYPE_OBJECT)

/*
 * Note that "loaded" property will be notified before the other properties are
 * set (and have their notify signals emitted).
 */
typedef enum
{
    ENTRY_PROP_LOADED = 1,
    ENTRY_PROP_UPDATE_TIME,
    ENTRY_PROP_STARRED,
    ENTRY_PROP_CURRENT,
    N_ENTRY_PROPS,
} WlipListEntryProperties;

static GParamSpec *ENTRY_PROPS[N_ENTRY_PROPS] = {NULL};

static void
wlip_list_entry_get_property(
    GObject *obj, guint prop_id, GValue *value, GParamSpec *pspec
)
{
    WlipListEntry *self = WLIP_LIST_ENTRY(obj);

    switch (prop_id)
    {
    case ENTRY_PROP_LOADED:
        g_value_set_boolean(value, self->loaded);
        break;
    case ENTRY_PROP_UPDATE_TIME:
        g_value_set_int64(value, self->update_time);
        break;
    case ENTRY_PROP_STARRED:
        g_value_set_boolean(value, self->starred);
        break;
    case ENTRY_PROP_CURRENT:
        g_value_set_boolean(value, self->current);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(obj, prop_id, pspec);
        break;
    }
}

static void
wlip_list_entry_finalize(GObject *obj)
{
    WlipListEntry *self = WLIP_LIST_ENTRY(obj);

    g_hash_table_unref(self->mime_types);

    G_OBJECT_CLASS(wlip_list_entry_parent_class)->finalize(obj);
}

static void
wlip_list_entry_class_init(WlipListEntryClass *class)
{
    GObjectClass *obj_class = G_OBJECT_CLASS(class);

    obj_class->get_property = wlip_list_entry_get_property;
    obj_class->finalize = wlip_list_entry_finalize;

    ENTRY_PROPS[ENTRY_PROP_LOADED] = g_param_spec_boolean(
        "loaded",
        NULL,
        NULL,
        FALSE,
        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS | G_PARAM_EXPLICIT_NOTIFY
    );
    ENTRY_PROPS[ENTRY_PROP_UPDATE_TIME] = g_param_spec_int64(
        "update_time",
        NULL,
        NULL,
        G_MININT64,
        G_MAXINT64,
        0,
        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS | G_PARAM_EXPLICIT_NOTIFY
    );
    ENTRY_PROPS[ENTRY_PROP_STARRED] = g_param_spec_boolean(
        "starred",
        NULL,
        NULL,
        FALSE,
        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS | G_PARAM_EXPLICIT_NOTIFY
    );
    ENTRY_PROPS[ENTRY_PROP_CURRENT] = g_param_spec_boolean(
        "current",
        NULL,
        NULL,
        FALSE,
        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS | G_PARAM_EXPLICIT_NOTIFY
    );
}

static void
wlip_list_entry_init(WlipListEntry *self)
{
    self->id = -1;
    self->mime_types = g_hash_table_new_full(
        g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_bytes_unref
    );
}

/*
 * Create new entry that is uninitally unloaded.
 */
static WlipListEntry *
wlip_list_entry_new(void)
{
    return g_object_new(WLIP_TYPE_LIST_ENTRY, NULL);
}

struct _WlipList
{
    GObject parent;

    WlipDaemon *daemon;

    // Total number of entries in history
    int64_t n_entries;

    // Sequence of currently instantiated entries, stored in GWeakRef objects.
    GSequence *entries;
};

static void
entry_loaded_cb(WlipDaemon *daemon, GAsyncResult *result, GWeakRef *entryref)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(JsonObject) resp =
        wlip_daemon_request_finish(daemon, result, &error);
    g_autoptr(WlipListEntry) entry = g_weak_ref_get(entryref);

    free_entry_weak_ref(entryref);
    if (entry == NULL)
        // Entry finalized, do nothing
        return;

    entry->id = json_object_get_int_member_with_default(resp, "id", -1);
    if (entry->id == -1)
        return;

    entry->creation_time =
        json_object_get_int_member_with_default(resp, "creation_time", -1);
    if (entry->creation_time == -1)
        return;

    entry->update_time =
        json_object_get_int_member_with_default(resp, "update_time", -1);
    if (entry->update_time == -1)
        return;

    entry->starred =
        json_object_get_boolean_member_with_default(resp, "starred", FALSE);
    entry->current =
        json_object_get_boolean_member_with_default(resp, "current", FALSE);

    if (JSON_NODE_HOLDS_ARRAY(json_object_get_member(resp, "mime_types")))
    {
        JsonArray *mime_types =
            json_object_get_array_member(resp, "mime_types");

        for (guint i = 0; i < json_array_get_length(mime_types); i++)
        {
            const char *mime_type =
                json_array_get_string_element(mime_types, i);

            if (mime_type == NULL)
                continue;
            g_hash_table_insert(entry->mime_types, g_strdup(mime_type), NULL);
        }
    }

    entry->loaded = TRUE;
    g_object_notify_by_pspec(G_OBJECT(entry), ENTRY_PROPS[ENTRY_PROP_LOADED]);

    g_object_notify_by_pspec(
        G_OBJECT(entry), ENTRY_PROPS[ENTRY_PROP_UPDATE_TIME]
    );
    g_object_notify_by_pspec(G_OBJECT(entry), ENTRY_PROPS[ENTRY_PROP_STARRED]);
    g_object_notify_by_pspec(G_OBJECT(entry), ENTRY_PROPS[ENTRY_PROP_CURRENT]);
}

static void *
wlip_list_get_item(GListModel *list, guint position)
{
    WlipList      *self = WLIP_LIST(list);
    WlipListEntry *entry;
    GWeakRef      *entryref;
    GSequenceIter *iter;

    if (position >= self->n_entries)
        return NULL;

    iter = g_sequence_get_iter_at_pos(self->entries, position);

    if (g_sequence_iter_is_end(iter))
    {
        // Create new entry object and start loading it.
        entryref = g_new(GWeakRef, 1);
        entry = wlip_list_entry_new();

        g_weak_ref_init(entryref, entry);
        g_sequence_insert_before(iter, entryref);

        // Create a new weak ref to be used for the request
        entryref = g_new(GWeakRef, 1);
        g_weak_ref_init(entryref, entry);

        wlip_daemon_request_async(
            self->daemon,
            WLIP_DAEMON_REQUEST_ENTRY,
            G_PRIORITY_LOW,
            NULL,
            (GAsyncReadyCallback)entry_loaded_cb,
            entryref,
            (int64_t)position
        );
    }
    else
    {
        entryref = g_sequence_get(iter);
        entry = g_weak_ref_get(entryref); // Will return strong reference
    }

    return entry;
}

static GType
wlip_list_get_item_type(GListModel *list G_GNUC_UNUSED)
{
    return WLIP_TYPE_LIST_ENTRY;
}

static guint
wlip_list_get_n_items(GListModel *list)
{
    return WLIP_LIST(list)->n_entries;
}

static void
wlip_list_model_init(GListModelInterface *iface)
{
    iface->get_item = wlip_list_get_item;
    iface->get_item_type = wlip_list_get_item_type;
    iface->get_n_items = wlip_list_get_n_items;
}

G_DEFINE_TYPE_WITH_CODE(
    WlipList,
    wlip_list,
    G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE(G_TYPE_LIST_MODEL, wlip_list_model_init)
)

static void
wlip_list_finalize(GObject *obj)
{
    WlipList *self = WLIP_LIST(obj);

    g_sequence_free(self->entries);

    G_OBJECT_CLASS(wlip_list_parent_class)->finalize(obj);
}

static void
wlip_list_dispose(GObject *obj)
{
    WlipList *self = WLIP_LIST(obj);

    g_clear_object(&self->daemon);

    G_OBJECT_CLASS(wlip_list_parent_class)->dispose(obj);
}

static void
wlip_list_class_init(WlipListClass *class)
{
    GObjectClass *obj_class = G_OBJECT_CLASS(class);

    obj_class->finalize = wlip_list_finalize;
    obj_class->dispose = wlip_list_dispose;
}

static void
wlip_list_init(WlipList *self)
{
    self->entries = g_sequence_new((GDestroyNotify)free_entry_weak_ref);
}

static void
event_cb(WlipDaemon *daemon G_GNUC_UNUSED, JsonObject *event, WlipList *list)
{
    const char *event_type =
        json_object_get_string_member_with_default(event, "event", NULL);

    if (event_type == NULL)
        return;

    if (strcmp(event_type, "cleared") == 0)
    {
    }
    else
    {
        int64_t id = json_object_get_int_member_with_default(event, "id", -1);
        int64_t idx =
            json_object_get_int_member_with_default(event, "index", -1);

        if (id == -1 || idx == -1)
            return;

        if (strcmp(event_type, "new") == 0)
        {
            g_list_model_items_changed(G_LIST_MODEL(list), idx, 0, 1);
        }
        if (strcmp(event_type, "deleted") == 0)
        {
            GSequenceIter *iter =
                g_sequence_get_iter_at_pos(list->entries, idx);

            if (!g_sequence_iter_is_end(iter))
                g_sequence_remove(iter);
            g_list_model_items_changed(G_LIST_MODEL(list), idx, 1, 0);
        }
    }
}

static void
history_size_cb(WlipDaemon *daemon, GAsyncResult *result, WlipList *list)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(JsonObject) resp =
        wlip_daemon_request_finish(daemon, result, &error);

    if (resp == NULL)
    {
        g_warning("Error querying history size: %s", error->message);
        goto exit;
    }

    list->n_entries = json_object_get_int_member_with_default(resp, "size", 0);

    // Start listening for events
    g_signal_connect_object(
        list->daemon, "event", G_CALLBACK(event_cb), list, G_CONNECT_DEFAULT
    );
    wlip_daemon_request_async(
        list->daemon,
        WLIP_DAEMON_REQUEST_SUBSCRIBE,
        G_PRIORITY_LOW,
        NULL,
        NULL,
        NULL,
        "new",
        "current",
        "cleared",
        "deleted",
        "starred",
        "updated",
        NULL
    );
    g_list_model_items_changed(G_LIST_MODEL(list), 0, 0, list->n_entries);

exit:
    g_object_unref(list);
}

WlipList *
wlip_list_new(WlipDaemon *daemon)
{
    WlipList *list = g_object_new(WLIP_TYPE_LIST, NULL);

    list->daemon = g_object_ref(daemon);

    // Get the initial history size, after that we can start subscribing to
    // events.
    wlip_daemon_request_async(
        daemon,
        WLIP_DAEMON_REQUEST_HISTORY_SIZE,
        G_PRIORITY_HIGH,
        NULL,
        (GAsyncReadyCallback)history_size_cb,
        g_object_ref(list)
    );

    return list;
}
