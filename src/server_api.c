#include "server_api.h"
#include "alloc.h"
#include "clipboard.h"
#include "hashtable.h"
#include "server.h"
#include <assert.h>

/*
 * A terminator reply is:
 * {
 *   "success": <true|false>,
 *   "serial": <int>
 * }
 */

typedef struct
{
    const char *name;
    void (*func)(command_T *cmd);
} commanddef_T;

static void handler_delete_entry(command_T *cmd);
static void handler_get_data(command_T *cmd);
static void handler_list_clipboards(command_T *cmd);
static void handler_list_entries(command_T *cmd);
static void handler_modify_entry(command_T *cmd);
static void handler_set_mimetype(command_T *cmd);

// Should be in lexiographic order to allow binary search.
static commanddef_T COMMANDS[] = {
    {"DeleteEntry", handler_delete_entry},
    {"GetData", handler_get_data},
    {"ListClipboards", handler_list_clipboards},
    {"ListEntries", handler_list_entries},
    {"ModifyEntry", handler_modify_entry},
    {"SetMimeType", handler_set_mimetype}
};

static int
compare_command_name(const void *key, const void *member)
{
    return strcmp(key, ((commanddef_T *)member)->name);
}

/*
 * Execute the given command (run its handler function).
 */
void
server_api_exec(command_T *cmd)
{
    assert(cmd != NULL);

    commanddef_T *def = bsearch(
        cmd->name, COMMANDS, ARRAY_SIZE(COMMANDS), sizeof(commanddef_T),
        compare_command_name
    );

    if (def == NULL)
    {
        command_send_reply(cmd, false, NULL, NULL, 0);
        return;
    }

    wlip_debug("Executing command '%s'", cmd->name);

    def->func(cmd);
}

/*
 * Get info about an entry with either the ID or index + clipboard. Returns 1 if
 * id is used, 2 if idx is used, and -1 on error. "id" takes priority over
 * index.
 */
static int
get_entry_info(
    command_T *cmd, uint8_t idbuf[SHA256_BLOCK_SIZE], int64_t *idx,
    clipboard_T **cb
)
{
    assert(cmd != NULL);
    assert(idbuf != NULL && idx != NULL && cb != NULL);

    struct json_object *j_clipboard;
    struct json_object *j_idx;
    struct json_object *j_id;

    if (!json_object_object_get_ex(cmd->args, "clipboard", &j_clipboard) ||
        !json_object_is_type(j_clipboard, json_type_string))
        j_clipboard = NULL;

    if (!json_object_object_get_ex(cmd->args, "idx", &j_idx) ||
        !json_object_is_type(j_idx, json_type_int))
        j_idx = NULL;
    if (!json_object_object_get_ex(cmd->args, "id", &j_id) ||
        !json_object_is_type(j_id, json_type_string))
        j_id = NULL;

    if (j_id != NULL)
    {
        uint32_t len = json_object_get_string_len(j_id);

        if (len != 64)
            return -1;

        const char *id = json_object_get_string(j_id);
        sha256_hex2digest(id, idbuf);
        return 1;
    }
    else if (j_idx != NULL && j_clipboard != NULL)
    {
        clipboard_T *c = find_clipboard(json_object_get_string(j_clipboard));
        int64_t i = json_object_get_int64(j_idx);

        if (c == NULL || i < 0)
            return -1;

        *idx = i;
        *cb = c;
        return 2;
    }
    return -1;
}

/*
 * Delete the nth entry from the database for the clipboard. Returns a
 * terminator on success (including if idx doesn't exist). Takes in the
 * arguments:
 * {
 *   "clipboard": <string>,
 *   "idx": <int>
 *   "id": <64 byte string>
 * }
 *
 * Either "idx" & "clipboard" or "id" must be provided. If both are provided,
 * then "id" is used.
 *
 * Returns a terminator.
 */
static void
handler_delete_entry(command_T *cmd)
{
    int64_t idx;
    clipboard_T *cb;
    uint8_t id[SHA256_BLOCK_SIZE];

    int ret = get_entry_info(cmd, id, &idx, &cb);

    if (ret == 1)
    {
        if (clipboard_delete_id(id) == FAIL)
            goto fail;
    }
    else if (ret == 2)
    {
        if (clipboard_delete_entry(cb, idx) == FAIL)
            goto fail;
    }
    else
        goto fail;

    command_send_reply(cmd, true, NULL, NULL, 0);
    return;
fail:
    command_send_reply(cmd, false, NULL, NULL, 0);
}

/*
 * Return the contents/data of the given data id. Arguments:
 * {
 *   "dataid": <data id>
 * }
 *
 * Return value: None (binary data attached to reply)
 */
static void
handler_get_data(command_T *cmd)
{
    struct json_object *j_dataid;

    if (!json_object_object_get_ex(cmd->args, "dataid", &j_dataid) ||
        !json_object_is_type(j_dataid, json_type_string))
        goto fail;

    uint32_t len = json_object_get_string_len(j_dataid);

    if (len != 64)
        goto fail;

    const char *id = json_object_get_string(j_dataid);
    const uint8_t *idbuf = sha256_hex2digest(id, NULL);

    clipdata_T *data;

    // Check if data is already loaded
    data = database_get_data(idbuf, id);

    if (data == NULL)
        goto fail;

    command_send_reply(cmd, true, NULL, data->content.data, data->content.len);
    clipdata_unref(data);

    return;
fail:
    command_send_reply(cmd, false, NULL, NULL, 0);
}

/*
 * Handle the 'ListClipboards' command. Returns an array of strings. Takes in no
 * arguments.
 */
static void
handler_list_clipboards(command_T *cmd)
{
    hashtable_T *clipboards = get_clipboards();
    hashtableiter_T iter = HASHTABLEITER_INIT(clipboards);
    clipboard_T *cb;

    struct json_object *j_ret = json_object_new_array_ext(clipboards->len);

    WLIP_JSON_CHECK(json_object_new_array_ext, j_ret);

    while ((cb = hashtableiter_next(&iter, offsetof(clipboard_T, name))) !=
           NULL)
    {
        struct json_object *j_clipboard =
            json_object_new_string_len(cb->name, cb->name_len);

        WLIP_JSON_CHECK(json_object_new_string_len, j_clipboard);

        json_object_array_add(j_ret, j_clipboard);
    }

    command_send_reply(cmd, true, j_ret, NULL, 0);
    json_object_put(j_ret);
}

static void
send_entry(clipentry_T *entry, void *udata)
{
    command_T *cmd = udata;

    // Create array of mime types
    hashtableiter_T iter;
    hashtableiter_init(&iter, &entry->mime_types);

    struct json_object *j_mimetypes = json_object_new_object();
    mimetype_T *mt;

    WLIP_JSON_CHECK(json_object_new_object, j_mimetypes);

    while ((mt = hashtableiter_next(&iter, offsetof(mimetype_T, name))))
    {
        if (mt->data == NULL)
            continue;

        struct json_object *j_dataid = json_object_new_string_len(
            sha256_digest2hex(mt->data->id, NULL), 64
        );

        WLIP_JSON_CHECK(json_object_new_string_len, j_dataid);
        json_object_object_add_ex(
            j_mimetypes, mt->name, j_dataid, JSON_C_OBJECT_ADD_KEY_IS_NEW
        );
    }

    // Create array of attributes
    hashtableiter_init(&iter, &entry->attributes);

    struct json_object *j_attributes = json_object_new_object();
    attribute_T *attr;

    WLIP_JSON_CHECK(json_object_new_object, j_attributes);

    while ((attr = hashtableiter_next(&iter, offsetof(attribute_T, name))))
    {
        struct json_object *j_val;

        switch (attr->type)
        {
        case ATTRIBUTE_TYPE_STRING:
            j_val = json_object_new_string(attr->val.str);
            break;
        case ATTRIBUTE_TYPE_INTEGER:
            j_val = json_object_new_int64(attr->val.integer);
            break;
        case ATTRIBUTE_TYPE_NUMBER:
            j_val = json_object_new_double(attr->val.number);
            break;
        default:
            continue;
        }
        WLIP_JSON_CHECK(json_object_new_string_len, j_val);

        json_object_object_add_ex(
            j_attributes, attr->name, j_val, JSON_C_OBJECT_ADD_KEY_IS_NEW
        );
    }

    struct json_object *j_ret = construct_json_object(
        "sjjib", "id", sha256_digest2hex(entry->id, NULL), 64, "mimetypes",
        j_mimetypes, "attributes", j_attributes, "creation_time",
        entry->creation_time, "starred", entry->starred
    );

    command_send_reply(cmd, true, j_ret, NULL, 0);
    json_object_put(j_ret);
    clipentry_unref(entry);
}

/*
 * Return the entries starting at "idx" up to "n" entries in the clipboard. If
 * "idx" is out of range, then nothing is done. If "n" goes past the end of the
 * list, then it is truncated. "args" should be in the format:
 * {
 *   "idx": <int>,
 *   "n": <int>,
 *   "clipboard": <string>
 * }
 *
 * Multiple replies, each an entry, in the format below are returned:
 * {
 *   "id": <string>,
 *   "mimetypes": {
 *     "<mime type>": "<data id>",
 *     ...
 *   },
 *   "attributes": {
 *     "<attribute name>": <int|double|string>
 *   }
 *   "creation_time": <int>,
 *   "starred": <bool>
 * }
 *
 * The replies will be ended by a terminator. The entries will be sorted from
 * most recent (first) to oldest (last), determined by creation_time.
 */
static void
handler_list_entries(command_T *cmd)
{
    struct json_object *j_idx, *j_n, *j_clipboard;

    if (!json_object_is_type(cmd->args, json_type_object) ||
        !json_object_object_get_ex(cmd->args, "idx", &j_idx) ||
        !json_object_is_type(j_idx, json_type_int) ||
        !json_object_object_get_ex(cmd->args, "n", &j_n) ||
        !json_object_is_type(j_n, json_type_int) ||
        !json_object_object_get_ex(cmd->args, "clipboard", &j_clipboard) ||
        !json_object_is_type(j_clipboard, json_type_string))
        goto fail;

    int64_t idx = json_object_get_int64(j_idx);
    int64_t n = json_object_get_int64(j_n);
    const char *clipboard = json_object_get_string(j_clipboard);

    clipboard_T *cb = find_clipboard(clipboard);

    if (cb == NULL ||
        clipboard_get_entries(cb, idx, n, send_entry, cmd) == FAIL)
        // Clipboard doesn't exist or error occured
        goto fail;

    command_send_reply(cmd, true, NULL, NULL, 0);
    return;
fail:
    command_send_reply(cmd, false, NULL, NULL, 0);
}

/*
 * Create an entry and serialize it into the database as the most recent entry.
 * If "id" or "idx" is provided, then the entry is modified/updated, if it
 * exists. If the clipboard has no database backend, then the entry is created
 * and set + synced as the current entry. Format:
 * {
 *   "idx": <int>,
 *   "n": <int>,
 *   "clipboard": <string>
 *
 *   "mimetypes": {
 *     "<mime type>": <data id|null>, -- not added if data id doesn't exist.
 *     ...
 *   },
 *   "attributes": {
 *     "<attribute>": <value|null>,
 *     ...
 *   },
 *   "starred": bool
 * }
 *
 * If any value in "mimetypes" or "attributes" is null, then it will be removed
 * if it exists.
 *
 * Return value:
 * {
 *   "id": <entry id>
 * }
 */
static void
handler_modify_entry(command_T *cmd)
{
    int64_t idx;
    clipboard_T *cb;
    uint8_t id[SHA256_BLOCK_SIZE];

    int ret = get_entry_info(cmd, id, &idx, &cb);
    clipentry_T *entry;

    if (ret > 0)
    {
        // Modify entry
        if ((ret == 2 && clipboard_get_entry(cb, idx, &entry) == FAIL) ||
            (ret == 1 && clipboard_get_id(id, &entry) == FAIL))
            goto fail;
    }
    else
        // Create new entry
        entry = clipentry_new(NULL, cb);

    // Create/update mime types
    struct json_object *j_mimetypes;

    if (json_object_object_get_ex(cmd->args, "mimetypes", &j_mimetypes) &&
        json_object_is_type(j_mimetypes, json_type_object))
    {
        json_object_object_foreach(j_mimetypes, mimetype, j_dataid)
        {
            hash_T hash = hash_get(mimetype);
            hashbucket_T *b =
                hashtable_lookup(&entry->mime_types, mimetype, hash);

            if (json_object_is_type(j_dataid, json_type_string))
            {
                const char *dataid = json_object_get_string(j_dataid);
                const uint8_t *digest = sha256_hex2digest(dataid, NULL);

                clipdata_T *data = clipdata_get(digest);
                mimetype_T *mt;

                if (data == NULL)
                    continue;

                if (HB_ISEMPTY(b))
                {
                    mt = mimetype_new(mimetype, data);
                    hashtable_add(&entry->mime_types, b, mt->name, hash);
                }
                else
                {
                    mt = HB_GET(b, mimetype_T, name);

                    if (mt->data != NULL)
                        clipdata_unref(mt->data);
                    mt->data = data;
                }
            }
            // Remove mime type if it exists
            else if (json_object_is_type(j_dataid, json_type_null) &&
                     !HB_ISEMPTY(b))
                hashtable_remove_bucket(&entry->mime_types, b);
        }
    }

    // Create/update attributes
    struct json_object *j_attributes;

    if (json_object_object_get_ex(cmd->args, "attributes", &j_attributes) &&
        json_object_is_type(j_attributes, json_type_object))
    {
        json_object_object_foreach(j_attributes, attribute, j_attribute)
        {
            hash_T hash = hash_get(attribute);
            hashbucket_T *b =
                hashtable_lookup(&entry->attributes, attribute, hash);

            if (json_object_is_type(j_attributes, json_type_null) &&
                !HB_ISEMPTY(b))
                // Remove attribute
                hashtable_remove_bucket(&entry->attributes, b);
            else
            {
                // Add or update attribute to given value.
                attribute_T *attr;
                bool exists = false;

                if (HB_ISEMPTY(b))
                    attr = attribute_new(attribute);
                else
                {
                    attr = HB_GET(b, attribute_T, name);
                    exists = true;
                }

                switch (json_object_get_type(j_attribute))
                {
                case json_type_string:
                    attr->type = ATTRIBUTE_TYPE_STRING;

                    if (attr->val.str != NULL)
                        wlip_free(attr->val.str);

                    attr->val.str =
                        wlip_strdup(json_object_get_string(j_attribute));
                    break;
                case json_type_int:
                case json_type_boolean:
                    attr->type = ATTRIBUTE_TYPE_INTEGER;
                    attr->val.integer = json_object_get_int64(j_attribute);
                    break;
                case json_type_double:
                    attr->type = ATTRIBUTE_TYPE_NUMBER;
                    attr->val.number = json_object_get_double(j_attribute);
                    break;
                default:
                    // Just ignore attribute
                    if (!exists)
                        attribute_free(attr);
                    continue;
                }

                if (!exists)
                    hashtable_add(&entry->attributes, b, attr->name, hash);
            }
        }
    }

    struct json_object *j_starred;

    if (json_object_object_get_ex(cmd->args, "starred", &j_starred) &&
        json_object_is_type(j_starred, json_type_boolean))
        entry->starred = json_object_get_boolean(j_starred);

    if (clipentry_update(entry) == FAIL)
    {
        clipentry_unref(entry);
        goto fail;
    }

    // Return entry ID
    struct json_object *j_ret = construct_json_object(
        "s", "id", sha256_digest2hex(entry->id, NULL), 64
    );

    command_send_reply(cmd, true, j_ret, NULL, 0);
    json_object_put(j_ret);
    clipentry_unref(entry);

    return;
fail:
    command_send_reply(cmd, false, NULL, NULL, 0);
    return;
}

/*
 * Create or update the mime types of the given entry using the attached binary
 * data. All mime types in the array will be set to the binary data. If the
 * clipboard the entry is in has no database backend, then the data will not
 * be saved in the filesystem. Arguments:
 * {
 *   "idx": <int>,
 *   "n": <int>,
 *   "clipboard": <string>,
 *
 *   "mimetypes": [
 *      "<mime type>",
 *      ...
 *   ]
 * }
 *
 * Return value:
 * {
 *   "dataid": <data id>
 * }
 */
static void
handler_set_mimetype(command_T *cmd)
{
    if (cmd->binary == NULL)
        goto fail;

    int64_t idx;
    clipboard_T *cb;
    uint8_t id[SHA256_BLOCK_SIZE];

    int ret = get_entry_info(cmd, id, &idx, &cb);
    clipentry_T *entry;
    struct json_object *j_mimetypes;

    if ((ret == 2 && clipboard_get_entry(cb, idx, &entry) == FAIL) ||
        (ret == 1 && clipboard_get_id(id, &entry) == FAIL) || ret < 0 ||
        !json_object_object_get_ex(cmd->args, "mimetypes", &j_mimetypes) ||
        !json_object_is_type(j_mimetypes, json_type_array))
        goto fail;

    // Create the clipdata_T object
    SHA256_CTX sha;
    uint8_t dataid[SHA256_BLOCK_SIZE];

    sha256_init(&sha);
    sha256_update(&sha, cmd->binary, cmd->binary_len);
    sha256_final(&sha, dataid);

    // Check if data is already exists
    clipdata_T *data = clipdata_get(dataid);

    if (data == NULL)
    {
        // Create new clipdata_T
        data = clipdata_new();

        memcpy(data->id, dataid, SHA256_BLOCK_SIZE);

        array_take(&data->content, cmd->binary, cmd->binary_len);
        data->state = DATA_STATE_LOADED;
        cmd->binary = NULL;

        clipdata_export(data);
    }

    for (size_t i = 0; i < json_object_array_length(j_mimetypes); i++)
    {
        struct json_object *j_mimetype =
            json_object_array_get_idx(j_mimetypes, i);

        if (!json_object_is_type(j_mimetype, json_type_string))
            continue;

        const char *mimetype = json_object_get_string(j_mimetype);
        hash_T hash = hash_get(mimetype);
        hashbucket_T *b = hashtable_lookup(&entry->mime_types, mimetype, hash);
        mimetype_T *mt;

        if (HB_ISEMPTY(b))
        {
            mt = mimetype_new(mimetype, clipdata_ref(data));
            hashtable_add(&entry->mime_types, b, mt->name, hash);
        }
        else
        {
            // Update mime type
            mt = HB_GET(b, mimetype_T, name);

            if (mt->data != data)
            {
                clipdata_unref(mt->data);
                mt->data = clipdata_ref(data);
            }
        }
    }

    int res = clipentry_update(entry);
    clipdata_unref(data);
    clipentry_unref(entry);

    if (res == FAIL)
        goto fail;

    // Return data id
    struct json_object *j_ret = construct_json_object(
        "s", "dataid", sha256_digest2hex(dataid, NULL), 64
    );

    command_send_reply(cmd, true, j_ret, NULL, 0);
    json_object_put(j_ret);

    return;
fail:
    command_send_reply(cmd, false, NULL, NULL, 0);
    return;
}

// vim: ts=4 sw=4 sts=4 et
