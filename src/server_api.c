#include "server_api.h"
#include "clipboard.h"
#include "hashtable.h"
#include "server.h"
#include <assert.h>

/*
 * A terminator reply is:
 * {
 *   "success": true,
 *   "serial": <int>
 * }
 */

typedef struct
{
    const char *name;
    void (*func)(command_T *cmd);
} commanddef_T;

static void handler_list_clipboards(command_T *cmd);
static void handler_list_entries(command_T *cmd);

// Should be in lexiographic order to allow binary search.
static commanddef_T COMMANDS[] = {
    {"ListClipboards", handler_list_clipboards},
    {"ListEntries", handler_list_entries},
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
 * "idx" is out of range, then a terminator is returned. If "n" goes past the
 * end of the list, then it is truncated. "args" should be in the format:
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
 * The replies will be ended by a terminator.
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
    {
        command_send_reply(cmd, false, NULL, NULL, 0);
        return;
    }

    int64_t idx = json_object_get_int64(j_idx);
    int64_t n = json_object_get_int64(j_n);
    const char *clipboard = json_object_get_string(j_clipboard);

    clipboard_T *cb = find_clipboard(clipboard);

    if (cb == NULL ||
        clipboard_get_entries(cb, idx, n, send_entry, cmd) == FAIL)
    {
        // Clipboard doesn't exist or error occured
        command_send_reply(cmd, false, NULL, NULL, 0);
        return;
    }
    command_send_reply(cmd, true, NULL, NULL, 0);
}

// vim: ts=4 sw=4 sts=4 et
