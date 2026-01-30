#include "alloc.h"
#include "clipboard.h"
#include "lua/api.h"
#include <assert.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

/*
 * 'clipentry:get_mimetype(mime_type)' - Return the data object for the mime
 * type. Returns nil if mime type doesn't exist.
 */
static int
method_get_mimetype(lua_State *L)
{
    clipentry_T *entry = *(clipentry_T **)lua_touserdata(L, 1);
    const char *mime_type = luaL_checkstring(L, 2);

    mimetype_T *mt = hashtable_find(
        &entry->mime_types, mime_type, offsetof(mimetype_T, name)
    );

    if (mt == NULL)
    {
        lua_pushnil(L);
        return 1;
    }

    clipdata_T **udata = lua_newuserdatauv(L, sizeof(*udata), 0);

    *udata = clipdata_ref(mt->data);
    luaL_setmetatable(L, WLUA_USERDATA_CLIPDATA);

    return 1;
}

/*
 * 'clipentry:set_mimetype(mime_type, data)' - Set/update the mime type to the
 * data object.
 */
static int
method_set_mimetype(lua_State *L)
{
    clipentry_T *entry = *(clipentry_T **)lua_touserdata(L, 1);
    const char *mime_type = luaL_checkstring(L, 2);
    clipdata_T *data =
        *(clipdata_T **)luaL_checkudata(L, 3, WLUA_USERDATA_CLIPDATA);

    hash_T hash = hash_get(mime_type);
    hashbucket_T *b = hashtable_lookup(&entry->mime_types, mime_type, hash);

    if (HB_ISEMPTY(b))
    {
        mimetype_T *mt = mimetype_new(mime_type, clipdata_ref(data));
        hashtable_add(&entry->mime_types, b, mt->name, hash);
    }
    else
    {
        mimetype_T *mt = HB_GET(b, mimetype_T, name);

        clipdata_unref(mt->data);
        mt->data = clipdata_ref(data);
    }

    return 0;
}

static int
iter_mimetypes(lua_State *L)
{
    hashtableiter_T *iter = lua_touserdata(L, lua_upvalueindex(2));
    mimetype_T *mt;

    mt = hashtableiter_next(iter, offsetof(mimetype_T, name));

    if (mt == NULL)
        return 0;

    lua_pushstring(L, mt->name);
    clipdata_T **udata = lua_newuserdatauv(L, sizeof(*udata), 0);

    *udata = clipdata_ref(mt->data);
    luaL_setmetatable(L, WLUA_USERDATA_CLIPDATA);

    return 2;
}

/*
 * 'clipentry:iter_mimetypes()' - Iterate over all mime types in entrry.
 */
static int
method_iter_mimetypes(lua_State *L)
{
    clipentry_T *entry = *(clipentry_T **)lua_touserdata(L, 1);
    hashtableiter_T *iter = lua_newuserdatauv(L, sizeof(*iter), 0);

    hashtableiter_init(iter, &entry->mime_types);

    lua_pushvalue(L, 1);  // Entry userdata (only used to keep a ref)
    lua_pushvalue(L, -2); // Hashtable iterator
    lua_pushcclosure(L, iter_mimetypes, 2);

    return 1;
}

/*
 * Push attribute value to stack if valid, otherwise nil.
 */
static void
attribute_to_lua(lua_State *L, attribute_T *attr)
{
    assert(attr != NULL);

    switch (attr->type)
    {
    case ATTRIBUTE_TYPE_INTEGER:
        lua_pushinteger(L, attr->val.integer);
        break;
    case ATTRIBUTE_TYPE_NUMBER:
        lua_pushnumber(L, attr->val.number);
        break;
    case ATTRIBUTE_TYPE_STRING:
        lua_pushstring(L, attr->val.str);
        break;
    default:
        lua_pushnil(L);
        break;
    }
}

/*
 * 'clipentry:get_attribute(name)' - Return the value for an attribute. Returns
 * nil if it doesn't exist.
 */
static int
method_get_attribute(lua_State *L)
{
    clipentry_T *entry = *(clipentry_T **)lua_touserdata(L, 1);
    const char *attribute = luaL_checkstring(L, 2);

    attribute_T *attr = hashtable_find(
        &entry->attributes, attribute, offsetof(attribute_T, name)
    );

    if (attr == NULL)
    {
        lua_pushnil(L);
        return 1;
    }

    attribute_to_lua(L, attr);

    return 1;
}

/*
 * 'clipentry:set_mimetype(mime_type, data)' - Set/update the attribute to the
 * value.
 */
static int
method_set_attribute(lua_State *L)
{
    clipentry_T *entry = *(clipentry_T **)lua_touserdata(L, 1);
    const char *attribute = luaL_checkstring(L, 2);

    hash_T hash = hash_get(attribute);
    hashbucket_T *b = hashtable_lookup(&entry->attributes, attribute, hash);

    attribute_T *attr;
    bool free = false;

    if (HB_ISEMPTY(b))
    {
        attr = attribute_new(attribute);
        free = true;
    }
    else
        attr = HB_GET(b, attribute_T, name);

    switch (lua_type(L, 3))
    {
    case LUA_TNUMBER:
        if (attr->type == ATTRIBUTE_TYPE_STRING)
            wlip_free(attr->val.str);
        if (lua_isinteger(L, 3))
        {
            attr->type = ATTRIBUTE_TYPE_INTEGER;
            attr->val.integer = lua_tointeger(L, 3);
        }
        else
        {
            attr->type = ATTRIBUTE_TYPE_NUMBER;
            attr->val.integer = lua_tonumber(L, 3);
        }
        break;
    case LUA_TSTRING:
        if (attr->type == ATTRIBUTE_TYPE_STRING)
            wlip_free(attr->val.str);
        attr->type = ATTRIBUTE_TYPE_STRING;
        attr->val.str = wlip_strdup(lua_tostring(L, 3));
        break;
    default:
        if (free)
            attribute_free(attr);
        luaL_error(
            L, "Attribute value cannot have type '%s'", lua_typename(L, 3)
        );
    }

    if (HB_ISEMPTY(b))
        hashtable_add(&entry->attributes, b, attr->name, hash);

    return 0;
}

static int
iter_attributes(lua_State *L)
{
    hashtableiter_T *iter = lua_touserdata(L, lua_upvalueindex(2));
    attribute_T *attr;

    attr = hashtableiter_next(iter, offsetof(attribute_T, name));

    if (attr == NULL)
        return 0;

    lua_pushstring(L, attr->name);
    attribute_to_lua(L, attr);

    return 2;
}

/*
 * 'clipentry:iter_attributes()' - Iterate over all attributes in entry.
 */
static int
method_iter_attributes(lua_State *L)
{
    clipentry_T *entry = *(clipentry_T **)lua_touserdata(L, 1);
    hashtableiter_T *iter = lua_newuserdatauv(L, sizeof(*iter), 0);

    hashtableiter_init(iter, &entry->attributes);

    lua_pushvalue(L, 1);  // Entry userdata (only used to keep a ref)
    lua_pushvalue(L, -2); // Hashtable iterator
    lua_pushcclosure(L, iter_attributes, 2);

    return 1;
}

/*
 * 'clipentry.__gc'
 */
static int
metamethod_gc(lua_State *L)
{
    clipentry_T *entry = *(clipentry_T **)lua_touserdata(L, 1);

    clipentry_unref(entry);
    return 0;
}

/*
 * 'clipentry.__index'
 */
static int
metamethod_index(lua_State *L)
{
    clipentry_T *entry = *(clipentry_T **)lua_touserdata(L, 1);
    const char *key = lua_tostring(L, 2);

    if (strcmp(key, "id") == 0)
        lua_pushstring(L, sha256_digest2hex(entry->id, NULL));
    else if (strcmp(key, "creation_time") == 0)
        lua_pushinteger(L, entry->creation_time);
    else if (strcmp(key, "starred") == 0)
        lua_pushboolean(L, entry->starred);
    else if (strcmp(key, "clipboard") == 0)
    {
        clipboard_T **udata = lua_newuserdatauv(L, sizeof(*udata), 0);

        *udata = entry->clipboard;
        luaL_setmetatable(L, WLUA_USERDATA_CLIPBOARD);
    }
    else if (luaL_getmetafield(L, 1, key) == LUA_TNIL)
        lua_pushnil(L);
    return 1;
}

/*
 * 'clipentry.__tostring'
 */
static int
metamethod_tostring(lua_State *L)
{
    clipentry_T *entry = *(clipentry_T **)lua_touserdata(L, 1);

    lua_pushfstring(L, "entry %s", sha256_digest2hex(entry->id, NULL));
    return 1;
}

/*
 * 'clipentry.__eq'
 */
static int
metamethod_eq(lua_State *L)
{
    clipentry_T *a = *(clipentry_T **)lua_touserdata(L, 1);
    clipentry_T *b = *(clipentry_T **)lua_touserdata(L, 2);

    lua_pushboolean(L, memcmp(a->id, b->id, SHA256_BLOCK_SIZE) == 0);
    return 1;
}

/*
 * Create the metatable for the 'wlip.clipentry' userdata.
 */
void
wlua_metatable_clipentry(lua_State *L)
{
    assert(L != NULL);

    static const luaL_Reg clipentry_methods[] = {
        {"get_mimetype", method_get_mimetype},
        {"set_mimetype", method_set_mimetype},
        {"iter_mimetypes", method_iter_mimetypes},
        {"get_attribute", method_get_attribute},
        {"set_attribute", method_set_attribute},
        {"iter_attributes", method_iter_attributes},
        {"__gc", metamethod_gc},
        {"__index", metamethod_index},
        {"__tostring", metamethod_tostring},
        {"__eq", metamethod_eq},
        {NULL, NULL}
    };

    if (luaL_newmetatable(L, WLUA_USERDATA_CLIPENTRY) == 1)
        luaL_setfuncs(L, clipentry_methods, 0);
    lua_pop(L, 1);
}
