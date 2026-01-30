#include "clipboard.h"
#include "lua/api.h"
#include <assert.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

/*
 * 'clipdata.__gc'
 */
static int
metamethod_gc(lua_State *L)
{
    clipdata_T *data = *(clipdata_T **)lua_touserdata(L, 1);

    clipdata_unref(data);
    return 0;
}

/*
 * 'clipentry.__index'
 */
static int
metamethod_index(lua_State *L)
{
    clipdata_T *data = *(clipdata_T **)lua_touserdata(L, 1);
    const char *key = lua_tostring(L, 2);

    if (strcmp(key, "id") == 0)
        lua_pushstring(L, sha256_digest2hex(data->id, NULL));
    else if (strcmp(key, "content") == 0)
        lua_pushlstring(L, data->content.data, data->content.len);
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
    clipdata_T *data = *(clipdata_T **)lua_touserdata(L, 1);

    lua_pushfstring(L, "data %s", sha256_digest2hex(data->id, NULL));
    return 1;
}

/*
 * 'clipentry.__eq'
 */
static int
metamethod_eq(lua_State *L)
{
    clipdata_T *a = *(clipdata_T **)lua_touserdata(L, 1);
    clipdata_T *b = *(clipdata_T **)lua_touserdata(L, 2);

    lua_pushboolean(L, memcmp(a->id, b->id, SHA256_BLOCK_SIZE) == 0);
    return 1;
}

/*
 * Create the metatable for the 'wlip.clipdata' userdata.
 */
void
wlua_metatable_clipdata(lua_State *L)
{
    assert(L != NULL);

    static const luaL_Reg clipentry_methods[] = {
        {"__gc", metamethod_gc},
        {"__index", metamethod_index},
        {"__tostring", metamethod_tostring},
        {"__eq", metamethod_eq},
        {NULL, NULL}
    };

    if (luaL_newmetatable(L, WLUA_USERDATA_CLIPDATA) == 1)
        luaL_setfuncs(L, clipentry_methods, 0);
    lua_pop(L, 1);
}
