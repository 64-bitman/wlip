#include "lua/api.h"
#include "clipboard.h"
#include "lua/api/api_clipboard.h"
#include "lua/api/api_clipdata.h"
#include "lua/api/api_clipentry.h"
#include "wayland.h"
#include <assert.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <stdbool.h>

/*
 * 'wlip.add_clipboard(name, opts)' - Add clipboard and return it
 */
static int
module_wlip_add_clipboard(lua_State *L)
{
    luaL_checktype(L, 2, LUA_TTABLE);

    const char *name = luaL_checkstring(L, 1);
    int64_t max_entries;
    bool no_database;

    // Get options from table

    // opts["max_entries"]
    lua_getfield(L, 2, "max_entries");
    max_entries = luaL_optinteger(L, -1, -1);
    lua_pop(L, 1);

    assert(lua_type(L, 2) == LUA_TTABLE);

    // opts["no_database"]
    lua_getfield(L, 2, "no_database");
    no_database = lua_toboolean(L, -1);
    lua_pop(L, 1);

    clipboard_T *cb = clipboard_new(name);

    if (cb == NULL)
    {
        lua_pushnil(L);
        return 1;
    }

    if (max_entries > 0)
        cb->max_entries = max_entries;
    cb->no_database = no_database;

    clipboard_T **udata = lua_newuserdatauv(L, sizeof(clipboard_T *), 0);

    *udata = cb;
    luaL_setmetatable(L, WLUA_USERDATA_CLIPBOARD);

    return 1;
}

/*
 * Push the 'wlip' module onto the stack.
 */
static int
module_wlip(lua_State *L)
{
    static const luaL_Reg funcs[] = {
        {"add_clipboard", module_wlip_add_clipboard}, {NULL, NULL}
    };
    luaL_newlib(L, funcs);
    return 1;
}

/*
 * '__eq' metamethod handler for pointer equality
 */
int
wlua_metamethod_ptr_eq(lua_State *L)
{
    void **a = lua_touserdata(L, 1);
    void **b = lua_touserdata(L, 2);

    lua_pushboolean(L, *a == *b);
    return 1;
}

/*
 * Register the the API modules and create the metatables for the userdata.
 */
void
wlua_register_api(lua_State *L)
{
    assert(L != NULL);

    luaL_requiref(L, "wlip", module_wlip, false);
    lua_pop(L, 1);

    wlua_metatable_clipboard(L);
    wlua_metatable_clipentry(L);
    wlua_metatable_clipdata(L);
}
