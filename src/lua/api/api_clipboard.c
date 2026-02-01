#include "lua/api/api_clipboard.h"
#include "alloc.h"
#include "clipboard.h"
#include "lua/api.h"
#include "lua/script.h"
#include "wayland.h"
#include <assert.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

/*
 * 'clipboard:attach(seat, selection)' - Attach a Wayland selection to the
 * clipboard. Returns true if successful. If "seat" is nil, then use the first
 * found seat.
 */
static int
method_attach(lua_State *L)
{
    clipboard_T *cb =
        *(clipboard_T **)luaL_checkudata(L, 1, WLUA_USERDATA_CLIPBOARD);
    const char *seat_name = lua_isnil(L, 2) ? NULL : luaL_checkstring(L, 2);
    const char *selection_name = luaL_checkstring(L, 3);
    wlselection_type_T type;

    if (strcmp(selection_name, "regular") == 0)
        type = WLSELECTION_TYPE_REGULAR;
    else if (strcmp(selection_name, "primary") == 0)
        type = WLSELECTION_TYPE_PRIMARY;
    else
    {
        luaL_error(L, "Selection type '%s' is not valid", selection_name);
        return 0; // Silence warning
    }

    wlseat_T *seat = wayland_get_seat(seat_name);

    if (seat == NULL)
    {
        lua_pushboolean(L, false);
        return 1;
    }

    lua_pushboolean(L, wayland_attach_selection(seat, type, cb));
    return 1;
}

/*
 * 'clipboard:sync()' - Sync the selections attached to the clipboard.
 */
static int
method_sync(lua_State *L)
{
    clipboard_T *cb =
        *(clipboard_T **)luaL_checkudata(L, 1, WLUA_USERDATA_CLIPBOARD);

    clipboard_sync(cb, NULL);

    return 0;
}

/*
 * 'clipboard:watch_event(event, callback)' - Call "callback" when "event" is
 * triggered for the clipboard. Returns a unique ID that can be used to remove
 * the callback. Note that the ID may be reused after :unwatch_event() is
 * called.
 */
static int
method_watch_event(lua_State *L)
{
    clipboard_T *cb =
        *(clipboard_T **)luaL_checkudata(L, 1, WLUA_USERDATA_CLIPBOARD);
    const char *event = luaL_checkstring(L, 2);

    lua_pushvalue(L, 3);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    clipboard_watch_event(cb, event, ref);

    lua_pushinteger(L, ref);
    return 1;
}

/*
 * 'clipboard:unwatch_event(id)' - Remove the event callback with the given ID
 * from the clipboard. Returns true if successfully removed.
 */
static int
method_unwatch_event(lua_State *L)
{
    clipboard_T *cb =
        *(clipboard_T **)luaL_checkudata(L, 1, WLUA_USERDATA_CLIPBOARD);
    int ref = luaL_checkinteger(L, 2);

    lua_pushboolean(L, clipboard_unwatch_event(cb, ref));
    return 1;
}

/*
 * 'clipboard:load(idx)' - Load the given entry at the index into the clipboard.
 * Returns true if successful.
 */
static int
method_load(lua_State *L)
{
    clipboard_T **udata = luaL_checkudata(L, 1, WLUA_USERDATA_CLIPBOARD);
    clipboard_T *cb = *udata;

    int64_t idx = luaL_checkinteger(L, 2);

    lua_pushboolean(L, clipboard_load(cb, idx));
    return 1;
}

/*
 * Emit the 'selection.start' event for clipboard. Modifies "mime_types" to
 * remove the mime types that have are rejected by the callbacks.
 */
void
wlua_clipboard_emit_selection_start(clipboard_T *cb, hashtable_T *mime_types)
{
    assert(cb != NULL);
    assert(mime_types != NULL);

    lua_State *L = WLUA_L;
    int *refs = cb->event_cb.selection_start.data;

    for (uint32_t i = 0; i < cb->event_cb.selection_start.len; i++)
    {
        int ref = refs[i];

        lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
        lua_createtable(L, mime_types->len, 0);

        hashtableiter_T iter = HASHTABLEITER_INIT(mime_types);
        const char *mime_type;
        int i = 1;

        while ((mime_type = hashtableiter_next(&iter, 0)) != NULL)
        {
            lua_pushstring(L, mime_type);
            lua_rawseti(L, -2, i++);
        }

        if (lua_pcall(L, 1, 1, 0) != LUA_OK)
        {
            const char *errmsg = lua_tostring(L, -1);

            wlip_warn(
                "Error calling clipboard 'selection.start' callback: %s", errmsg
            );
            lua_pop(L, 1);
            continue;
        }
        if (!lua_istable(L, -1))
        {
            wlip_warn(
                "Error calling clipboard 'selection.start' callback: return "
                "value must be an array of strings"
            );
            continue;
        }

        lua_Unsigned ret_len = lua_rawlen(L, -1);

        for (lua_Unsigned k = 1; k <= ret_len; k++)
        {
            lua_rawgeti(L, -1, k);
            if (!lua_isstring(L, -1))
            {
                wlip_warn(
                    "Error calling clipboard 'selection.start' callback: "
                    "return value must be an array of strings"
                );
                continue;
            }
            const char *mime = lua_tostring(L, -1);

            wlip_free(hashtable_remove(mime_types, mime, 0));
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
    }
}
/*
 * Emit the 'selection.end' event for clipboard. Returns true if entry is
 * allowed.
 */
bool
wlua_clipboard_emit_selection_end(clipboard_T *cb, clipentry_T *entry)
{
    assert(cb != NULL);
    assert(entry != NULL);

    lua_State *L = WLUA_L;
    int *refs = cb->event_cb.selection_end.data;

    // Create entry userdata
    clipentry_T **udata = lua_newuserdatauv(L, sizeof(*udata), 2);

    *udata = clipentry_ref(entry);
    luaL_setmetatable(L, WLUA_USERDATA_CLIPENTRY);

    int entry_idx = lua_absindex(L, -1);
    bool allow = true;

    // Entry is allowed only if all callback return true (make sure to call all
    // callbacks).
    for (uint32_t i = 0; i < cb->event_cb.selection_end.len; i++)
    {
        int ref = refs[i];

        lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
        lua_pushvalue(L, entry_idx);

        if (lua_pcall(L, 1, 1, 0) != LUA_OK)
        {
            const char *errmsg = lua_tostring(L, -1);

            wlip_warn(
                "Error calling clipboard 'selection.end' callback: %s", errmsg
            );
            lua_pop(L, 1);
            continue;
        }

        if (allow)
            allow = lua_toboolean(L, -1);
        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    return allow;
}

/*
 * Create the metatable for the 'wlip.clipboard' userdata.
 */
void
wlua_metatable_clipboard(lua_State *L)
{
    assert(L != NULL);

    static const luaL_Reg clipboard_methods[] = {
        {"attach", method_attach},
        {"sync", method_sync},
        {"watch_event", method_watch_event},
        {"unwatch_event", method_unwatch_event},
        {"load", method_load},
        {"__eq", wlua_metamethod_ptr_eq},
        {NULL, NULL}
    };

    if (luaL_newmetatable(L, WLUA_USERDATA_CLIPBOARD) == 1)
    {
        luaL_setfuncs(L, clipboard_methods, 0);

        // 'wlip.clipboard'.__index = metatable
        lua_pushstring(L, "__index");
        lua_pushvalue(L, -2);
        lua_rawset(L, -3);
    }
    lua_pop(L, 1);
}
