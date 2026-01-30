#pragma once

#include "clipboard.h"
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

void
wlua_clipboard_emit_selection_start(clipboard_T *cb, hashtable_T *mime_types);
bool wlua_clipboard_emit_selection_end(clipboard_T *cb, clipentry_T *entry);

void wlua_metatable_clipboard(lua_State *L);
