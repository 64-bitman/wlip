#pragma once

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

// Names for userdata metatables
#define WLUA_USERDATA_CLIPBOARD "wlip.clipboard"
#define WLUA_USERDATA_CLIPENTRY "wlip.clipentry"
#define WLUA_USERDATA_CLIPDATA "wlip.clipdata"

int wlua_metamethod_ptr_eq(lua_State *L);

void wlua_register_api(lua_State *L);
