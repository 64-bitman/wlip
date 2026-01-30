#pragma once

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

extern lua_State *WLUA_L;

int lua_init(void);
void lua_uninit(void);

#ifndef NDEBUG
void wlua_dump_stack(void);
#endif

// vim: ts=4 sw=4 sts=4 et
