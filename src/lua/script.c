#include "script.h"
#include "alloc.h"
#include "util.h"
#include <assert.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

static struct
{
    lua_State *L;
} LUA;

void *
lua_alloc_func(void *ud UNUSED, void *ptr, size_t osize UNUSED, size_t nsize)
{
    if (nsize == 0)
    {
        wlip_free(ptr);
        return NULL;
    }
    else
        return wlip_realloc(ptr, nsize);
}

/*
 * Create the main Lua state and setup the API. Does not load/execute any files.
 * Returns OK on success and FAIL on failure
 */
int
lua_init(void)
{
    assert(LUA.L == NULL);

    LUA.L = lua_newstate(lua_alloc_func, NULL);

    if (LUA.L == NULL)
    {
        wlip_error("Cannot create Lua state");
        return FAIL;
    }
    luaL_openlibs(LUA.L);

    return OK;
}

void
lua_uninit(void)
{
    assert(LUA.L != NULL);

    lua_close(LUA.L);
    LUA.L = NULL;
}

// vim: ts=4 sw=4 sts=4 et
