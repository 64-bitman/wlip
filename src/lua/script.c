#include "lua/script.h"
#include "alloc.h"
#include "lua/api.h"
#include "util.h"
#include <assert.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

lua_State *WLUA_L;

static void *
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
 * Execute the configuration file. Returns OK on success and FAIL on failure.
 */
static int
execute_config(void)
{
    // Configuration directories to use, in ascending priority.
    static char config_dirs[2][PATH_MAX];

    const char *xdgconfighome = getenv("XDG_CONFIG_HOME");
    const char *home = getenv("HOME");

    if (xdgconfighome != NULL)
        wlip_snprintf(config_dirs[0], PATH_MAX, "%s/wlip", xdgconfighome);
    else if (home != NULL)
        wlip_snprintf(config_dirs[0], PATH_MAX, "%s/.config/wlip", home);
    else
        wlip_snprintf(
            config_dirs[0], PATH_MAX, "%s/.config/wlip",
            getpwuid(getuid())->pw_dir
        );
    wlip_snprintf(config_dirs[1], PATH_MAX, "/etc/wlip");

    // Get the configuration directory to read
    struct stat sb;
    const char *config_dir = NULL;

    for (int i = 0; i < ARRAY_SIZE(config_dirs); i++)
        if (stat(config_dirs[i], &sb) == 0 && S_ISDIR(sb.st_mode))
        {
            config_dir = config_dirs[i];
            break;
        }

    char cfg[PATH_MAX];

    if (config_dir == NULL)
    {
        wlip_error("Cannot find config directory");
        return FAIL;
    }
    wlip_snprintf(cfg, PATH_MAX, "%s/config.lua", config_dir);

    if (stat(cfg, &sb) == -1 || !S_ISREG(sb.st_mode))
    {
        wlip_error(
            "Config file '%s' does not exist or is not a text file", cfg
        );
        return FAIL;
    }

    if (luaL_dofile(WLUA_L, cfg) != LUA_OK)
    {
        const char *errmsg = lua_tostring(WLUA_L, -1);

        wlip_error("Failed executing config file: %s", errmsg);
        return FAIL;
    }

    return OK;
}

/*
 * Create the main Lua state and setup the API. Returns OK on success and FAIL
 * on failure
 */
int
lua_init(void)
{
    assert(WLUA_L == NULL);

    WLUA_L = lua_newstate(lua_alloc_func, NULL);

    if (WLUA_L == NULL)
    {
        wlip_error("Error creating Lua state");
        return FAIL;
    }
    luaL_openlibs(WLUA_L);
    wlua_register_api(WLUA_L);

    if (execute_config() == FAIL)
    {
        lua_uninit();
        return FAIL;
    }

    return OK;
}

void
lua_uninit(void)
{
    if (WLUA_L == NULL)
        return;

    lua_close(WLUA_L);
    WLUA_L = NULL;
}

#ifndef NDEBUG
/*
 * Useful for debugging
 */
void
wlua_dump_stack(void)
{
    assert(WLUA_L != NULL);

    int i;
    int top = lua_gettop(WLUA_L);

    printf("<Lua stack top>\n");

    for (i = top; i >= 1; i--)
    {
        int t = lua_type(WLUA_L, i);

        printf("(%d|%d): ", i, i - top - 1);
        switch (t)
        {
        case LUA_TSTRING:
            printf("(string, '%s')", lua_tostring(WLUA_L, i));
            break;
        case LUA_TBOOLEAN:
            printf(
                "(boolean, '%s')", lua_toboolean(WLUA_L, i) ? "true" : "false"
            );
            break;
        case LUA_TNUMBER:
            printf("(string, '%lf')", lua_tonumber(WLUA_L, i));
            break;
        default:
            printf("(%s)", lua_typename(WLUA_L, t));
            break;
        }
        if (i > 1)
            printf("\n");
    }
    printf("\n<Lua stack bottom>\n");
}
#endif

// vim: ts=4 sw=4 sts=4 et
