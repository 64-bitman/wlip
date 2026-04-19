#include "util.h"
#include "wlip.h"
#include <errno.h> // IWYU pragma: keep
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // IWYU pragma: keep
#include <unistd.h>

void
wlip_log(const char *fmt, ...)
{
    if (WLIP.log_fp == NULL)
        return;

    va_list ap;

    va_start(ap, fmt);
    vfprintf(WLIP.log_fp, fmt, ap);
    fputc('\n', WLIP.log_fp);
    va_end(ap);

    fflush(WLIP.log_fp);
}

char *
wlip_strdup_printf(const char *fmt, ...)
{
    char   *str;
    va_list ap;
    int     len;

    va_start(ap, fmt);
    len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    str = malloc(len + 1);
    if (str == NULL)
        return NULL;

    va_start(ap, fmt);
    vsnprintf(str, len + 1, fmt, ap);
    va_end(ap);

    return str;
}

/*
 * Get user home directory, returns NULL on failure.
 */
static const char *
get_home(void)
{
    const char *home = getenv("HOME");

    if (home == NULL)
    {
        struct passwd *pwd = getpwuid(getuid());

        if (pwd == NULL)
        {
            wlip_err("get_home() getpwuid");
            return NULL;
        }

        home = pwd->pw_dir;
    }

    return home;
}

/*
 * Return allocated string containing the specified base dir suffixed with
 * "child". Returns NULL on failure.
 */
char *
get_base_dir(enum base_directory type, const char *child)
{
    const char *xdg;
    char       *dir;

    switch (type)
    {
    case XDG_CONFIG_HOME:
        xdg = getenv("XDG_CONFIG_HOME");
        break;
    case XDG_DATA_HOME:
        xdg = getenv("XDG_DATA_HOME");
        break;
    case XDG_RUNTIME_DIR:
        xdg = getenv("XDG_RUNTIME_DIR");
        break;
    default:
        wlip_abort("Unknown base directory %d", type);
    }

    if (xdg == NULL)
    {
        if (type == XDG_RUNTIME_DIR)
            dir = wlip_strdup_printf(
                "/run/user/%d%s%s", getuid(), *child == NUL ? "" : "/", child
            );
        else
        {
            const char *home = get_home();

            if (home == NULL)
                return NULL;

            if (type == XDG_CONFIG_HOME)
                dir = wlip_strdup_printf("%s/.config/%s", home, child);
            else
                dir = wlip_strdup_printf("%s/.local/share/%s", home, child);
        }
    }
    else
        dir =
            wlip_strdup_printf("%s%s%s", xdg, *child == NUL ? "" : "/", child);

    if (dir == NULL)
    {
        wlip_err("Error allocating directory path");
        return NULL;
    }

    return dir;
}
