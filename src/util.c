#include "util.h"
#include <errno.h> // IWYU pragma: keep
#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // IWYU pragma: keep
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

void
wlip_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
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

/*
 * Get time in nanoseconds depending on clock ID.
 */
int64_t
get_time_ns(clockid_t id)
{
    struct timespec ts;

    if (clock_gettime(id, &ts) == -1)
    {
        wlip_err("Error getting time");
        return -1;
    }

    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/*
 * Write all data to file descriptor. Returns OK on success and FAIL on failure.
 */
int
write_data(int fd, const uint8_t *data, size_t len)
{
    ssize_t w = 0;
    while (len > 0 && (w = write(fd, data, len)) > 0)
        len -= w;

    return w == -1 ? FAIL : OK;
}

/*
 * Create a lock file at the given path, and store its file descriptor in
 * "lock_fd". Returns OK on success and FAIL on failure.
 */
int
create_lock(const char *path, int *lock_fd)
{
    int fd = open(path, O_RDWR | O_CREAT);

    if (fd == -1)
    {
        wlip_err("Error creating lock file '%s'", path);
        return FAIL;
    }

    struct flock fl;

    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = fl.l_len = 0;

    if (fcntl(fd, F_SETLK, &fl) == -1)
    {
        wlip_err("Error locking file '%s'", path);
        close(fd);
        return FAIL;
    }

    *lock_fd = fd;
    return OK;
}

/*
 * Returns locking PID if file is locked, otherwise -1 if unlocked or if it
 * doesn't exist. Returns 0 if an error occured.
 */
pid_t
lock_is_locked(const char *path)
{
    chmod(path, 0644);
    int fd = open(path, O_RDWR);

    if (fd == -1)
    {
        if (errno == ENOENT)
            return -1;
        else
        {
            wlip_err("Failed opening file '%s'", path);
            return 0;
        }
    }

    struct flock fl;
    int          ret;

    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = fl.l_len = 0;

    ret = fcntl(fd, F_GETLK, &fl);
    close(fd);

    if (ret != -1)
        return fl.l_type == F_WRLCK ? fl.l_pid : -1;
    return 0;
}

/*
 * Return string value of key "member" inside object "obj", else NULL.
 */
const char *
get_json_string(struct json_object *obj, const char *member)
{
    struct json_object *j_obj;

    if (!json_object_object_get_ex(obj, member, &j_obj))
        return NULL;

    return json_object_get_string(j_obj);
}

/*
 * Store integer value of key "member" inside object "obj" in "store". Returns
 * OK on success and FAIl on failure.
 */
int
get_json_integer(struct json_object *obj, const char *member, int64_t *store)
{
    struct json_object *j_obj;

    if (!json_object_object_get_ex(obj, member, &j_obj))
        return FAIL;

    *store = json_object_get_int64(j_obj);
    return OK;
}

/*
 * Add an integer value to a JSON object.
 */
void
add_json_integer(
    struct json_object *obj, const char *key, int64_t val, bool key_is_static
)
{
    json_object_object_add_ex(
        obj,
        key,
        json_object_new_int64(val),
        key_is_static ? JSON_C_OBJECT_ADD_CONSTANT_KEY : 0
    );
}

/*
 * Add a boolean value to a JSON object.
 */
void
add_json_boolean(
    struct json_object *obj, const char *key, bool val, bool key_is_static
)
{
    json_object_object_add_ex(
        obj,
        key,
        json_object_new_boolean(val),
        key_is_static ? JSON_C_OBJECT_ADD_CONSTANT_KEY : 0
    );
}

/*
 * Add a string value to a JSON object.
 */
void
add_json_string(
    struct json_object *obj,
    const char         *key,
    const char         *val,
    bool                key_is_static
)
{
    json_object_object_add_ex(
        obj,
        key,
        json_object_new_string(val),
        key_is_static ? JSON_C_OBJECT_ADD_CONSTANT_KEY : 0
    );
}
