#include "util.h"
#include "log.h"
#include <errno.h> // IWYU pragma: keep
#include <fcntl.h>
#include <pwd.h>
#include <regex.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // IWYU pragma: keep
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

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
            log_errwarn("Error getting passwd entry");
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
        log_abort("Unknown base directory %d", type);
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
        log_errwarn("Error allocating directory path");
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
        log_errwarn("Error getting time");
        return -1;
    }

    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/*
 * Check if "target" matches any of the regexes in arr, which must not be NULL.
 */
bool
match_regex_array(regex_t *arr, int len, const char *target)
{
    for (int i = 0; i < len; i++)
    {
        regex_t *reg = arr + i;

        if (regexec(reg, target, 0, NULL, 0) == 0)
            return true;
    }
    return false;
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
        log_errerror("Error creating lock file '%s'", path);
        return FAIL;
    }

    struct flock fl;

    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = fl.l_len = 0;

    if (fcntl(fd, F_SETLK, &fl) == -1)
    {
        log_errerror("Error locking file '%s'", path);
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
            log_errerror("Failed opening file '%s'", path);
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

    if (!json_object_object_get_ex(obj, member, &j_obj) ||
        !json_object_is_type(j_obj, json_type_string))
        return NULL;

    return json_object_get_string(j_obj);
}

/*
 * Return length of string value of key "member" inside object "obj", else -1.
 */
int
get_json_string_len(struct json_object *obj, const char *member)
{
    struct json_object *j_obj;

    if (!json_object_object_get_ex(obj, member, &j_obj) ||
        !json_object_is_type(j_obj, json_type_string))
        return -1;

    return json_object_get_string_len(j_obj);
}

/*
 * Store integer value of key "member" inside object "obj" in "store". Returns
 * OK on success and FAIL on failure.
 */
int
get_json_integer(struct json_object *obj, const char *member, int64_t *store)
{
    struct json_object *j_obj;

    if (!json_object_object_get_ex(obj, member, &j_obj) ||
        !json_object_is_type(j_obj, json_type_int))
        return FAIL;

    *store = json_object_get_int64(j_obj);
    return OK;
}

/*
 * Store boolean value of key "member" inside object "obj" in "store". Returns
 * OK on success and FAIL on failure.
 */
int
get_json_boolean(struct json_object *obj, const char *member, bool *store)
{
    struct json_object *j_obj;

    if (!json_object_object_get_ex(obj, member, &j_obj) ||
        !json_object_is_type(j_obj, json_type_boolean))
        return FAIL;

    *store = json_object_get_boolean(j_obj);
    return OK;
}

/*
 * Return string value of element at "index" for array "arr", else NULL.
 */
const char *
get_json_arr_string(struct json_object *arr, size_t idx)
{
    struct json_object *j_obj = json_object_array_get_idx(arr, idx);

    if (j_obj == NULL || !json_object_is_type(j_obj, json_type_string))
        return NULL;

    return json_object_get_string(j_obj);
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

/*
 * Add a string value to a JSON array.
 */
void
add_json_arr_string(struct json_object *arr, const char *val)
{
    json_object_array_add(arr, json_object_new_string(val));
}

/*
 * Process the buffer containing JSON messages delimited by newlines. For each
 * message, call "callbak". Returns OK on success and FAIL on failure.
 */
int
process_json_buffer(
    const char          *buf,
    size_t               buflen,
    struct json_tokener *tokener,
    json_callback        callback,
    void                *udata
)
{
    size_t left = buflen;

    while (left > 0)
    {
        size_t      len, off = buflen - left;
        const char *nl = memchr(buf + off, '\n', left);

        if (nl == NULL)
            len = left;
        else
            len = nl - (buf + off);

        if (len == 0)
        {
            // Consume newline
            left--;
            continue;
        }

        enum json_tokener_error j_err;
        struct json_object     *obj;

        obj = json_tokener_parse_ex(tokener, buf + off, len);
        j_err = json_tokener_get_error(tokener);

        if (j_err == json_tokener_success)
        {
            callback(obj, udata);

            left -= len + (nl != NULL);
        }
        else if (j_err == json_tokener_continue)
            break;
        else
        {
            log_error(
                "Error parsing JSON message: %s", json_tokener_error_desc(j_err)
            );
            return FAIL;
        }
    }

    return OK;
}

/*
 * Return the mime type that represents "class" from the JSON array "arr".
 * Returned string is owned by the JSON array object. Returns NULL on failure.
 */
const char *
find_mime_type(struct json_object *arr, enum mime_type_class class)
{
    static const char *text[] = {
        "text/plain;charset=utf-8",
        "text/plain",
        "TEXT",
        "STRING",
        "UTF8_STRING"
    };
    static const char *image[] = {"image/png", "image/jpeg"};

    const char **mime_types;
    int          mime_types_len;

    switch (class)
    {
    case MIMETYPE_CLASS_TEXT:
        mime_types = text;
        mime_types_len = N_ELEMENTS(text);
        break;
    case MIMETYPE_CLASS_IMAGE:
        mime_types = image;
        mime_types_len = N_ELEMENTS(image);
        break;
    default:
        log_abort("Unknown mime type class %d", class);
    }

    size_t len = json_object_array_length(arr);

    for (size_t i = 0; i < len; i++)
    {
        struct json_object *j_mime_type = json_object_array_get_idx(arr, i);

        if (json_object_is_type(j_mime_type, json_type_string))
        {
            const char *mime_type = json_object_get_string(j_mime_type);

            for (int k = 0; k < mime_types_len; k++)
                if (strcmp(mime_type, mime_types[k]) == 0)
                    return mime_type;
        }
    }
    return NULL;
}

/*
 * Make the given fd non blocking. Returns OK on success and FAIL on failure.
 */
int
set_fd_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        log_errwarn("Error setting fd non-blocking");
        return FAIL;
    }
    return OK;
}
