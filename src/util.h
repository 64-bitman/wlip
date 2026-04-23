#pragma once

#include <json.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h> // IWYU pragma: keep
#include <wayland-util.h>

#define OK 0
#define FAIL -1

#define NUL '\0'

#define STRINGIFY_DIRECT(x) #x
#define STRINGIFY(x) STRINGIFY_DIRECT(x)

#define clear(ptr)                                                             \
    do                                                                         \
    {                                                                          \
        free(ptr);                                                             \
        ptr = NULL;                                                            \
    } while (false)
#define array_clear(arr)                                                       \
    do                                                                         \
    {                                                                          \
        wl_array_release(arr);                                                 \
        wl_array_init(arr);                                                    \
    } while (false)

#define wlip_err(fmt, ...) wlip_log(fmt ": %s", ##__VA_ARGS__, strerror(errno))
#define wlip_abort(fmt, ...)                                                   \
    do                                                                         \
    {                                                                          \
        wlip_log(fmt, ##__VA_ARGS__);                                          \
        abort();                                                               \
    } while (false)

#ifdef __GNUC__
#    define UNUSED __attribute__((__unused__))
#    define PRINTFLIKE(n, m) __attribute__((format(printf, n, m)))
#else
#    define UNUSED
#    define PRINTFLIKE(n, m)
#endif

enum base_directory
{
    XDG_CONFIG_HOME,
    XDG_DATA_HOME,
    XDG_RUNTIME_DIR
};

typedef void (*timer_func)(void *udata);
/*
 * Timer source that only triggers once then is removed.
 */
struct timer
{
    int64_t remaining; // In nanoseconds

    timer_func callback; // If NULL, then timer is not active
    void      *udata;

    struct wl_list link;
};

void    wlip_log(const char *fmt, ...) PRINTFLIKE(1, 2);
char   *wlip_strdup_printf(const char *fmt, ...) PRINTFLIKE(1, 2);
char   *get_base_dir(enum base_directory type, const char *child);
int64_t get_time_ns(clockid_t id);
int     write_data(int fd, const uint8_t *data, size_t len);

int   create_lock(const char *path, int *lock_fd);
pid_t lock_is_locked(const char *path);

const char *get_json_string(struct json_object *obj, const char *member);
int
get_json_integer(struct json_object *obj, const char *member, int64_t *store);
void add_json_integer(
    struct json_object *obj, const char *key, int64_t val, bool key_is_static
);
void add_json_boolean(
    struct json_object *obj, const char *key, bool val, bool key_is_static
);
void add_json_string(
    struct json_object *obj,
    const char         *key,
    const char         *val,
    bool                key_is_static
);
