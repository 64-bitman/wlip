#pragma once

#define OK 0
#define FAIL -1

enum base_directory
{
    XDG_CONFIG_HOME,
    XDG_DATA_HOME,
    XDG_RUNTIME_DIR
};

#define NUL '\0'

#define wlip_err(fmt, ...) wlip_log(fmt ": %s", ##__VA_ARGS__, strerror(errno));
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

void  wlip_log(const char *fmt, ...) PRINTFLIKE(1, 2);
char *wlip_strdup_printf(const char *fmt, ...) PRINTFLIKE(1, 2);
char *get_base_dir(enum base_directory type, const char *child);
