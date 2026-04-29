#pragma once

#include <errno.h>
#include <stdarg.h>

enum log_level
{
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_NONE
};

#define log_print(l, fmt, ...)                                                 \
    log_print_ex(l, __FILE_NAME__, __LINE__, fmt, ##__VA_ARGS__)
#define log_err(l, fmt, ...)                                                   \
    log_print(l, fmt ": %s", ##__VA_ARGS__, strerror(errno))

#define log_debug(fmt, ...) log_print(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) log_print(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) log_print(LOG_WARN, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) log_print(LOG_ERROR, fmt, ##__VA_ARGS__)

#define log_errdebug(fmt, ...) log_err(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define log_errinfo(fmt, ...) log_err(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_errwarn(fmt, ...) log_err(LOG_WARN, fmt, ##__VA_ARGS__)
#define log_errerror(fmt, ...) log_err(LOG_ERROR, fmt, ##__VA_ARGS__)

#define log_abort(fmt, ...)                                                    \
    do                                                                         \
    {                                                                          \
        log_error(fmt, ##__VA_ARGS__);                                         \
        abort();                                                               \
    } while (false)

// clang-format off
void log_init(const char *log_path);
void log_set_level(enum log_level level);
void log_print_ex( enum log_level level, const char *file, int lnum, const char *fmt, ...);
// clang-format on
