#pragma once

#include "util.h"
#include <json.h>

#define WLIP_JSON_CHECK(func, obj)                                             \
    do                                                                         \
    {                                                                          \
        if (obj == NULL)                                                       \
        {                                                                      \
            wlip_error(STRINGIFY(func) "() fail: %s\n", strerror(errno)); \
            abort();                                                           \
        }                                                                      \
    } while (false)

struct json_object *construct_json_object(const char *fmt, ...);
