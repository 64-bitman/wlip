#include "json_util.h"
#include <assert.h>
#include <json.h>
#include <stdarg.h>

/*
 * Construct a JSON object using the variadic arguments. "format" can have the
 * follwing specifiers:
 *
 * "s": string (ownership not taken)
 * "i": integer
 * "b": boolean
 * "j": struct json_object * (ownership is taken)
 *
 * The variadic arguments should be in the format of:
 * <name>, <value>
 *
 * For strings:
 * <name>, <string>, <uint32_t len>
 *
 * Note that all keys must be unique
 */
struct json_object *
construct_json_object(const char *fmt, ...)
{
    assert(fmt != NULL);

    struct json_object *obj = json_object_new_object();
    va_list ap;

    WLIP_JSON_CHECK(json_object_new_object, obj);
    va_start(ap, fmt);

    for (char c = *fmt; c != NUL; c = *(++fmt))
    {
        const char *name = va_arg(ap, const char *);
        struct json_object *subobj;

        switch (c)
        {
        case 's':
        {
            const char *str = va_arg(ap, const char *);
            uint32_t len = va_arg(ap, uint32_t);

            subobj = json_object_new_string_len(str, len);
            break;
        }
        case 'i':
        {
            int64_t nr = va_arg(ap, int64_t);

            subobj = json_object_new_int64(nr);
            break;
        }
        case 'b':
            bool b = va_arg(ap, int);

            subobj = json_object_new_boolean(b);
            break;
        case 'j':
            subobj = va_arg(ap, struct json_object *);
            break;
        default:
            wlip_error("construct_json_object() unknown specifier");
            abort();
        }

        json_object_object_add_ex(
            obj, name, subobj, JSON_C_OBJECT_ADD_KEY_IS_NEW
        );
    }

    va_end(ap);

    return obj;
}
