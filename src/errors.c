#include "errors.h"

/*
 * Convert the given error code nto a string. Note that some error strings have
 * format specifiers.
 */
const char *
error_to_string(ErrorCode code)
{
    switch (code)
    {
    case WLIP_OK:
        return "Success";
    case WLIP_INVALID_CLIPBOARD_NAME:
        return "Clipboard name must only contain alphanumeric and underscore "
               "characters";
    case WLIP_INVALID_CLIPBOARD_LEN:
        return "Clipboard name too long or has length of zero";
    case WLIP_CLIPBOARD_ALREADY_EXISTS:
        return "Clipboard of same name '%s' already exists";
    }
    return "Unknown error";
}
