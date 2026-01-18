#pragma once

typedef enum
{
    ERROR_NONE,
    ERROR_EEXIST,
    ERROR_CLIPBOARD_NAME,
    ERROR_CONNECT,
} errorcode_T;

#define ERRMSG_SIZE 512

typedef struct
{
    errorcode_T code;
    char msg[ERRMSG_SIZE];
} error_T;

#define ERROR_INIT {ERROR_NONE}
#define ERROR_ISNONE(e) ((e)->code == ERROR_NONE)

#define OK 0
#define FAIL -1

void error_set(error_T *error, errorcode_T code, const char *fmt, ...);
