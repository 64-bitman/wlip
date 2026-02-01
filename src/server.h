#pragma once

#include "util.h"
#include <json.h>
#include <stdint.h>

typedef struct connection_S connection_T;

// Represents a command received from a client
typedef struct
{
    const char *name;
    struct json_object *args; // May be NULL if there are no arguments
    int64_t serial;
    uint8_t *binary; // NULL if there is no binary data attached
    uint32_t binary_len;
    connection_T *ct; // Internal use
} command_T;

int server_init(void);
void server_uninit(void);

void command_send_reply(
    command_T *cmd, bool success, struct json_object *ret,
    const char_u *binary_data, uint32_t binary_len
);

// vim: ts=4 sw=4 sts=4 et
