#pragma once

#include "util.h"
#include <stdint.h>

typedef struct clipboard_S clipboard_T;
typedef struct clipentry_S clipentry_T;

// Callback takes ownership of "entry".
typedef void (*deserialize_func_T)(clipentry_T *entry, void *udata);

void database_uninit(void);

int database_serialize(clipentry_T *entry);
int database_deserialize(
    int64_t start, int64_t num, clipboard_T *cb, deserialize_func_T func,
    void *udata
);
clipentry_T *database_deserialize_index(int64_t idx, clipboard_T *cb);
clipentry_T *database_deserialize_id(const char_u buf[SHA256_BLOCK_SIZE]);

// vim: ts=4 sw=4 sts=4 et
