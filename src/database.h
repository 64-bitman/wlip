#pragma once

#include "util.h"
#include <stdint.h>

typedef struct clipboard_S clipboard_T;
typedef struct clipentry_S clipentry_T;
typedef struct clipdata_S clipdata_T;

// Callback takes ownership of "entry".
typedef void (*deserialize_func_T)(clipentry_T *entry, void *udata);

void database_uninit(void);

int database_serialize(clipentry_T *entry);
clipdata_T *database_get_data(
    const char_u digest[SHA256_BLOCK_SIZE], const char data_id[65]
);
int database_load_data(clipdata_T *data);
int database_deserialize(
    int64_t start, int64_t num, clipboard_T *cb, deserialize_func_T func,
    void *udata
);
clipentry_T *database_deserialize_index(int64_t idx, clipboard_T *cb);
clipentry_T *database_deserialize_id(const char_u buf[SHA256_BLOCK_SIZE]);

int database_delete_idx(
    clipboard_T *cb, int64_t idx, char_u idbuf[SHA256_BLOCK_SIZE]
);
int database_delete_id(char_u id[SHA256_BLOCK_SIZE], clipentry_T **store);

// vim: ts=4 sw=4 sts=4 et
