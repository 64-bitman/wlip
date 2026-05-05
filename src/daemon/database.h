#pragma once

#include "config.h"
#include "ext-data-control-v1.h"
#include <json.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <wayland-util.h>

struct wlip;

enum database_transaction
{
    TRANSACTION_BEGIN,
    TRANSACTION_IMMEDIATE,
    TRANSACTION_COMMIT,
    TRANSACTION_ROLLBACK,
};

struct database_entry
{
    enum
    {
        DATABASE_ENTRY_STARRED = 1 << 0,
        DATABASE_ENTRY_UPDATE = 1 << 1
    } flags;

    int64_t id;
    int64_t creation_time; // In milliseconds
    int64_t update_time;   // In milliseconds
    bool    starred;
};

typedef void (*entry_func)(struct database_entry *entry, void *udata);

struct database
{
    sqlite3 *handle;

    struct wlip *wlip;

    struct
    {
        sqlite3_stmt *save_setting;
        sqlite3_stmt *get_setting;

        sqlite3_stmt *begin_transaction;
        sqlite3_stmt *begin_immediate;
        sqlite3_stmt *commit_transaction;
        sqlite3_stmt *rollback_transaction;

        sqlite3_stmt *serialize_entry;
        sqlite3_stmt *update_entry;
        sqlite3_stmt *serialize_mime_type;
        sqlite3_stmt *serialize_data;

        sqlite3_stmt *deserialize_mime_types;
        sqlite3_stmt *deserialize_mime_type_data;
        sqlite3_stmt *deserialize_entries;
        sqlite3_stmt *deserialize_entry;

        sqlite3_stmt *entry_exists;

        sqlite3_stmt *delete_entry;

        sqlite3_stmt *n_entries;

        sqlite3_stmt *get_index;
    } stmt;
};

// clang-format off
int database_init(struct database *db, const char *dir, struct wlip *wlip);
void database_uninit(struct database *db);
int database_do_transaction(struct database *db, enum database_transaction type);
int64_t database_serialize_entry(struct database *db, struct database_entry *entry, bool selection);
int database_serialize_mime_type(struct database *db, int64_t id, const char *mime_type, const uint8_t *data_id, uint8_t *data, size_t len);
int database_offer_mime_types(struct database *db, int64_t id, struct ext_data_control_source_v1 *source);
sqlite3_stmt *database_deserialize_mime_type_data(struct database *db, int64_t id, const char *mime_type);
int database_save_selection_hash(struct database *db, const uint8_t *hash);
int database_get_selection_hash(struct database *db, uint8_t *hash);
int database_deserialize_entries(struct database *db, int64_t start, int64_t n, entry_func callback, void *udata);
int database_deserialize_entry(struct database *db, int64_t idx, struct database_entry *entry);
int database_deserialize_entry_id(struct database *db, int64_t id, struct database_entry *entry);
void database_add_mime_types(struct database *db, int64_t id, struct json_object *obj);
bool database_id_exists(struct database *db, int64_t id);
int database_save_int_setting(struct database *db, const char *key, int64_t val);
int database_get_int_setting(struct database *db, const char *key, int64_t *val);
int database_delete_entry(struct database *db, int64_t id);
int64_t database_get_history_size(struct database *db);
int64_t database_get_index(struct database *db, int64_t id);
// clang-format on
