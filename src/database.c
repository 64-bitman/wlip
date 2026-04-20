#include "database.h"
#include "config.h"
#include "ext-data-control-v1.h"
#include "sha256.h"
#include "util.h"
#include <errno.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <wayland-util.h>

#define DATABASE_VER 1

// clang-format off
static const char *SCHEMA =
    "PRAGMA foreign_keys = ON;"
    "PRAGMA journal_mode = WAL;"
    "PRAGMA synchronous = NORMAL;"
    "PRAGMA user_version = " STRINGIFY(DATABASE_VER) ";"
    ""
    "CREATE TABLE IF NOT EXISTS Settings ("
    "   Key             TEXT PRIMARY KEY,"
    "   Value           NOT NULL"
    ") WITHOUT ROWID;"
    ""
    "CREATE TABLE IF NOT EXISTS Entries ("
    "   Id              INTEGER PRIMARY KEY,"
    "   Creation_time   INTEGER NOT NULL,"
    "   Update_time     INTEGER NOT NULL,"
    "   Starred         BOOLEAN NOT NULL"
    ");"
    ""
    "CREATE TABLE IF NOT EXISTS Mime_types ("
    "   Id              INTEGER NOT NULL,"
    "   Mime_type       TEXT NOT NULL,"
    "   Data_id         BLOB(32)," // May be NULL
    "   PRIMARY KEY (Id, Mime_type),"
    "   FOREIGN KEY (Id) REFERENCES Entries(Id) ON DELETE CASCADE"
    "   FOREIGN KEY (Data_id) REFERENCES Data(Data_id) ON DELETE RESTRICT"
    ") WITHOUT ROWID;"
    ""
    "CREATE TABLE IF NOT EXISTS Data ("
    "   Data_id         BLOB(32) PRIMARY KEY,"
    "   Data            BLOB NOT NULL"
    ") WITHOUT ROWID;"
    ""
    "CREATE TRIGGER IF NOT EXISTS trim_entries "
    "   AFTER INSERT ON Entries BEGIN "
    "       DELETE FROM Entries WHERE Creation_time IN ("
    "           SELECT Creation_time FROM Entries WHERE Starred = 0 "
    "               ORDER BY Creation_time DESC LIMIT -1 OFFSET ("
    "                   SELECT Value FROM Settings WHERE Key = 'Max_entries'"
    "               )"
    "       );"
    "END;"
    ""
    "CREATE TRIGGER IF NOT EXISTS del_data_row "
    "   AFTER DELETE ON main.Mime_types BEGIN "
    "       DELETE FROM Data WHERE Data_id = OLD.Data_id "
    "           AND NOT EXISTS (SELECT 1 FROM Mime_types WHERE"
    "               Data_id = OLD.Data_id); "
    "END;"
    ""
    "CREATE TRIGGER IF NOT EXISTS del_data_row_on_update "
    "   AFTER UPDATE OF Data_id ON main.Mime_types BEGIN "
    "       DELETE FROM Data WHERE Data_id = OLD.Data_id "
    "           AND NOT EXISTS (SELECT 1 FROM Mime_types WHERE"
    "               Data_id = OLD.Data_id); "
    "END;"
    "";
// clang-format on

static int  database_prepare_statements(struct database *db);
static void database_finalize_statements(struct database *db);

/*
 * Initialize the database at the given path If "dir" is NULL, then use an in
 * memory database. Returns OK on success and FAIL on failure.
 */
int
database_init(struct database *db, const char *dir, struct config *config)
{
    char *tofree = NULL;

    if (dir == NULL)
    {
        tofree = get_base_dir(XDG_DATA_HOME, "wlip");
        dir = tofree;
    }
    if (dir == NULL)
        return FAIL;
    if (mkdir(dir, 0755) == -1 && errno != EEXIST)
    {
        wlip_err("Error creating directory '%s'", dir);
        free(tofree);
        return FAIL;
    }

    char *path = wlip_strdup_printf("%s/history.sqlite3", dir);

    free(tofree);
    if (path == NULL)
        return FAIL;

    int flags =
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX;
    int ret = sqlite3_open_v2(path, &db->handle, flags, NULL);

    free(path);
    if (ret != SQLITE_OK)
    {
        wlip_log(
            "Error opening database at '%s': %s",
            dir,
            sqlite3_errmsg(db->handle)
        );

        if (db->handle != NULL)
            sqlite3_close(db->handle);
        return FAIL;
    }

    // Execute database schema
    char *err_msg = NULL;

    ret = sqlite3_exec(db->handle, SCHEMA, NULL, NULL, &err_msg);

    if (ret != SQLITE_OK)
    {
        wlip_log("Error executing database schema: %s", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db->handle);
        return FAIL;
    }

    db->config = config;

    // Apply relevant config options to "Settings" table
    char *settings_statement_fmt =
        "INSERT OR REPLACE INTO Settings (Key, Value) "
        "    VALUES ('Max_entries', %" PRId64 ");";
    char *settings_statement =
        wlip_strdup_printf(settings_statement_fmt, config->max_entries);

    if (settings_statement == NULL ||
        sqlite3_exec(db->handle, settings_statement, NULL, NULL, &err_msg) !=
            SQLITE_OK)
    {
        wlip_log("Error executing database settings: %s", err_msg);

        free(settings_statement);
        sqlite3_free(err_msg);
        sqlite3_close(db->handle);
        return FAIL;
    }
    free(settings_statement);

    if (database_prepare_statements(db) == FAIL)
    {
        sqlite3_close(db->handle);
        return FAIL;
    }

    return OK;
}

void
database_uninit(struct database *db)
{
    database_finalize_statements(db);

    sqlite3_close(db->handle);
}

static int
database_prepare_statements(struct database *db)
{
    memset(&db->stmt, 0, sizeof(db->stmt));

    const char *statement;

    statement = "INSERT OR REPLACE INTO Settings (Key, Value) "
                "   VALUES (?, ?);";
    if (sqlite3_prepare_v2(
            db->handle, statement, -1, &db->stmt.save_setting, NULL
        ) != SQLITE_OK)
        goto fail;

    statement = "SELECT Value FROM Settings WHERE Key = ?;";
    if (sqlite3_prepare_v2(
            db->handle, statement, -1, &db->stmt.get_setting, NULL
        ) != SQLITE_OK)
        goto fail;

    statement = "BEGIN TRANSACTION;";
    if (sqlite3_prepare_v2(
            db->handle, statement, -1, &db->stmt.begin_transaction, NULL
        ) != SQLITE_OK)
        goto fail;

    statement = "BEGIN IMMEDIATE TRANSACTION;";
    if (sqlite3_prepare_v2(
            db->handle, statement, -1, &db->stmt.begin_immediate, NULL
        ) != SQLITE_OK)
        goto fail;

    statement = "COMMIT;";
    if (sqlite3_prepare_v2(
            db->handle, statement, -1, &db->stmt.commit_transaction, NULL
        ) != SQLITE_OK)
        goto fail;

    statement = "ROLLBACK TRANSACTION;";
    if (sqlite3_prepare_v2(
            db->handle, statement, -1, &db->stmt.rollback_transaction, NULL
        ) != SQLITE_OK)
        goto fail;

    statement = "INSERT INTO Entries (Creation_time, Update_time, Starred) "
                "VALUES (?, ?, ?) RETURNING Id;";
    if (sqlite3_prepare_v2(
            db->handle, statement, -1, &db->stmt.serialize_entry, NULL
        ) != SQLITE_OK)
        goto fail;

    statement = "UPDATE Entries SET Update_time = ?, Starred = ? "
                "   WHERE Id = ?;";
    if (sqlite3_prepare_v2(
            db->handle, statement, -1, &db->stmt.update_entry, NULL
        ) != SQLITE_OK)
        goto fail;

    statement = "INSERT OR IGNORE INTO Mime_types (Id, Mime_type, Data_id) "
                "VALUES (?, ?, ?);";
    if (sqlite3_prepare_v2(
            db->handle, statement, -1, &db->stmt.serialize_mime_type, NULL
        ) != SQLITE_OK)
        goto fail;

    statement = "INSERT OR IGNORE INTO Data (Data_id, Data) VALUES (?, ?);";
    if (sqlite3_prepare_v2(
            db->handle, statement, -1, &db->stmt.serialize_data, NULL
        ) != SQLITE_OK)
        goto fail;

    statement = "SELECT Mime_type, Data_id FROM Mime_types WHERE Id = ?;";
    if (sqlite3_prepare_v2(
            db->handle, statement, -1, &db->stmt.deserialize_mime_types, NULL
        ) != SQLITE_OK)
        goto fail;

    statement = "SELECT Data.Data FROM Data LEFT JOIN Mime_types "
                "   ON Mime_types.Data_id = Data.Data_id WHERE "
                "       Mime_types.Id = ? AND Mime_types.Mime_type = ?;";
    if (sqlite3_prepare_v2(
            db->handle,
            statement,
            -1,
            &db->stmt.deserialize_mime_type_data,
            NULL
        ) != SQLITE_OK)
        goto fail;

    statement = "SELECT Id, Creation_time, Update_time, Starred FROM Entries"
                "   ORDER BY Id DESC LIMIT ? OFFSET ?;";
    if (sqlite3_prepare_v2(
            db->handle, statement, -1, &db->stmt.deserialize_entries, NULL
        ) != SQLITE_OK)
        goto fail;

    return OK;
fail:
    wlip_log(
        "Error preparing database statement '%s': %s",
        statement,
        sqlite3_errmsg(db->handle)
    );
    database_finalize_statements(db);
    return FAIL;
}

static void
database_finalize_statements(struct database *db)
{
    if (db->stmt.save_setting != NULL)
        sqlite3_finalize(db->stmt.save_setting);
    if (db->stmt.save_setting != NULL)
        sqlite3_finalize(db->stmt.get_setting);

    if (db->stmt.serialize_entry != NULL)
        sqlite3_finalize(db->stmt.begin_transaction);
    if (db->stmt.serialize_entry != NULL)
        sqlite3_finalize(db->stmt.begin_immediate);
    if (db->stmt.serialize_entry != NULL)
        sqlite3_finalize(db->stmt.commit_transaction);
    if (db->stmt.serialize_entry != NULL)
        sqlite3_finalize(db->stmt.rollback_transaction);

    if (db->stmt.serialize_entry != NULL)
        sqlite3_finalize(db->stmt.serialize_entry);
    if (db->stmt.serialize_entry != NULL)
        sqlite3_finalize(db->stmt.update_entry);
    if (db->stmt.serialize_mime_type != NULL)
        sqlite3_finalize(db->stmt.serialize_mime_type);
    if (db->stmt.serialize_data != NULL)
        sqlite3_finalize(db->stmt.serialize_data);

    if (db->stmt.deserialize_mime_types != NULL)
        sqlite3_finalize(db->stmt.deserialize_mime_types);
    if (db->stmt.deserialize_mime_type_data != NULL)
        sqlite3_finalize(db->stmt.deserialize_mime_type_data);
    if (db->stmt.deserialize_entries != NULL)
        sqlite3_finalize(db->stmt.deserialize_entries);
}

/*
 * Start a transaction for the database. Returns OK on success and FAIL on
 * failure.
 */
int
database_do_transaction(struct database *db, enum database_transaction type)
{
    sqlite3_stmt *stmt;

    switch (type)
    {
    case TRANSACTION_BEGIN:
        stmt = db->stmt.begin_transaction;
        break;
    case TRANSACTION_IMMEDIATE:
        stmt = db->stmt.begin_immediate;
        break;
    case TRANSACTION_COMMIT:
        stmt = db->stmt.commit_transaction;
        break;
    case TRANSACTION_ROLLBACK:
        stmt = db->stmt.rollback_transaction;
        break;
    default:
        wlip_abort("Unknown transaction %d", type);
        break;
    }

    int ret = sqlite3_step(stmt);

    sqlite3_reset(stmt);
    if (ret != SQLITE_DONE)
    {
        wlip_log(
            "Error starting database transaction %d: %s",
            type,
            sqlite3_errmsg(db->handle)
        );
        return FAIL;
    }

    return OK;
}

/*
 * Serialize an entry into the database and return its ID. If "entry" is NULL,
 * then a new entry is created automatically, and its ID is returned. Returns -1
 * on failure.
 */
int64_t
database_serialize_entry(struct database *db, struct database_entry *entry)
{
    sqlite3_stmt *stmt;

    if (entry != NULL)
    {
        stmt = db->stmt.update_entry;
        sqlite3_bind_int64(stmt, 1, entry->update_time);
        sqlite3_bind_int(stmt, 2, entry->starred);
        sqlite3_bind_int64(stmt, 3, entry->id);
    }
    else
    {
        int64_t t = get_time_ns(CLOCK_REALTIME) / 1000000;

        stmt = db->stmt.serialize_entry;
        sqlite3_bind_int64(stmt, 1, t);
        sqlite3_bind_int64(stmt, 2, t);
        sqlite3_bind_int(stmt, 3, false);
    }

    int64_t id = -1;
    int     ret = sqlite3_step(stmt);

    if ((entry == NULL && ret != SQLITE_ROW) ||
        (entry != NULL && ret != SQLITE_DONE))
    {
        wlip_log(
            "Error serializing entry into database: %s",
            sqlite3_errmsg(db->handle)
        );
        goto exit;
    }

    if (entry == NULL)
        id = sqlite3_column_int64(stmt, 0);
    else
        id = entry->id;

exit:
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    return id;
}

static int
database_serialize_data(
    struct database *db, const uint8_t *data_id, uint8_t *data, size_t len
)
{
    sqlite3_stmt *stmt = db->stmt.serialize_data;

    sqlite3_bind_blob(stmt, 1, data_id, SHA256_BLOCK_SIZE, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, data, len, SQLITE_STATIC);

    int ret = sqlite3_step(stmt);

    sqlite3_reset(stmt);
    if (ret != SQLITE_DONE)
    {
        wlip_log(
            "Error serializing data into database: %s",
            sqlite3_errmsg(db->handle)
        );
        return FAIL;
    }

    return OK;
}

/*
 * Serialize "data" into the database for "mime_type" associated with entry
 * "id". Returns OK on success and FAIL on failure.
 */
int
database_serialize_mime_type(
    struct database *db,
    int64_t          id,
    const char      *mime_type,
    const uint8_t   *data_id,
    uint8_t         *data,
    size_t           len
)
{
    // If "data" is NULL, then "Data_id" in "Mime_types" table will just be
    // NULL.
    if (data != NULL && database_serialize_data(db, data_id, data, len) == FAIL)
        return FAIL;

    sqlite3_stmt *stmt = db->stmt.serialize_mime_type;

    sqlite3_bind_int64(stmt, 1, id);
    sqlite3_bind_text(stmt, 2, mime_type, -1, SQLITE_STATIC);
    if (data == NULL)
        sqlite3_bind_null(stmt, 3);
    else
        sqlite3_bind_blob(stmt, 3, data_id, SHA256_BLOCK_SIZE, SQLITE_STATIC);

    int ret = sqlite3_step(stmt);

    sqlite3_reset(stmt);
    if (ret != SQLITE_DONE)
    {
        wlip_log(
            "Error serializing mime type into database: %s",
            sqlite3_errmsg(db->handle)
        );
        return FAIL;
    }

    return OK;
}

/*
 * Make the source offer the mime types associated with the entry "id".
 */
void
database_offer_mime_types(
    struct database *db, int64_t id, struct ext_data_control_source_v1 *source
)
{
    sqlite3_stmt *stmt = db->stmt.deserialize_mime_types;
    int           ret;

    sqlite3_bind_int64(stmt, 1, id);

    while ((ret = sqlite3_step(stmt)) == SQLITE_ROW)
    {
        const char *mime_type = (char *)sqlite3_column_text(stmt, 0);

        ext_data_control_source_v1_offer(source, mime_type);
    }

    sqlite3_reset(stmt);

    if (ret != SQLITE_DONE)
        wlip_log(
            "Error deserializing mime types from database: %s",
            sqlite3_errmsg(db->handle)
        );
}

/*
 * Return the data row for the given mime type for entry "id" as an sqlite
 * statement. Returns NULL on failure (remember to call sqlite3_reset()).
 */
sqlite3_stmt *
database_deserialize_mime_type_data(
    struct database *db, int64_t id, const char *mime_type
)
{
    sqlite3_stmt *stmt = db->stmt.deserialize_mime_type_data;

    sqlite3_bind_int64(stmt, 1, id);
    sqlite3_bind_text(stmt, 2, mime_type, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW)
        return stmt;

    wlip_log(
        "Error deserializing mime type data from database: %s",
        sqlite3_errmsg(db->handle)
    );
    sqlite3_reset(stmt);
    return NULL;
}

/*
 * Save the given selection SHA256 hash as "Selection_hash" in the "Settings"
 * table. Returns OK on success and FAIL on failure.
 */
int
database_save_selection_hash(struct database *db, const uint8_t *hash)
{
    sqlite3_stmt *stmt = db->stmt.save_setting;

    sqlite3_bind_text(stmt, 1, "Selection_hash", -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, hash, SHA256_BLOCK_SIZE, SQLITE_STATIC);

    int ret = sqlite3_step(stmt);

    sqlite3_reset(stmt);
    if (ret != SQLITE_DONE)
    {
        wlip_log(
            "Error saving selection hash into database: %s",
            sqlite3_errmsg(db->handle)
        );
        return FAIL;
    }

    return OK;
}

/*
 * Get the saved selection hash from the database, if any. Returns OK on success
 * and FAIL on failure.
 */
int
database_get_selection_hash(struct database *db, uint8_t *hash)
{
    sqlite3_stmt *stmt = db->stmt.get_setting;

    sqlite3_bind_text(stmt, 1, "Selection_hash", -1, SQLITE_STATIC);

    int ret = sqlite3_step(stmt);

    if (ret != SQLITE_ROW)
        goto fail;

    const uint8_t *data = sqlite3_column_blob(stmt, 0);
    int            size = sqlite3_column_bytes(stmt, 0);

    if (size != SHA256_BLOCK_SIZE)
    {
        wlip_log("Saved selection hash is not 32 bytes?");
        goto fail;
    }

    if (data == NULL)
        goto fail;

    memcpy(hash, data, SHA256_BLOCK_SIZE);
    sqlite3_reset(stmt);

    return OK;
fail:
    sqlite3_reset(stmt);
    return FAIL;
}

/*
 * Return info of entries starting at "start" up to "n" entries, calling
 * "callback" for each entry. Returns OK on success and FAIL on failure.
 */
int
database_deserialize_entries(
    struct database *db,
    int64_t          start,
    int64_t          n,
    entry_func       callback,
    void            *udata
)
{
    sqlite3_stmt *stmt = db->stmt.deserialize_entries;
    int           ret;

    sqlite3_bind_int64(stmt, 1, n);
    sqlite3_bind_int64(stmt, 2, start);

    while ((ret = sqlite3_step(stmt)) == SQLITE_ROW)
    {
        struct database_entry entry = {
            .id = sqlite3_column_int64(stmt, 0),
            .creation_time = sqlite3_column_int64(stmt, 1),
            .update_time = sqlite3_column_int64(stmt, 2),
            .starred = sqlite3_column_int(stmt, 3)
        };

        callback(&entry, udata);
    }

    sqlite3_reset(stmt);

    if (ret != SQLITE_DONE)
    {
        wlip_log(
            "Error deserializing entries from database: %s",
            sqlite3_errmsg(db->handle)
        );
        return FAIL;
    }

    return OK;
}

void
deserialize_callback(struct database_entry *entry, void *udata)
{
    struct database_entry *store = udata;

    *store = *entry;
}

/*
 * Store info of entry at index "idx" in database in "entry". Returns OK on
 * success and FAIL on failure.
 */
int
database_deserialize_entry(
    struct database *db, int64_t idx, struct database_entry *entry
)
{
    return database_deserialize_entries(
        db, idx, 1, deserialize_callback, entry
    );
}
