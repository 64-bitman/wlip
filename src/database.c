#include "database.h"
#include "alloc.h"
#include "clipboard.h"
#include "util.h"
#include <assert.h>
#include <limits.h>
#include <pwd.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DO_TRANSACTION(type, ret)                                              \
    do                                                                         \
    {                                                                          \
        sqlite3_stmt *stmt = STATEMENTS.type.stmt;                             \
        assert(!sqlite3_stmt_busy(stmt));                                      \
        sqlite3_step(stmt);                                                    \
        if (sqlite3_reset(stmt) != SQLITE_OK)                                  \
        {                                                                      \
            wlip_warn(                                                         \
                "Failed starting database transaction: %s",                    \
                sqlite3_errmsg(DB.handle)                                      \
            );                                                                 \
            return ret;                                                        \
        }                                                                      \
    } while (false)

#define DATABASE_VER 1

// clang-format off
static const char *DB_SCHEMA =
    "PRAGMA foreign_keys = ON;"
    "PRAGMA journal_mode = WAL;"
    "PRAGMA synchronous = NORMAL;"
    "PRAGMA user_version = " STRINGIFY(DATABASE_VER) ";"
    ""
    "CREATE TABLE IF NOT EXISTS Entries ("
    "   Id BLOB(32) UNIQUE,"
    "   Creation_time INTEGER NOT NULL,"
    "   Starred BOOLEAN NOT NULL,"
    "   Clipboard TEXT NOT NULL,"
    "   PRIMARY KEY (Id, Creation_time)"
    ");"
    ""
    "CREATE TABLE IF NOT EXISTS Mime_types ("
    "   Id BLOB(32),"
    "   Mime_type TEXT,"
    "   Data_id BLOB(32),"
    "   PRIMARY KEY (Id, Mime_type),"
    "   FOREIGN KEY (Id) REFERENCES Entries(Id) ON DELETE CASCADE,"
    "   FOREIGN KEY (Data_id) REFERENCES Data(Data_id) ON DELETE RESTRICT"
    ") WITHOUT ROWID;"
    ""
    "CREATE TABLE IF NOT EXISTS Data ("
    "   Data_id BLOB(32) PRIMARY KEY,"
    "   Encrypted BOOLEAN NOT NULL"
    ") WITHOUT ROWID;"
    ""
    "CREATE TABLE IF NOT EXISTS Attributes ("
    "   Id BLOB(32),"
    "   Name TEXT,"
    "   Value NOT NULL,"
    "   PRIMARY KEY (Id, Name),"
    "   FOREIGN KEY (Id) REFERENCES Entries(Id) ON DELETE CASCADE"
    ") WITHOUT ROWID;"
    ""
    "CREATE TEMP TRIGGER IF NOT EXISTS on_data_row_del "
    "AFTER DELETE ON main.Data BEGIN "
    "   SELECT remove_data_file(OLD.Data_id); "
    "END;"
    ""
    "CREATE TEMP TRIGGER IF NOT EXISTS del_data_row "
    "AFTER DELETE ON main.Mime_types BEGIN "
    "   DELETE FROM Data WHERE Data_id = OLD.Data_id "
    "       AND NOT EXISTS (SELECT 1 FROM Mime_types WHERE"
    "                       Data_id = OLD.Data_id); "
    "END;"
    ""
    "CREATE TEMP TRIGGER IF NOT EXISTS del_data_row_on_update "
    "AFTER UPDATE OF Data_id ON main.Mime_types BEGIN "
    "   DELETE FROM Data WHERE Data_id = OLD.Data_id "
    "       AND NOT EXISTS (SELECT 1 FROM Mime_types WHERE"
    "                       Data_id = OLD.Data_id); "
    "END;"
    ""
    "CREATE TEMP TRIGGER IF NOT EXISTS trim_entries "
    "AFTER INSERT ON Entries BEGIN "
    "   DELETE FROM Entries WHERE Clipboard = NEW.Clipboard "
    "       AND Starred = 0 "
    "       AND Creation_time < ("
    "           SELECT MIN(Creation_time) FROM ("
    "               SELECT Creation_time FROM Entries "
    "               ORDER BY Creation_time DESC "
    "               LIMIT clipboard_max_entries(NEW.Clipboard) "
    "           )"
    "       );"
    "END;"
    "";
// clang-format on

typedef struct
{
    sqlite3_stmt *stmt;
    const char *statement;
} preparedstmt_T;

// clang-format off
static struct
{
    preparedstmt_T begin_transaction;
    preparedstmt_T begin_transaction_immediate;
    preparedstmt_T commit_transaction;
    preparedstmt_T rollback_transaction;
    preparedstmt_T delete_attribute;
    preparedstmt_T delete_mime_type;
    preparedstmt_T delete_entry_by_id;
    preparedstmt_T delete_entry_by_index;
    preparedstmt_T serialize_data;
    preparedstmt_T serialize_attribute;
    preparedstmt_T serialize_mime_type;
    preparedstmt_T serialize_entry;
    preparedstmt_T deserialize_mime_types;
    preparedstmt_T deserialize_attributes;
    preparedstmt_T deserialize_entry_with_id;
    preparedstmt_T deserialize_entries;
    preparedstmt_T end; // Array terminator
} STATEMENTS = {
    .begin_transaction = {
        .statement = "BEGIN TRANSACTION;"
    },
    .begin_transaction_immediate = {
        .statement = "BEGIN IMMEDIATE TRANSACTION;",
    },
    .commit_transaction = {
        .statement = "COMMIT;"
    },
    .rollback_transaction = {
        .statement = "ROLLBACK TRANSACTION;"
    },
    .delete_attribute = {
        .statement = "DELETE FROM Attributes WHERE Id = ? AND Name = ?;",
    },
    .delete_mime_type = {
        .statement = "DELETE FROM Mime_types WHERE Id = ? AND Mime_type = ?;",
    },
    .delete_entry_by_id = {
        .statement = "DELETE FROM Entries WHERE Id = ?;",
    },
    .delete_entry_by_index = {
        .statement =
            "WITH target AS ("
            "   SELECT Id FROM Entries WHERE Clipboard = ? "
            "   ORDER BY Creation_time DESC LIMIT 1 OFFSET ?"
            ") DELETE FROM Entries WHERE Id IN (SELECT Id FROM target);",
    },
    .serialize_data = {
        .statement =
            "INSERT OR IGNORE INTO Data (Data_id, Encrypted) "
            "   VALUES (?, ?);",
    },
    .serialize_attribute = {
        .statement =
            "INSERT INTO Attributes (Id, Name, Value) "
            "   VALUES (?, ?, ?) ON CONFLICT(Id, Name) "
            "       DO UPDATE SET Value = ?;",
    },
    .serialize_mime_type = {
        .statement =
            "INSERT INTO Mime_types (Id, Mime_type, Data_id) "
            "   VALUES (?, ?, ?) ON CONFLICT(Id, Mime_type) "
            "       DO UPDATE SET Data_id = ?;",
    },
    .serialize_entry = {
        .statement =
            "INSERT INTO Entries (Id, Creation_time, Starred, Clipboard) "
            "   VALUES (?, ?, ?, ?) ON CONFLICT(Id) "
            "       DO UPDATE SET Clipboard = ?, Starred = ?;"
    },
    .deserialize_mime_types = {
        .statement = "SELECT Mime_type, Data_id FROM Mime_types WHERE Id = ?;"
    },
    .deserialize_attributes = {
        .statement = "SELECT Name, Value FROM Attributes WHERE Id = ?;"
    },
    .deserialize_entry_with_id = {
        .statement =
            "SELECT Id, Creation_time, Starred, Clipboard "
            "   FROM Entries WHERE Id = ?;"
    },
    .deserialize_entries = {
        .statement =
            "SELECT Id, Creation_time, Starred FROM Entries"
            "    WHERE Clipboard = ? ORDER BY Creation_time DESC LIMIT ? OFFSET ?;"
    },
    .end = {0}
};
// clang-format on

// Singleton state for database connection. It is initialized lazily, i.e. on
// the first database function call.
static struct
{
    char *local_dir; // Directory where everything is stored
    char *data_dir;  // Directory inside local_dir where files are
                     // stored.

    sqlite3 *handle; // NULL if not initialized
} DB;

#ifdef TESTING
// Database is always in memory when testing
static bool DB_IN_MEMORY = true;

typedef struct
{
    clipdata_T *data;
    char id[65]; // Data id in hexadecimal form
} memoryfile_T;

hashtable_T MEMORY_STORE;

static void
memoryfile_free(memoryfile_T *f)
{
    assert(f != NULL);

    clipdata_unref(f->data);
    wlip_free(f);
}

/*
 * Same as sqlfunc_delete_data_file() but for when database is in memory.
 */
static void
sqlfunc_delete_data_file_inmemory(
    sqlite3_context *ctx, int argc, sqlite3_value **argv
)
{
    if (argc != 1)
    {
        sqlite3_result_null(ctx);
        return;
    }

    const char *data_id = (const char *)sqlite3_value_text(argv[0]);
    hash_T hash = hash_get(data_id);
    hashbucket_T *b = hashtable_lookup(&MEMORY_STORE, data_id, hash);

    if (!HB_ISEMPTY(b))
    {
        memoryfile_T *f = HB_GET(b, memoryfile_T, id);
        memoryfile_free(f);
        hashtable_remove_bucket(&MEMORY_STORE, b);
    }

    sqlite3_result_null(ctx);
}

#endif

/*
 * Removes the corresponding file for the given data id in the data
 * directory.
 */
static void
sqlfunc_delete_data_file(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    if (argc != 1)
    {
        sqlite3_result_null(ctx);
        return;
    }

    const char *data_id = (const char *)sqlite3_value_text(argv[0]);
    char path[PATH_MAX];

    wlip_snprintf(path, PATH_MAX, "%s/%s", DB.data_dir, data_id);

    unlink(path);
    sqlite3_result_null(ctx);
}

/*
 * Get maxmimum number of entries associated with a clipboard
 */
static void
sqlfunc_clipboard_max_entries(
    sqlite3_context *ctx, int argc UNUSED, sqlite3_value **argv
)
{
    assert(argc == 1);
    const char *name = (const char *)sqlite3_value_text(argv[0]);
    clipboard_T *cb = find_clipboard(name);

    if (cb == NULL)
        sqlite3_result_int64(ctx, 0);
    else
        sqlite3_result_int64(ctx, cb->max_entries);
}

/*
 * Migrate the database from "old" version. Returns OK on success and FAIL on
 * failure. Currently useless.
 */
static int
database_migrate(int32_t old UNUSED)
{
    return OK;
}

/*
 * Initialize the database connection. Returns OK on success and FAIL on
 * failure.
 */
static int
database_init()
{
    if (DB.handle != NULL)
        return OK;

    const char *wlip_database = getenv("WLIP_DATABASE");
    char local_dir[PATH_MAX];
    char data_dir[PATH_MAX];
    char location[PATH_MAX];

    if (wlip_database != NULL)
        wlip_snprintf(DB.local_dir, PATH_MAX, "%s", wlip_database);
    else
    {
        // Use the default location
        const char *datahome = getenv("XDG_DATA_HOME");

        if (datahome == NULL)
        {
            // First check $HOME, then use getpwuid()
            const char *home = getenv("HOMEM");

            if (home != NULL)
                wlip_snprintf(
                    local_dir, PATH_MAX, "%s/.local/share/wlip", home
                );
            else
            {
                struct passwd *pw = getpwuid(getuid());
                wlip_snprintf(
                    local_dir, PATH_MAX, "%s/.local/share/wlip", pw->pw_dir
                );
            }
        }
        else
            wlip_snprintf(local_dir, PATH_MAX, "%s/wlip", datahome);
    }
    wlip_snprintf(data_dir, PATH_MAX, "%s/data", local_dir);
    wlip_snprintf(location, PATH_MAX, "%s/history.sqlite3", local_dir);

    int flags =
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX;
#ifdef TESTING
    if (DB_IN_MEMORY)
        flags |= SQLITE_OPEN_MEMORY;
    else
#endif
        if (wlip_mkdir(local_dir) == -1 || wlip_mkdir(data_dir) == -1)
    {
        wlip_error(
            "Failed creating database directory '%s' and '%s': %s", local_dir,
            data_dir, strerror(errno)
        );
        return FAIL;
    }

    int ret = sqlite3_open_v2(location, &DB.handle, flags, NULL);

    if (ret != SQLITE_OK)
    {
        wlip_error(
            "Failed opening database at '%s': %s", location,
            sqlite3_errmsg(DB.handle)
        );
        return FAIL;
    }

    // First query database user version to see if it is outdated.
    sqlite3_stmt *uv_stmt;

    ret = sqlite3_prepare_v2(
        DB.handle, "PRAGMA user_version;", -1, &uv_stmt, NULL
    );
    if (ret != SQLITE_OK)
    {
        wlip_error(
            "Failed preparing statement 'PRAGMA user_version': %s",
            sqlite3_errmsg(DB.handle)
        );
        database_uninit();
        return FAIL;
    }

    ret = sqlite3_step(uv_stmt);
    if (ret == SQLITE_ROW)
    {
        int32_t uver = sqlite3_column_int(uv_stmt, 0);

        // If uver is newer than DATABASE_VER, then I guess guarante that all
        // versions are backwards compatible?
        if (DATABASE_VER > uver)
            if (database_migrate(uver) == FAIL)
            {
                sqlite3_finalize(uv_stmt);
                database_uninit();
                return FAIL;
            }
    }
    sqlite3_finalize(uv_stmt);

    void (*delete_func)(sqlite3_context *, int, sqlite3_value **);

#ifdef TESTING
    if (DB_IN_MEMORY)
        delete_func = sqlfunc_delete_data_file_inmemory;
    else
#endif
        delete_func = sqlfunc_delete_data_file;

    // Create user functions
    if (sqlite3_create_function(
            DB.handle, "remove_data_file", 1, SQLITE_UTF8, NULL, delete_func,
            NULL, NULL
        ) != SQLITE_OK)
    {
        wlip_error(
            "Failed creating user function: %s", sqlite3_errmsg(DB.handle)
        );
        database_uninit();
        return FAIL;
    }
    if (sqlite3_create_function(
            DB.handle, "clipboard_max_entries", 1, SQLITE_UTF8, NULL,
            sqlfunc_clipboard_max_entries, NULL, NULL
        ) != SQLITE_OK)
    {
        wlip_error(
            "Failed creating user function: %s", sqlite3_errmsg(DB.handle)
        );
        database_uninit();
        return FAIL;
    }

    // Execute database schema
    char *err_msg;

    if (sqlite3_exec(DB.handle, DB_SCHEMA, NULL, NULL, &err_msg) != SQLITE_OK)
    {
        wlip_error("Failed creaing database schema: %s", err_msg);
        sqlite3_free(err_msg);
        database_uninit();
        return FAIL;
    }

    // Prepare all the statements
    preparedstmt_T *statements = (preparedstmt_T *)&STATEMENTS;

    for (int i = 0; statements[i].statement != NULL; i++)
    {
        assert(statements[i].stmt == NULL);
        assert(statements[i].statement != NULL);

        int ret = sqlite3_prepare_v2(
            DB.handle, statements[i].statement, -1, &statements[i].stmt, NULL
        );

        if (ret != SQLITE_OK)
        {
            wlip_error(
                "Failed preparing statement '%s': %s", statements[i].statement,
                sqlite3_errmsg(DB.handle)
            );
            database_uninit();
            return FAIL;
        }
    }

    DB.local_dir = wlip_strdup(local_dir);
    DB.data_dir = wlip_strdup(data_dir);
#ifdef TESTING
    hashtable_init(&MEMORY_STORE);
#endif

    return OK;
}

/*
 * Uninitialize the database connection if there is one, else do nothing. Should
 * only be called when all transactions are done.
 */
void
database_uninit(void)
{
    if (DB.handle == NULL)
        return;

    wlip_debug("Database statistics:");
    wlip_debug(
        "Current memory usage: %" PRId64, (int64_t)sqlite3_memory_used()
    );

    preparedstmt_T *statements = (preparedstmt_T *)&STATEMENTS;

    // Free each prepared statement
    for (int i = 0; statements[i].statement != NULL; i++)
        if (statements[i].stmt != NULL)
        {
#ifndef NDEBUG
            if (sqlite3_stmt_busy(statements[i].stmt))
            {
                wlip_warn("Statement '%s' not reset", statements[i].statement);
                abort();
            }
#endif
            sqlite3_finalize(statements[i].stmt);
            statements[i].stmt = NULL;
        }

#ifdef TESTING
    hashtable_clear_func(
        &MEMORY_STORE, (hb_freefunc_T)memoryfile_free,
        offsetof(memoryfile_T, id)
    );
#endif

    wlip_free(DB.local_dir);
    wlip_free(DB.data_dir);
    sqlite3_close(DB.handle);
    memset(&DB, 0, sizeof(DB));
}

/*
 * Create the file to store the data in (or if in memory, then store it in the
 * table). Returns OK on success and FAIL on failure.
 */
static void
create_data_file(clipdata_T *data)
{
    assert(data != NULL);

    const char *id = sha256_digest2hex(data->id, NULL);

#ifdef TESTING
    if (DB_IN_MEMORY)
    {
        hash_T hash = hash_get(id);
        hashbucket_T *b = hashtable_lookup(&MEMORY_STORE, id, hash);

        if (HB_ISEMPTY(b))
        {
            memoryfile_T *f = wlip_malloc(sizeof(memoryfile_T));

            f->data = clipdata_ref(data);
            memcpy(f->id, id, 65);
        }
        return;
    }
#endif

    char path[PATH_MAX];
    wlip_snprintf(path, PATH_MAX, "%s/%s", DB.data_dir, id);

    // Check if file already exists
    struct stat sb;
    if (stat(path, &sb) == 0)
        return;

    FILE *fp = fopen(path, "w");

    fwrite(data->content.data, 1, data->content.len, fp);

    if (ferror(fp) != 0)
        wlip_warn("Failed writing to file '%s'", path);

    fclose(fp);

    return;
}

/*
 * Serialize the data into the database. Returns OK on success and FAIL on
 * failure.
 */
static int
database_serialize_data(clipdata_T *data)
{
    assert(data != NULL);

    sqlite3_stmt *stmt = STATEMENTS.serialize_data.stmt;

    assert(!sqlite3_stmt_busy(stmt));

    sqlite3_bind_blob(stmt, 1, data->id, sizeof(data->id), SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, false);

    sqlite3_step(stmt);
    if (sqlite3_reset(stmt) != SQLITE_OK)
    {
        wlip_warn(
            "Failed serializing data into database: %s",
            sqlite3_errmsg(DB.handle)
        );
        return FAIL;
    }

    return OK;
}

/*
 * Serialize the mime types of the entry into the database. Returns OK on
 * success and FAIL on failure.
 */
static int
serialize_mime_types(clipentry_T *entry)
{
    assert(entry != NULL);

    sqlite3_stmt *stmt = STATEMENTS.serialize_mime_type.stmt;
    sqlite3_stmt *del_stmt = STATEMENTS.delete_mime_type.stmt;

    assert(!sqlite3_stmt_busy(stmt));
    assert(!sqlite3_stmt_busy(del_stmt));

    hashtableiter_T iter = HASHTABLEITER_INIT(&entry->mime_types);
    mimetype_T *mt;

    while ((mt = hashtableiter_next(&iter, offsetof(mimetype_T, name))))
    {
        if (mt->data == NULL)
        {
            // Mime type is removed
            sqlite3_bind_blob(
                del_stmt, 1, entry->id, sizeof(entry->id), SQLITE_STATIC
            );
            sqlite3_bind_text(del_stmt, 2, mt->name, -1, SQLITE_STATIC);

            sqlite3_step(del_stmt);
            if (sqlite3_reset(del_stmt) != OK)
            {
                wlip_warn(
                    "Failed removing mime type '%s' from database: %s",
                    mt->name, sqlite3_errmsg(DB.handle)
                );
                return FAIL;
            }
        }
        else if (mt->data->state != DATA_STATE_LOADED)
            wlip_warn(
                "Data '%s' is unloaded?", sha256_digest2hex(mt->data->id, NULL)
            );
        else
        {
            create_data_file(mt->data);
            if (database_serialize_data(mt->data) == FAIL)
                return FAIL;

            sqlite3_bind_blob(
                stmt, 1, entry->id, sizeof(entry->id), SQLITE_STATIC
            );
            sqlite3_bind_text(stmt, 2, mt->name, -1, SQLITE_STATIC);
            sqlite3_bind_blob(
                stmt, 3, mt->data->id, sizeof(mt->data->id), SQLITE_STATIC
            );

            sqlite3_step(stmt);
            if (sqlite3_reset(stmt) != SQLITE_OK)
            {
                wlip_warn(
                    "Failed serializing mime type '%s' into database: %s",
                    mt->name, sqlite3_errmsg(DB.handle)
                );
                return FAIL;
            }
        }
    }

    return OK;
}

/*
 * Serialize the attributes of the entry into the database. Returns OK on
 * success and FAIL on failure.
 */
static int
serialize_attributes(clipentry_T *entry)
{
    assert(entry != NULL);

    sqlite3_stmt *stmt = STATEMENTS.serialize_attribute.stmt;
    sqlite3_stmt *del_stmt = STATEMENTS.delete_attribute.stmt;

    assert(!sqlite3_stmt_busy(stmt));
    assert(!sqlite3_stmt_busy(del_stmt));

    hashtableiter_T iter = HASHTABLEITER_INIT(&entry->attributes);
    attribute_T *attr;

    while ((attr = hashtableiter_next(&iter, offsetof(attribute_T, name))))
    {
        switch (attr->type)
        {
        case ATTRIBUTE_TYPE_STRING:
            sqlite3_bind_text(stmt, 3, attr->val.str, -1, SQLITE_STATIC);
            break;
        case ATTRIBUTE_TYPE_INTEGER:
            sqlite3_bind_int64(stmt, 3, attr->val.integer);
            break;
        case ATTRIBUTE_TYPE_NUMBER:
            sqlite3_bind_double(stmt, 3, attr->val.number);
            break;
        case ATTRIBUTE_TYPE_REMOVED:
            sqlite3_bind_blob(
                del_stmt, 1, entry->id, sizeof(entry->id), SQLITE_STATIC
            );
            sqlite3_bind_text(del_stmt, 2, attr->name, -1, SQLITE_STATIC);

            sqlite3_step(del_stmt);
            if (sqlite3_reset(del_stmt) != OK)
            {
                wlip_warn(
                    "Failed removing attribute '%s' from database: %s",
                    attr->name, sqlite3_errmsg(DB.handle)
                );
                return FAIL;
            }

            break;
        }

        sqlite3_bind_blob(stmt, 1, entry->id, sizeof(entry->id), SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, attr->name, -1, SQLITE_STATIC);

        sqlite3_step(stmt);
        if (sqlite3_reset(stmt) != OK)
        {
            wlip_warn(
                "Failed serializing attribute '%s' into database: %s",
                attr->name, sqlite3_errmsg(DB.handle)
            );
            return FAIL;
        }
    }

    return OK;
}

/*
 * Serialize a clipentry_T into the database. If the entry already exists in the
 * database, then it is updated/modified. Note that it is not valid to change
 * the clipboard of a entry without creating a new id.  Returns OK on success
 * and FAIL on failure.
 */
int
database_serialize(clipentry_T *entry)
{
    assert(entry != NULL);

    wlip_debug("Serializing entry into database");

    if (database_init() == FAIL)
        return FAIL;

    DO_TRANSACTION(begin_transaction_immediate, FAIL);

    sqlite3_stmt *stmt = STATEMENTS.serialize_entry.stmt;

    assert(!sqlite3_stmt_busy(stmt));

    // Create row in "Entries" table
    sqlite3_bind_blob(stmt, 1, entry->id, sizeof(entry->id), SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, entry->creation_time);
    sqlite3_bind_int(stmt, 3, entry->starred);
    sqlite3_bind_text(stmt, 4, entry->clipboard->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, entry->clipboard->name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, entry->starred);

    sqlite3_step(stmt);
    if (sqlite3_reset(stmt) != SQLITE_OK)
    {
        wlip_warn(
            "Failed creating entry row in database: %s",
            sqlite3_errmsg(DB.handle)
        );
        goto fail;
    }

    if (serialize_mime_types(entry) == FAIL ||
        serialize_attributes(entry) == FAIL)
        goto fail;

    DO_TRANSACTION(commit_transaction, FAIL);
    return OK;
fail:
    DO_TRANSACTION(rollback_transaction, FAIL);
    return FAIL;
}

/*
 * Return the data for the given data id, which must be passed in digest and in
 * hexadecimal form. Returns NULL on failure.
 */
clipdata_T *
database_load_data(
    const char_u digest[SHA256_BLOCK_SIZE], const char data_id[65]
)
{
    assert(digest != NULL);
    assert(data_id != NULL);

    char path[PATH_MAX];
    wlip_snprintf(path, PATH_MAX, "%s/%s", DB.data_dir, data_id);

    struct stat sb;
    FILE *fp = NULL;
    long size;

    if (stat(path, &sb) == -1 || !S_ISREG(sb.st_mode) ||
        (fp = fopen(path, "r")) == NULL || fseek(fp, 0, SEEK_END) == -1 ||
        (size = ftell(fp)) == -1 || fseek(fp, 0, SEEK_SET) == -1)
    {
        wlip_warn("Error opening file '%s': %s", path, strerror(errno));
        if (fp != NULL)
            fclose(fp);
        return NULL;
    }

    // Check for overflow
    if (sizeof(size) != sizeof(uint32_t) && size > UINT32_MAX)
    {
        wlip_warn(
            "File '%s' is too large to be loaded (%" PRId64 " bytes)", path,
            size
        );
        return NULL;
    }

    clipdata_T *data = clipdata_new();

    array_grow(&data->content, size);
    fread(data->content.data, 1, size, fp);

    if (ferror(fp) != 0)
    {
        wlip_warn("Error reading file '%s': %s", path, strerror(errno));
        clipdata_unref(data);
        fclose(fp);
        return NULL;
    }

    data->content.len = size;
    data->state = DATA_STATE_LOADED;
    memcpy(data->id, digest, SHA256_BLOCK_SIZE);

    fclose(fp);

    return data;
}

/*
 * Deserialize the mime types into the given clipentry_T. Returns OK on success
 * and FAIL on failure.
 */
static int
deserialize_mime_types(clipentry_T *entry)
{
    assert(entry != NULL);

    sqlite3_stmt *stmt = STATEMENTS.deserialize_mime_types.stmt;

    assert(!sqlite3_stmt_busy(stmt));
    sqlite3_bind_blob(stmt, 1, entry->id, sizeof(entry->id), SQLITE_STATIC);

    while (true)
    {
        int ret = sqlite3_step(stmt);

        if (ret == SQLITE_ROW)
        {
            const char *mime_type = (const char *)sqlite3_column_text(stmt, 0);
            const char_u *data_id = sqlite3_column_blob(stmt, 1);

            if (sqlite3_column_bytes(stmt, 1) != SHA256_BLOCK_SIZE)
            {
                wlip_warn("Data id is not of length 32 bytes?");
                sqlite3_reset(stmt);
                return FAIL;
            }

            clipdata_T *data =
                database_load_data(data_id, sha256_digest2hex(data_id, NULL));

            if (data == NULL)
            {
                sqlite3_reset(stmt);
                return FAIL;
            }

            mimetype_T *mt = mimetype_new(mime_type, data);

            hash_T hash = hash_get(mime_type);
            hashbucket_T *b =
                hashtable_lookup(&entry->mime_types, mime_type, hash);

            // Should always be empty
            if (HB_ISEMPTY(b))
                hashtable_add(&entry->mime_types, b, mt->name, hash);
            else
                mimetype_free(mt);
        }
        else if (ret == SQLITE_DONE)
            break;
        else
        {
            wlip_warn(
                "Failed deserializing mime types: %s", sqlite3_errmsg(DB.handle)
            );
            sqlite3_reset(stmt);
            return FAIL;
        }
    }

    sqlite3_reset(stmt);
    return OK;
}

/*
 * Deserialize the attributes into the given clipentry_T. Returns OK on success
 * and FAIL on failure.
 */
static int
deserialize_attributes(clipentry_T *entry)
{
    assert(entry != NULL);

    sqlite3_stmt *stmt = STATEMENTS.deserialize_attributes.stmt;

    assert(!sqlite3_stmt_busy(stmt));
    sqlite3_bind_blob(stmt, 1, entry->id, sizeof(entry->id), SQLITE_STATIC);

    while (true)
    {
        int ret = sqlite3_step(stmt);

        if (ret == SQLITE_ROW)
        {
            const char *name = (const char *)sqlite3_column_text(stmt, 0);
            attribute_T *attr = attribute_new(name);
            int type = sqlite3_column_type(stmt, 1);

            switch (type)
            {
            case SQLITE_INTEGER:
                attr->type = ATTRIBUTE_TYPE_INTEGER;
                attr->val.integer = sqlite3_column_int64(stmt, 1);
                break;
            case SQLITE_FLOAT:
                attr->type = ATTRIBUTE_TYPE_NUMBER;
                attr->val.number = sqlite3_column_double(stmt, 1);
                break;
            case SQLITE_TEXT:
                attr->type = ATTRIBUTE_TYPE_STRING;
                attr->val.str =
                    wlip_strdup((const char *)sqlite3_column_text(stmt, 1));
                break;
            default:
                wlip_warn("Unknown attribute type %d, skipping", type);
                attribute_free(attr);
                continue;
            }

            hash_T hash = hash_get(name);
            hashbucket_T *b = hashtable_lookup(&entry->attributes, name, hash);

            // Should always be empty
            if (HB_ISEMPTY(b))
                hashtable_add(&entry->attributes, b, attr->name, hash);
            else
                attribute_free(attr);
        }
        else if (ret == SQLITE_DONE)
            break;
        else
        {
            wlip_warn(
                "Failed deserializing attribute: %s", sqlite3_errmsg(DB.handle)
            );
            sqlite3_reset(stmt);
            return FAIL;
        }
    }

    sqlite3_reset(stmt);
    return OK;
}

/*
 * Deserialize an entry from the sqlite3 statement. If "cb" is NULL, then the
 * statement is assumed to be from an ID lookup. Returns NULL on failure.
 */
static clipentry_T *
deserialize_entry(clipboard_T *cb, sqlite3_stmt *stmt)
{
    assert(stmt != NULL);

    const char_u *id = sqlite3_column_blob(stmt, 0);

    if (sqlite3_column_bytes(stmt, 0) != SHA256_BLOCK_SIZE)
    {
        wlip_warn("Entry id is not of length 32 bytes?");
        return NULL;
    }
    if (cb == NULL)
    {
        const char *clipboard = (const char *)sqlite3_column_text(stmt, 3);

        cb = find_clipboard(clipboard);

        if (cb == NULL)
        {
            wlip_warn(
                "Error deserializing entry, clipboard '%s' does not exist",
                clipboard
            );
            return NULL;
        }
    }

    int64_t creation_time = sqlite3_column_int64(stmt, 1);
    bool starred = sqlite3_column_int(stmt, 2) ? true : false;

    clipentry_T *entry = clipentry_new(id, cb);

    if (deserialize_mime_types(entry) == FAIL ||
        deserialize_attributes(entry) == FAIL)
    {
        clipentry_unref(entry);
        return NULL;
    }

    entry->creation_time = creation_time;
    entry->starred = starred;

    return entry;
}

/*
 * Deserialize an entries from the database starting at "start" up to "num"
 * entries and "func" for each entry. Note that the entry is not freed after
 * "func" is called. Caller must ensure "start" and "num" are greater or equal
 * to zero. Returns OK on success and FAIL on failure.
 */
int
database_deserialize(
    int64_t start, int64_t num, clipboard_T *cb, deserialize_func_T func,
    void *udata
)
{
    assert(start >= 0);
    assert(num > 0);
    assert(cb != NULL);
    assert(func != NULL);

    wlip_debug("Deserializing %" PRId64 " entries from database", num);

    if (database_init() == FAIL)
        return FAIL;

    DO_TRANSACTION(begin_transaction, FAIL);

    sqlite3_stmt *stmt = STATEMENTS.deserialize_entries.stmt;

    assert(!sqlite3_stmt_busy(stmt));
    sqlite3_bind_text(stmt, 1, cb->name, cb->name_len, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, num);
    sqlite3_bind_int64(stmt, 3, start);

    while (true)
    {
        int ret = sqlite3_step(stmt);

        if (ret == SQLITE_ROW)
        {
            clipentry_T *entry = deserialize_entry(cb, stmt);

            if (entry == NULL)
                goto fail;
            func(entry, udata);
        }
        else if (ret == SQLITE_DONE)
            break;
        else
        {
            wlip_warn(
                "Failed deserializing entries: %s", sqlite3_errmsg(DB.handle)
            );
            goto fail;
        }
    }

    sqlite3_reset(stmt);
    DO_TRANSACTION(commit_transaction, FAIL);
    return OK;
fail:
    sqlite3_reset(stmt);
    DO_TRANSACTION(rollback_transaction, FAIL);
    return FAIL;
}

static void
deserialize_cb(clipentry_T *entry, void *udata)
{
    clipentry_T **store = udata;

    *store = entry;
}

/*
 * Helper function for database_deserialize() that uses 1 for "num". Returns
 * NULL on failure.
 */
clipentry_T *
database_deserialize_index(int64_t idx, clipboard_T *cb)
{
    assert(idx >= 0);
    assert(cb != NULL);

    clipentry_T *store = NULL;
    int ret = database_deserialize(idx, 1, cb, deserialize_cb, &store);

    if (ret == FAIL)
    {
        // Callback may have been called but error occured after
        if (store != NULL)
            clipentry_unref(store);
        return NULL;
    }
    return store;
}

/*
 * Deserialize the entry with the given ID from the database. Returns NULL on
 * failure. ID must be in digest form.
 */
clipentry_T *
database_deserialize_id(const char_u buf[SHA256_BLOCK_SIZE])
{
    assert(buf != NULL);

    wlip_debug("Deserializing entry from database");

    if (database_init() == FAIL)
        return NULL;

    DO_TRANSACTION(begin_transaction, NULL);

    sqlite3_stmt *stmt = STATEMENTS.deserialize_entry_with_id.stmt;

    assert(!sqlite3_stmt_busy(stmt));
    sqlite3_bind_blob(stmt, 1, buf, SHA256_BLOCK_SIZE, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_ROW)
    {
        wlip_warn(
            "Failed deserializing entry by id: %s", sqlite3_errmsg(DB.handle)
        );
        goto fail;
    }

    clipentry_T *entry = deserialize_entry(NULL, stmt);

    if (entry == NULL)
        goto fail;

    sqlite3_reset(stmt);
    DO_TRANSACTION(commit_transaction, NULL);

    return entry;
fail:
    sqlite3_reset(stmt);
    DO_TRANSACTION(rollback_transaction, NULL);
    return NULL;
}

// vim: ts=4 sw=4 sts=4 et
