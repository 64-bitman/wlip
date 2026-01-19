#include "alloc.h"
#include "clipboard.h"
#include "database.h"
#include "event.h"
#include "lua/script.h"
#include "util.h"
#include "version.h"
#include "wayland.h"
#include <assert.h>
#include <errno.h> // IWYU pragma: keep
#include <getopt.h>
#include <jansson.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static struct option OPTIONS[] = {
    {"version", no_argument, 0, 'v'},
    {"help", no_argument, 0, 'h'},
    {"debug", no_argument, 0, 'd'},
};

static int config_setup(void);
static int parse_config(const char *cfg, FILE *cfg_fp);

static void
help(void)
{
    printf("Usage: wlip [OPTION?] - clipboard manager\n");
    printf("\n");
    printf("Options:\n");
    printf("-v, --version   Show version\n");
    printf("-h, --help      Show this message\n");
    printf("-d, --debug     Enable debug logging\n");
    printf("\n");
}

int
main(int argc, char *argv[])
{
    int c;
    int opt_index;

    while ((c = getopt_long(argc, argv, "vhd", OPTIONS, &opt_index)) != -1)
    {
        switch (c)
        {
        case 'v':
            printf(PROJECT_VERSION "\n");
            return EXIT_SUCCESS;
        case 'h':
            help();
            return EXIT_SUCCESS;
        case 'd':
            wlip_set_debug(true);
            break;
        case '?':
            break;
        default:
            printf("getopt returned character code 0x%x ??\n", c);
        }
    }
    json_set_alloc_funcs(wlip_malloc, wlip_free);

    if (config_setup() == FAIL)
        return EXIT_FAILURE;

    event_run();

    lua_uninit();
    wayland_uninit();
    database_uninit();

    return EXIT_SUCCESS;
}

/*
 * Parse configuration files and setup clipboard manager. Returns OK on success
 * and FAIL on failure.
 */
static int
config_setup(void)
{
    // Configuration directories to use, in ascending priority.
    static char config_dirs[2][PATH_MAX];

    const char *xdgconfighome = getenv("XDG_CONFIG_HOME");
    const char *home = getenv("HOME");

    if (xdgconfighome != NULL)
        wlip_snprintf(config_dirs[0], PATH_MAX, "%s/wlip", xdgconfighome);
    else if (home != NULL)
        wlip_snprintf(config_dirs[0], PATH_MAX, "%s/.config/wlip", home);
    else
        wlip_snprintf(
            config_dirs[0], PATH_MAX, "%s/.config/wlip",
            getpwuid(getuid())->pw_dir
        );
    wlip_snprintf(config_dirs[1], PATH_MAX, "/etc/wlip");

    // Get the configuration directory to read
    struct stat sb;
    const char *config_dir = NULL;

    for (int i = 0; i < ARRAY_SIZE(config_dirs); i++)
        if (stat(config_dirs[i], &sb) == 0 && S_ISDIR(sb.st_mode))
        {
            config_dir = config_dirs[i];
            break;
        }

    char cfg[PATH_MAX];

    if (config_dir == NULL)
    {
        wlip_error("Cannot find config directory, exiting...");
        return FAIL;
    }
    wlip_snprintf(cfg, PATH_MAX, "%s/config.json", config_dir);

    if (stat(cfg, &sb) == -1 || !S_ISREG(sb.st_mode))
    {
        wlip_error(
            "Config file '%s' does not exist or is not a text file", cfg
        );
        return FAIL;
    }

    // Read file into memory
    FILE *fp = fopen(cfg, "r");

    if (fp == NULL)
    {
        wlip_error("Failed opening '%s': %s", cfg, strerror(errno));
        return FAIL;
    }

    int ret = parse_config(cfg, fp);

    fclose(fp);
    return ret;
}

/*
 * Parse "clipboards" JSON object. Returns OK on success and FAIL on failure.
 */
static int
parse_clipboards(json_t *parent)
{
    assert(parent != NULL);

    json_t *cfg_clipboards = json_object_get(parent, "clipboards");

    if (cfg_clipboards == NULL)
        // Doesn't exist
        return OK;
    else if (!json_is_object(cfg_clipboards))
    {
        wlip_error("'clipboards' is not an object");
        return FAIL;
    }

    void *iter = json_object_iter(cfg_clipboards);

    if (iter == NULL)
        return OK;

    do
    {
        const char *name = json_object_iter_key(iter);
        json_t *cfg_clipboard = json_object_iter_value(iter);

        if (!json_is_object(cfg_clipboard))
        {
            wlip_error("Member '%s' in 'clipboards' is not an object", name);
            return FAIL;
        }

        int64_t max_entries = 100;
        bool database = true;

        json_t *cfg_max_entries = json_object_get(cfg_clipboard, "max-entries");
        json_t *cfg_database = json_object_get(cfg_clipboard, "database");

        if (json_is_integer(cfg_max_entries))
        {
            max_entries = json_integer_value(cfg_max_entries);
            if (max_entries <= 0)
            {
                wlip_error("'max_entries' must be greater than zero");
                return FAIL;
            }
        }
        if (json_is_boolean(cfg_database))
            database = json_boolean_value(cfg_database);

        clipboard_T *cb = clipboard_new(name);

        if (cb == NULL)
            return FAIL;

        cb->no_database = !database;
        cb->max_entries = max_entries;
    } while ((iter = json_object_iter_next(cfg_clipboards, iter)) != NULL);

    return OK;
}

/*
 * Parse "seats" JSON object. Returns OK on success and FAIL on failure.
 */
static int
parse_seats(json_t *parent)
{
    assert(parent != NULL);

    json_t *cfg_seats = json_object_get(parent, "seats");

    if (cfg_seats == NULL)
        // Doesn't exist
        return OK;
    else if (!json_is_object(cfg_seats))
    {
        wlip_error("'seats' is not an object");
        return FAIL;
    }

    void *iter = json_object_iter(cfg_seats);

    if (iter == NULL)
        return OK;

    do
    {
        const char *name = json_object_iter_key(iter);

        // Ignore if seat doesn't exist
        wlseat_T *seat = wayland_get_seat(name);

        if (seat == NULL)
            continue;

        json_t *cfg_seat = json_object_iter_value(iter);

        if (!json_is_object(cfg_seat))
        {
            wlip_error("Member '%s' in 'seats' is not an object", name);
            return FAIL;
        }

        // Each corresponds to a clipboard name that selection should attach to
        const char *regular = NULL, *primary = NULL;

        json_t *cfg_regular = json_object_get(cfg_seat, "regular");
        json_t *cfg_primary = json_object_get(cfg_seat, "primary");

        if (json_is_string(cfg_regular))
            regular = json_string_value(cfg_regular);
        if (json_is_string(cfg_primary))
            primary = json_string_value(cfg_primary);

        const char *cbs[2] = {regular, primary};
        wlselection_type_T types[2] = {
            WLSELECTION_TYPE_REGULAR, WLSELECTION_TYPE_PRIMARY
        };

        for (int i = 0; i < ARRAY_SIZE(cbs); i++)
        {
            const char *cb_name = cbs[i];

            if (cb_name == NULL)
                continue;

            clipboard_T *cb = find_clipboard(cb_name);

            if (cb == NULL)
            {
                wlip_error("Clipboard '%s' does not exist", cb_name);
                return FAIL;
            }

            wayland_attach_selection(seat, types[i], cb);
        }
    } while ((iter = json_object_iter_next(cfg_seats, iter)) != NULL);

    return OK;
}

/*
 * Parse "scripts" JSON object. Returns OK on success and FAIL on failure.
 */
static int
parse_scripts(json_t *parent)
{
    assert(parent != NULL);

    if (lua_init() == FAIL)
        return FAIL;

    json_t *cfg_scripts = json_object_get(parent, "scripts");

    if (cfg_scripts == NULL)
        // Doesn't exist
        return OK;
    else if (!json_is_array(cfg_scripts))
    {
        wlip_error("'scripts' is not an array");
        return FAIL;
    }

    size_t idx;
    json_t *script_name;
    json_array_foreach(cfg_scripts, idx, script_name)
    {
        if (!json_is_string(script_name))
        {
            wlip_error("'scripts' contains non string value");
            return FAIL;
        }
    }

    return OK;
}

/*
 * Parse configuration file. Returns OK on success and FAIL on failure.
 */
static int
parse_config(const char *cfg, FILE *cfg_fp)
{
    assert(cfg != NULL);
    assert(cfg_fp != NULL);

    int ret = OK;

    json_error_t error;
    json_t *root = json_loadf(cfg_fp, 0, &error);

    if (root == NULL)
    {
        wlip_error(
            "Failed parsing '%s', error on line %d: %s", cfg, error.line,
            error.text
        );
        ret = FAIL;
        goto exit;
    }

    json_t *cfg_display = json_object_get(root, "display");
    const char *display = NULL;

    if (json_is_string(cfg_display))
        display = json_string_value(cfg_display);

    // Initialize Wayland connection with configured display (if specified).
    if (wayland_init(display) == FAIL)
    {
        ret = FAIL;
        goto exit;
    }

    if (parse_clipboards(root) == FAIL || parse_seats(root) == FAIL ||
        parse_scripts(root))
    {
        ret = FAIL;
        goto exit;
    }

    // Sync all the clipboards (make sure to do this last)
    hashtableiter_T citer = HASHTABLEITER_INIT(get_clipboards());
    clipboard_T *cb;

    while ((cb = hashtableiter_next(&citer, offsetof(clipboard_T, name))))
    {
        // Don't load entry from database if a Lua script set the entry.
        if (cb->entry == NULL)
            clipboard_load(cb, 0);
        clipboard_sync(cb, NULL);
    }

exit:
    json_decref(root);
    return ret;
}

// vim: ts=4 sw=4 sts=4 et
