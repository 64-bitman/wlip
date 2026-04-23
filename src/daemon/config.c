#include "config.h"
#include "tomlc17.h"
#include "util.h"
#include <errno.h> // IWYU pragma: keep
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int config_parse(struct config *config, const char *config_file);
static int save_pattern_array(toml_datum_t arr, struct wl_array *store);

/*
 * Parse and apply the configuration. If "config_dir" is NULL, then the default
 * path is used. Returns OK on success and FAIL on failure.
 */
int
config_init(struct config *config, const char *cfgdir)
{
    int   ret = OK;
    char *tofree = NULL;
    char *config_path = NULL;

    if (cfgdir == NULL)
    {
        tofree = get_base_dir(XDG_CONFIG_HOME, "wlip");
        cfgdir = tofree;
    }
    if (cfgdir == NULL)
        return FAIL;

    config_path = wlip_strdup_printf("%s/%s", cfgdir, "config.toml");
    if (config_path == NULL)
        goto fail;

    // Default values
    config->display_name = NULL;
    config->configured_seats = NULL;
    config->configured_seats_len = 0;
    wl_array_init(&config->allowed_mime_types);
    wl_array_init(&config->blocked_mime_types);

    config->max_entries = 100;
    config->persist = true;
    config->max_size = 10000000; // 10 MB

    if (access(config_path, F_OK) == 0 &&
        config_parse(config, config_path) == FAIL)
        goto fail;

    if (false)
fail:
        ret = FAIL;

    free(config_path);
    free(tofree);

    return ret;
}

void
config_uninit(struct config *config)
{
    for (uint32_t i = 0; i < config->configured_seats_len; i++)
        free(config->configured_seats[i].name);
    free(config->configured_seats);

    regex_t *reg;

    wl_array_for_each(reg, &config->allowed_mime_types) { regfree(reg); }
    wl_array_for_each(reg, &config->blocked_mime_types) { regfree(reg); }

    wl_array_release(&config->blocked_mime_types);
    wl_array_release(&config->allowed_mime_types);
    free(config->display_name);
}

/*
 * Parse and apply the config file. Returns OK on success and FAIL on failure.
 */
static int
config_parse(struct config *config, const char *config_file)
{
    toml_result_t result = toml_parse_file_ex(config_file);

    if (!result.ok)
    {
        wlip_log("Error parsing config file: %s", result.errmsg);
        return FAIL;
    }

    toml_datum_t t_display = toml_seek(result.toptab, "wlip.display");

    if (t_display.type == TOML_STRING)
    {
        if (config->display_name != NULL)
            config->display_name = strdup(t_display.u.s);
    }
    else if (t_display.type != TOML_UNKNOWN)
    {
        wlip_log("Config: wlip.display is not a string");
        goto fail;
    }

    toml_datum_t t_seats = toml_seek(result.toptab, "seats");

    if (t_seats.type == TOML_TABLE)
    {
        config->configured_seats =
            malloc(sizeof(struct config_seat) * t_seats.u.tab.size);

        if (config->configured_seats == NULL)
        {
            wlip_err("Error allocating config");
            goto fail;
        }

        for (int32_t i = 0; i < t_seats.u.tab.size; i++)
        {
            const char  *seatname = t_seats.u.tab.key[i];
            toml_datum_t t_seat = t_seats.u.tab.value[i];

            if (t_seat.type == TOML_TABLE)
            {
                struct config_seat *seat = config->configured_seats + i;

                seat->name = strdup(seatname);
                if (seat->name == NULL)
                {
                    wlip_err("Error allocating config");
                    goto fail;
                }

                toml_datum_t t_regular = toml_seek(t_seat, "regular");
                toml_datum_t t_primary = toml_seek(t_seat, "primary");

                seat->regular = seat->primary = true;
                if (t_regular.type == TOML_BOOLEAN)
                    seat->regular = t_regular.u.boolean;
                if (t_primary.type == TOML_BOOLEAN)
                    seat->primary = t_primary.u.boolean;
                config->configured_seats_len++;
            }
            else
            {
                wlip_log("Config: wlip.seats is not an table of tables");
                goto fail;
            }
        }
    }
    else if (t_seats.type != TOML_UNKNOWN)
    {
        wlip_log("Config: wlip.seats is not an table of tables");
        goto fail;
    }

    toml_datum_t t_max_entries = toml_seek(result.toptab, "wlip.max_entries");

    if (t_max_entries.type == TOML_INT64)
        config->max_entries = t_max_entries.u.int64;
    else if (t_max_entries.type != TOML_UNKNOWN)
    {
        wlip_log("Config: wlip.max_entries is not an integer");
        goto fail;
    }

    toml_datum_t t_persist = toml_seek(result.toptab, "wlip.persist");

    if (t_persist.type == TOML_BOOLEAN)
        config->persist = t_persist.u.boolean;
    else if (t_persist.type != TOML_UNKNOWN)
    {
        wlip_log("Config: wlip.persist is not a boolean");
        goto fail;
    }

    toml_datum_t t_allowed_mime_types =
        toml_seek(result.toptab, "wlip.allowed_mime_types");

    if (t_allowed_mime_types.type == TOML_ARRAY)
        save_pattern_array(t_allowed_mime_types, &config->allowed_mime_types);
    else if (t_allowed_mime_types.type != TOML_UNKNOWN)
    {
        wlip_log("Config: wlip.allowed_mime_types is not an array of strings");
        goto fail;
    }

    toml_datum_t t_blocked_mime_types =
        toml_seek(result.toptab, "wlip.blocked_mime_types");

    if (t_blocked_mime_types.type == TOML_ARRAY)
        save_pattern_array(t_blocked_mime_types, &config->blocked_mime_types);
    else if (t_blocked_mime_types.type != TOML_UNKNOWN)
    {
        wlip_log("Config: wlip.blocked_mime_types is not an array of strings");
        goto fail;
    }

    toml_datum_t t_max_size = toml_seek(result.toptab, "wlip.max_size");

    if (t_max_size.type == TOML_INT64)
        config->max_size = t_max_size.u.int64;
    else if (t_max_size.type != TOML_UNKNOWN)
    {
        wlip_log("Config: wlip.max_size is not an integer");
        goto fail;
    }

    toml_free(result);
    return OK;
fail:
    config_uninit(config);
    toml_free(result);
    return FAIL;
}

/*
 * Parse the TOML array of pattern/regexes, and store them in "store". Returns
 * OK on success and FAIL on failure.
 */
static int
save_pattern_array(toml_datum_t arr, struct wl_array *store)
{
    for (int32_t i = 0; i < arr.u.arr.size; i++)
    {
        toml_datum_t t_pattern = arr.u.arr.elem[i];

        if (t_pattern.type != TOML_STRING)
        {
            wlip_log(
                "Config: wlip.allowed_mime_types is not an array of strings"
            );
            return FAIL;
        }

        regex_t re;
        int     res = regcomp(&re, t_pattern.u.s, REG_EXTENDED | REG_NOSUB);

        if (res != 0)
        {
            static char errbuf[128];

            regerror(res, &re, errbuf, 128);
            wlip_log("Config: invalid pattern '%s': %s", t_pattern.u.s, errbuf);
            return FAIL;
        }

        regex_t *save = wl_array_add(store, sizeof(regex_t));

        if (save == NULL)
        {
            wlip_err("Error allocating allowed mime types array");
            regfree(&re);
            return FAIL;
        }

        *save = re;
    }
    return OK;
}
