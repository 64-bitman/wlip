#include "config.h"
#include "tomlc17.h"
#include "util.h"
#include <errno.h> // IWYU pragma: keep
#include <stdlib.h>
#include <string.h>

static int config_parse(struct config *config, const char *config_file);

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

    config->display_name = NULL;
    config->configured_seats = NULL;
    config->configured_seats_len = 0;
    wl_array_init(&config->allowed_mime_types);

    if (config_parse(config, config_path) == FAIL)
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

    config->max_entries = 100;
    if (t_max_entries.type == TOML_INT64)
        config->max_entries = t_max_entries.u.int64;
    else if (t_max_entries.type != TOML_UNKNOWN)
    {
        wlip_log("Config: wlip.max_entries is not an integer");
        goto fail;
    }

    toml_free(result);
    return OK;
fail:
    config_uninit(config);
    toml_free(result);
    return FAIL;
}
