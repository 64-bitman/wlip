#include "config.h"
#include "tomlc17.h"
#include "util.h"
#include "wlip.h"
#include <errno.h> // IWYU pragma: keep
#include <stdlib.h>
#include <string.h>

static int config_parse(const char *config_file);

/*
 * Parse and apply the configuration. If "config_dir" is NULL, then the default
 * path is used. Returns OK on success and FAIL on failure.
 */
int
config_init(const char *config_dir)
{
    int   ret = OK;
    char *tofree = NULL;
    char *config_path = NULL;

    if (config_dir == NULL)
    {
        tofree = get_base_dir(XDG_CONFIG_HOME, "wlip");
        config_dir = tofree;
    }
    if (config_dir == NULL)
        return FAIL;

    config_path = wlip_strdup_printf("%s/%s", config_dir, "config.toml");
    if (config_path == NULL)
        goto fail;

    if (config_parse(config_path) == FAIL)
        goto fail;

    if (false)
fail:
        ret = FAIL;

    free(config_path);
    free(tofree);

    return ret;
}

/*
 * Parse and apply the config file. Returns OK on success and FAIL on failure.
 */
static int
config_parse(const char *config_file)
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
        if (WLIP.display_name != NULL)
            WLIP.display_name = strdup(t_display.u.s);
    }
    else if (t_display.type != TOML_UNKNOWN)
    {
        wlip_log("Config: wlip.display is not a string");
        goto fail;
    }

    toml_datum_t t_seats = toml_seek(result.toptab, "wlip.seats");

    if (t_seats.type == TOML_ARRAY)
    {
        for (int32_t i = 0; i < t_seats.u.arr.size; i++)
        {
            toml_datum_t t_seat = t_seats.u.arr.elem[i];

            if (t_seat.type == TOML_STRING)
            {
                // First allocate a structure for the seat. We will later
                // receive the globals and then actually get the proxy if there
                // is one.
                struct wlip_seat *seat = calloc(1, sizeof(*seat));
                bool              success = false;

                if (seat != NULL)
                {
                    seat->name = strdup(t_seat.u.s);
                    if (seat->name != NULL)
                    {
                        wl_list_insert(&WLIP.seats, &seat->link);
                        success = true;
                    }
                }

                if (!success)
                {
                    free(seat);
                    wlip_err("Error creating seat structure");
                }
            }
            else
            {
                wlip_log("Config: wlip.seats is not an array of strings");
                goto fail;
            }
        }
    }
    else if (t_seats.type != TOML_UNKNOWN)
    {
        wlip_log("Config: wlip.seats is not an array of strings");
        goto fail;
    }

    toml_free(result);
    return OK;
fail:
    toml_free(result);
    return FAIL;
}
