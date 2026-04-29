#include "config.h"
#include "config_base.h"
#include "log.h"
#include "tomlc17.h"
#include "util.h"
#include <errno.h> // IWYU pragma: keep
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// clang-format off
static int save_pattern_array(toml_datum_t tab, const char *key, struct wl_array *store);
// clang-format on

/*
 * Parse and apply the configuration. If "config_dir" is NULL, then the default
 * path is used. Returns OK on success and FAIL on failure.
 */
int
config_init(struct config *config, const char *cfgdir)
{
    toml_result_t result;

    if (config_parse("wlip", cfgdir, &result) == FAIL)
        return FAIL;

    // clang-format off
    struct config_basic_option basic_options[] = {
        {
            .key = "wlip.display",
            .type = TOML_STRING,
            .store = &config->display_name,
            .def.str = NULL
        },
        {
            .key = "wlip.max_entries",
            .type = TOML_INT64,
            .store = &config->max_entries,
            .def.int64 = 100
        },
        {
            .key = "wlip.max_size",
            .type = TOML_INT64,
            .store = &config->max_size,
            .def.int64 = 10000000 // 10 MB
        },
        {
            .key = "wlip.persist",
            .type = TOML_BOOLEAN,
            .store = &config->persist,
            .def.boolean = true
            .def.int64 = true
        }
    };
    // clang-format on

    if (config_basic_options(
            result.toptab, basic_options, N_ELEMENTS(basic_options)
        ) == FAIL)
    {
        toml_free(result);
        return FAIL;
    }

    config->configured_seats = NULL;
    config->configured_seats_len = 0;
    wl_array_init(&config->allowed_mime_types);
    wl_array_init(&config->blocked_mime_types);

    toml_datum_t t_seats = toml_seek(result.toptab, "seats");
    int          ret = config_verify_type(t_seats, TOML_TABLE, "seats");

    if (ret == OK)
    {
        config->configured_seats =
            malloc(sizeof(struct config_seat) * t_seats.u.tab.size);

        if (config->configured_seats == NULL)
        {
            log_errerror("Error allocating config");
            goto fail;
        }

        for (int32_t i = 0; i < t_seats.u.tab.size; i++)
        {
            const char  *seatname = t_seats.u.tab.key[i];
            toml_datum_t t_seat = t_seats.u.tab.value[i];

            ret = config_verify_type(t_seat, TOML_TABLE, "seats.%s", seatname);

            if (ret == OK)
            {
                struct config_seat *seat = config->configured_seats + i;

                seat->name = strdup(seatname);
                if (seat->name == NULL)
                {
                    log_errerror("Config: error allocating seat name");
                    goto fail;
                }

                if (config_get_boolean(
                        t_seat, "regular", true, &seat->regular
                    ) == FAIL ||
                    config_get_boolean(
                        t_seat, "primary", true, &seat->primary
                    ) == FAIL)
                {
                    free(seat->name);
                    goto fail;
                }
                config->configured_seats_len++;
            }
        }
    }
    else if (ret == FAIL)
        goto fail;

    if (save_pattern_array(
            result.toptab,
            "wlip.allowed_mime_types",
            &config->allowed_mime_types
        ) == FAIL ||
        save_pattern_array(
            result.toptab,
            "wlip.blocked_mime_types",
            &config->blocked_mime_types
        ) == FAIL)
        goto fail;

    toml_free(result);
    return OK;
fail:
    config_uninit(config);
    toml_free(result);
    return FAIL;
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
 * Parse the TOML array of pattern/regexes, and store them in "store". Returns
 * OK on success and FAIL on failure.
 */
static int
save_pattern_array(toml_datum_t tab, const char *key, struct wl_array *store)
{
    toml_datum_t arr = toml_seek(tab, key);
    int          ret = config_verify_type(arr, TOML_ARRAY, key);

    if (ret == FAIL)
        return FAIL;
    else if (ret == IGNORED)
        return OK;

    for (int32_t i = 0; i < arr.u.arr.size; i++)
    {
        toml_datum_t t_pattern = arr.u.arr.elem[i];

        if (config_verify_type(t_pattern, TOML_STRING, "%s[%d]", key, i) ==
            FAIL)
            return FAIL;

        regex_t re;
        int     res = regcomp(&re, t_pattern.u.s, REG_EXTENDED | REG_NOSUB);

        if (res != 0)
        {
            static char errbuf[128];

            regerror(res, &re, errbuf, 128);
            log_error(
                "Config: invalid pattern '%s': %s", t_pattern.u.s, errbuf
            );
            return FAIL;
        }

        regex_t *save = wl_array_add(store, sizeof(regex_t));

        if (save == NULL)
        {
            log_errerror("Config: error allocating allowed mime types array");
            regfree(&re);
            return FAIL;
        }

        *save = re;
    }
    return OK;
}
