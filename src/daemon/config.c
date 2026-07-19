#include "config.h"
#include "config_base.h"
#include "log.h"
#include "tomlc17.h"
#include "util.h"
#include <assert.h>
#include <errno.h> // IWYU pragma: keep
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// clang-format off
static int extract_seats(const char *key UNUSED, toml_datum_t dat, void *vstore);
static int extract_pattern_array(const char *key UNUSED, toml_datum_t dat, void *vstore);
// clang-format on

/*
 * Parse and apply the configuration. If "config_dir" is NULL, then the default
 * path is used. Returns OK on success and FAIL on failure.
 */
int
config_init(struct config *config, const char *cfgdir)
{
    toml_result_t result;
    int           ret = config_parse("wlip", cfgdir, "config.toml", &result);

    if (ret == FAIL)
        return FAIL;

    // clang-format off
    *config = (struct config){
        .display_name = NULL,
        .max_entries = 100,
        .persist = true,
        .max_size = 10000000, // 10 MB

        .page_size = 4096,
        .cache_size = 1000,

        .configured_seats = NULL,
        .configured_seats_len = 0,

        .allowed_mime_types = NULL,
        .allowed_mime_types_len = 0,

        .blocked_mime_types = NULL,
        .blocked_mime_types_len = 0,
    };
    // clang-format on

    if (ret == IGNORED)
        return OK;

    ret = config_extract(
        result.toptab,
        "siibiiccc",
        "wlip.display",
        &config->display_name,
        "wlip.max_entries",
        &config->max_entries,
        "wlip.max_size",
        &config->max_size,
        "wlip.persist",
        &config->persist,
        "wlip.page_size",
        &config->page_size,
        "wlip.cache_size",
        &config->cache_size,
        "seats",
        TOML_TABLE,
        extract_seats,
        config,
        "wlip.allowed_mime_types",
        TOML_ARRAY,
        extract_pattern_array,
        config,
        "wlip.blocked_mime_types",
        TOML_ARRAY,
        extract_pattern_array,
        config
    );

    toml_free(result);

    if (ret == FAIL)
    {
        config_uninit(config);
        return FAIL;
    }

    return OK;
}

void
config_uninit(struct config *config)
{
    for (uint32_t i = 0; i < config->configured_seats_len; i++)
        free(config->configured_seats[i].name);
    free(config->configured_seats);

    for (uint32_t i = 0; i < config->allowed_mime_types_len; i++)
        regfree(config->allowed_mime_types + i);
    free(config->allowed_mime_types);

    for (uint32_t i = 0; i < config->blocked_mime_types_len; i++)
        regfree(config->blocked_mime_types + i);
    free(config->blocked_mime_types);

    free(config->display_name);
}

static int
extract_seats(const char *key UNUSED, toml_datum_t dat, void *vstore)
{
    struct config *config = vstore;

    config->configured_seats =
        malloc(sizeof(struct config_seat) * dat.u.tab.size);

    if (config->configured_seats == NULL)
    {
        log_errerror("Error allocating config");
        return FAIL;
    }

    for (int32_t i = 0; i < dat.u.tab.size; i++)
    {
        const char  *seatname = dat.u.tab.key[i];
        toml_datum_t t_seat = dat.u.tab.value[i];

        if (t_seat.type != TOML_TABLE)
        {
            log_error("Config: expected table for seat");
            return FAIL;
        }

        struct config_seat *seat = config->configured_seats + i;

        seat->name = strdup(seatname);
        if (seat->name == NULL)
        {
            log_errerror("Config: error allocating seat name");
            return FAIL;
        }

        int ret = config_extract(
            t_seat, "bb", "regular", &seat->regular, "primary", &seat->primary
        );

        if (ret == FAIL)
        {
            free(seat->name);
            return FAIL;
        }
        config->configured_seats_len++;
    }
    return OK;
}

/*
 * Parse the TOML array of pattern/regexes, and store them in "store". Returns
 * OK on success and FAIL on failure.
 */
static int
extract_pattern_array(const char *key, toml_datum_t dat, void *vstore)
{
    struct config *config = vstore;
    regex_t      **sarr;
    regex_t       *arr;
    uint32_t      *arr_len;

    if (strcmp(key, "wlip.allowed_mime_types") == 0)
    {
        sarr = &config->allowed_mime_types;
        arr_len = &config->allowed_mime_types_len;
    }
    else
    {
        sarr = &config->blocked_mime_types;
        arr_len = &config->blocked_mime_types_len;
    }

    assert(*sarr == NULL);
    *sarr = malloc(dat.u.arr.size * sizeof(regex_t));
    if (*sarr == NULL)
    {
        log_errerror("Error allocating pattern array");
        return FAIL;
    }

    arr = *sarr;

    for (int32_t i = 0; i < dat.u.arr.size; i++)
    {
        toml_datum_t t_pattern = dat.u.arr.elem[i];

        if (t_pattern.type != TOML_STRING)
        {
            log_error("Config: expected string for pattern in %s", key);
            return FAIL;
        }

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

        arr[i] = re;
        (*arr_len)++;
    }

    return OK;
}
