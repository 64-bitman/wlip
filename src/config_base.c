#include "config_base.h"
#include "log.h"
#include "tomlc17.h"
#include "util.h"
#include <stdarg.h>
#include <string.h> // IWYU pragma: keep
#include <unistd.h>

/*
 * Parse the configuration file in directory "dir" (inside $XDG_CONFIG_HOME). If
 * "cfgdir" is not NULL, then use that as the path to the config directory.
 * Returns OK on success and FAIL on failure, or IGNORED if file does not exist.
 */
int
config_parse(
    const char    *dir,
    const char    *cfgdir,
    const char    *cfgname,
    toml_result_t *result
)
{
    int   ret = FAIL;
    char *tofree = NULL;
    char *config_path = NULL;

    if (cfgdir == NULL)
    {
        tofree = get_base_dir(XDG_CONFIG_HOME, dir);
        cfgdir = tofree;
    }
    if (cfgdir == NULL)
        return FAIL;

    config_path = wlip_strdup_printf("%s/%s", cfgdir, cfgname);
    if (config_path == NULL)
        goto exit;

    if (access(config_path, R_OK) == -1)
    {
        ret = IGNORED;
        goto exit;
    }

    toml_result_t res = toml_parse_file_ex(config_path);

    if (!res.ok)
    {
        log_error("Error parsing config file: %s", res.errmsg);
        return FAIL;
    }

    *result = res;
    ret = OK;

exit:

    free(config_path);
    free(tofree);

    return ret;
}

/*
 * Extract options from the TOML table, using the types specified in "fmt" in
 * format of <key name>, <pointer to value store>. If key is not found, nothing
 * is done.
 *
 * "s": const char *
 * "i": int64_t
 * "b": boolean
 * "c": expected TOML type, then custom function specified after key name
 *
 * Returns OK on success and FAIL on failure.
 */
int
config_extract(toml_datum_t table, const char *fmt, ...)
{
    va_list ap;
    int     ret = OK;

    va_start(ap, fmt);
    for (const char *c = fmt; *c != NUL; c++)
    {
        const char  *key = va_arg(ap, const char *);
        toml_datum_t dat = toml_seek(table, key);
        toml_type_t  type = dat.type;
        const char  *expected_type = NULL;
        bool         ignore = false;

        if (type == TOML_UNKNOWN)
            ignore = true;

        switch (*c)
        {
        case 's':
            if (type == TOML_STRING || ignore)
            {
                const char **store = va_arg(ap, const char **);

                if (ignore)
                    break;

                char *str = strdup(dat.u.s);

                if (str != NULL)
                    *store = str;
            }
            else
                expected_type = "string";
            break;
        case 'i':
            if (type == TOML_INT64 || ignore)
            {
                int64_t *store = va_arg(ap, int64_t *);

                if (!ignore)
                    *store = dat.u.int64;
            }
            else
                expected_type = "integer";
            break;
        case 'b':
            if (type == TOML_BOOLEAN || ignore)
            {
                bool *store = va_arg(ap, bool *);

                if (!ignore)
                    *store = dat.u.boolean;
            }
            else
                expected_type = "boolean";
            break;
        case 'c':
            if (type == va_arg(ap, toml_type_t) || ignore)
            {
                config_extract_callback cb =
                    va_arg(ap, config_extract_callback);

                if (!ignore && cb(key, dat, va_arg(ap, void *)) == FAIL)
                    ret = FAIL;
            }
            else
            {
                log_error("Config: unknown value for %s", key);
                ret = FAIL;
            }
            break;
        }

        if (ret == FAIL)
            break;

        if (expected_type != NULL)
        {
            log_error("Config: expected %s for %s", expected_type, key);
            ret = FAIL;
            break;
        }
    }
    va_end(ap);

    return ret;
}
