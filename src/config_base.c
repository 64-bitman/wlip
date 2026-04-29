#include "config_base.h"
#include "log.h"
#include "tomlc17.h"
#include "util.h"
#include <assert.h>
#include <stdarg.h>
#include <string.h> // IWYU pragma: keep
#include <unistd.h>

/*
 * Parse the configuration file in directory "dir". If "cfgdir" is not NULL,
 * then use that as the path to the config directory. Returns OK on success and
 * FAIL on failure.
 */
int
config_parse(const char *dir, const char *cfgdir, toml_result_t *result)
{
    int   ret = OK;
    char *tofree = NULL;
    char *config_path = NULL;

    if (cfgdir == NULL)
    {
        tofree = get_base_dir(XDG_CONFIG_HOME, dir);
        cfgdir = tofree;
    }
    if (cfgdir == NULL)
        return FAIL;

    config_path = wlip_strdup_printf("%s/%s", cfgdir, "config.toml");
    if (config_path == NULL)
        goto fail;

    if (access(config_path, R_OK) == -1)
    {
        log_errerror("Error accessing config file '%s'", config_path);
        goto fail;
    }

    toml_result_t res = toml_parse_file_ex(config_path);

    if (!res.ok)
    {
        log_error("Error parsing config file: %s", res.errmsg);
        return FAIL;
    }

    *result = res;

    if (false)
fail:
        ret = FAIL;

    free(config_path);
    free(tofree);

    return ret;
}

/*
 * Verifies that the type of "dat" (with key "key") is "type" and return OK if
 * it is, else FAIL. If dat is TOML_UNKNOWN, then return IGNORED.
 */
int
config_verify_type(toml_datum_t dat, toml_type_t type, const char *key, ...)
{
    if (dat.type == type)
        return OK;
    else if (dat.type != TOML_UNKNOWN)
    {
        const char *str;

        switch (type)
        {
        case TOML_INT64:
            str = "an integer";
            break;
        case TOML_BOOLEAN:
            str = "a boolean";
            break;
        case TOML_STRING:
            str = "a string";
            break;
        case TOML_TABLE:
            str = "a table";
            break;
        case TOML_ARRAY:
            str = "an array";
            break;
        default:
            log_abort("Unsupported TOML type %d", type);
        }

        va_list     ap;
        static char buf[256];

        va_start(ap, key);
        vsnprintf(buf, 256, key, ap);
        va_end(ap);

        log_error("Config: '%s' is not %s", buf, str);
        return FAIL;
    }
    return IGNORED;
}

/*
 * Similar to toml_seek(), but returns FAIL on failure and emits error message.
 * If "def" is not NULL, then it is copied when "key" does not exist, otherwise
 * "val" is set to NULL.
 */
int
config_get_string(
    toml_datum_t tab, const char *key, const char *def, char **val
)
{
    toml_datum_t t_val = toml_seek(tab, key);
    int          ret = config_verify_type(t_val, TOML_STRING, key);

    if (ret == OK)
    {
        *val = strdup(t_val.u.s);
        if (*val == NULL)
            goto memerror;
    }
    else if (ret == IGNORED)
    {
        if (def == NULL)
            *val = NULL;
        else
        {
            *val = strdup(def);
            if (*val == NULL)
                goto memerror;
        }
    }
    else
        return FAIL;

    return OK;
memerror:
    log_errerror("Config: Error allocating value for '%s'", key);
    return FAIL;
}

int
config_get_integer(toml_datum_t tab, const char *key, int64_t def, int64_t *val)
{
    toml_datum_t t_val = toml_seek(tab, key);
    int          ret = config_verify_type(t_val, TOML_INT64, key);

    if (ret == OK)
        *val = t_val.u.int64;
    else if (ret == IGNORED)
        *val = def;
    else
        return FAIL;
    return OK;
}

int
config_get_boolean(toml_datum_t tab, const char *key, bool def, bool *val)
{
    toml_datum_t t_val = toml_seek(tab, key);
    int          ret = config_verify_type(t_val, TOML_BOOLEAN, key);

    if (ret == OK)
        *val = t_val.u.boolean;
    else if (ret == IGNORED)
        *val = def;
    else
        return FAIL;
    return OK;
}

/*
 * Get the list of basic options, either of type INT64, BOOLEAN, or STRING.
 * Returns OK on success and FAIL on failure.
 */
int
config_basic_options(
    toml_datum_t tab, const struct config_basic_option *options, int len
)
{
    for (int i = 0; i < len; i++)
    {
        struct config_basic_option option = options[i];
        int                        ret;

        switch (option.type)
        {
        case TOML_INT64:
            ret = config_get_integer(
                tab, option.key, option.def.int64, option.store
            );
            break;
        case TOML_BOOLEAN:
            ret = config_get_boolean(
                tab, option.key, option.def.boolean, option.store
            );
            break;
        case TOML_STRING:
            ret = config_get_string(
                tab, option.key, option.def.str, option.store
            );
            break;
        default:
            log_abort("TOML type %d is not a basic type", option.type);
        }

        if (ret == FAIL)
        {
            // Free any previous string options
            for (int k = 0; k < i; k++)
                if (options[k].type == TOML_STRING)
                    free(*(char **)options[k].store);
            return FAIL;
        }
    }
    return OK;
}
