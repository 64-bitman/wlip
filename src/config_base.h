#pragma once

#include "tomlc17.h"

#define STRING_OR_ARRAY ((toml_type_t) - 1)

struct config_basic_option
{
    const char *key;
    toml_type_t type;
    void       *store;
    union
    {
        int64_t     int64;
        bool        boolean;
        const char *str;
    } def;
};

// clang-format off
int config_parse(const char *dir, const char *cfgdir, toml_result_t *result);

int config_verify_type(toml_datum_t dat, toml_type_t type, const char *key, ...);

int config_get_string(toml_datum_t tab, const char *key, const char *def, char **val);
int config_get_integer(toml_datum_t tab, const char *key, int64_t def, int64_t *val);
int config_get_boolean(toml_datum_t tab, const char *key, bool def, bool *val);

int config_basic_options(toml_datum_t tab, const struct config_basic_option *options, int len);
// clang-format on
