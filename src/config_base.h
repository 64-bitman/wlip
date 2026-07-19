#pragma once

#include "tomlc17.h"

// clang-format off
typedef int (*config_extract_callback)(const char *key, toml_datum_t dat, void *vstore);

int config_parse(const char *dir, const char *cfgdir, const char *cfgname, toml_result_t *result);
int config_extract(toml_datum_t table, const char *fmt, ...);
// clang-format on
