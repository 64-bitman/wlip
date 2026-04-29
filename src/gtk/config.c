#include "config.h"
#include "config_base.h"
#include "log.h"
#include "tomlc17.h"
#include "util.h"

struct shortcut
{
    const char                    *name;
    const char                   **default_keybinds;
    const struct shortcut_handler *handler;
};

// clang-format off
static int config_get_shortcuts(GtkEventController *controller, toml_datum_t tab, const char *table, const struct shortcut *shortcuts, int len);
// clang-format on

int
config_init(
    struct config            *config,
    const char               *cfgdir,
    struct shortcut_handlers *handlers
)
{
    toml_result_t result;

    if (config_parse("wlipgtk", cfgdir, &result) == FAIL)
        return FAIL;

    char *keyboard_mode, *layer_mode;

    // clang-format off
    struct config_basic_option basic_options[] = {
        {
            .key = "window.width",
            .type = TOML_INT64,
            .store = &config->width,
            .def.int64 = 800
        },
        {
            .key = "window.height",
            .type = TOML_INT64,
            .store = &config->height,
            .def.int64 = 600
        },
        {
            .key = "window.keyboard_mode",
            .type = TOML_STRING,
            .store = &keyboard_mode,
            .def.str = "exclusive"
        },
        {
            .key = "window.layer_mode",
            .type = TOML_STRING,
            .store = &layer_mode,
            .def.str = "overlay"
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

    if (keyboard_mode != NULL)
    {
        if (strcmp(keyboard_mode, "exclusive") == 0)
            config->keyboard_mode = GTK_LAYER_SHELL_KEYBOARD_MODE_EXCLUSIVE;
        else if (strcmp(keyboard_mode, "on_demand") == 0)
            config->keyboard_mode = GTK_LAYER_SHELL_KEYBOARD_MODE_ON_DEMAND;
        else
        {
            log_error(
                "Unknown value '%s' for window.keyboard_mode", keyboard_mode
            );
            goto fail;
        }
        free(keyboard_mode);
    }

    if (layer_mode != NULL)
    {
        if (strcmp(layer_mode, "overlay") == 0)
            config->layer_mode = GTK_LAYER_SHELL_LAYER_OVERLAY;
        else if (strcmp(layer_mode, "top") == 0)
            config->layer_mode = GTK_LAYER_SHELL_LAYER_TOP;
        else if (strcmp(layer_mode, "bottom") == 0)
            config->layer_mode = GTK_LAYER_SHELL_LAYER_BOTTOM;
        else if (strcmp(layer_mode, "background") == 0)
            config->layer_mode = GTK_LAYER_SHELL_LAYER_BACKGROUND;
        else
        {
            log_error("Unknown value '%s' for window.layer_mode", layer_mode);
            goto fail;
        }
        free(layer_mode);
    }

    // clang-format off
    const struct shortcut global_shortcuts[] = {
        {
            .name = "quit",
            .default_keybinds = (const char *[]){"Escape", NULL},
            .handler = &handlers->quit
        }
    };
    // clang-format on

    toml_datum_t t_global_shortcuts =
        toml_seek(result.toptab, "shortcuts.global");

    config->global_shortcuts = gtk_shortcut_controller_new();

    if (config_get_shortcuts(
            config->global_shortcuts,
            t_global_shortcuts,
            "shortcuts.global",
            global_shortcuts,
            N_ELEMENTS(global_shortcuts)
        ) == FAIL)
        goto fail;

    toml_free(result);
    return OK;
fail:
    free(keyboard_mode);
    free(layer_mode);
    config_uninit(config);
    toml_free(result);
    return FAIL;
}

void
config_uninit(struct config *config)
{
    if (config->global_shortcuts != NULL)
        g_object_unref(config->global_shortcuts);
}

static int
config_get_keybind(
    GtkEventController *controller,
    GtkShortcutAction  *action,
    const char         *keybind
)
{
    unsigned int key, modifiers;

    gtk_accelerator_parse(keybind, &key, &modifiers);
    if (key == 0 && modifiers == 0)
    {
        log_error("Invalid keybind '%s'", keybind);
        return FAIL;
    }

    GtkShortcutTrigger *trigger = gtk_keyval_trigger_new(key, modifiers);

    gtk_shortcut_controller_add_shortcut(
        GTK_SHORTCUT_CONTROLLER(controller),
        gtk_shortcut_new(trigger, g_object_ref(action))
    );
    return OK;
}

/*
 * Parse the table of shortcuts, where each key in the table either has a string
 * or string array value of keybinds. Returns OK on success and FAIL on failure.
 */
static int
config_get_shortcuts(
    GtkEventController    *controller,
    toml_datum_t           tab,
    const char            *table,
    const struct shortcut *shortcuts,
    int                    len
)
{
    int ret = config_verify_type(tab, TOML_TABLE, table);

    if (ret == FAIL)
        return FAIL;
    else if (ret == IGNORED)
    {
        for (int i = 0; i < len; i++)
        {
            struct shortcut shortcut = shortcuts[i];
            g_autoptr(GtkShortcutAction) action = gtk_callback_action_new(
                shortcut.handler->callback, shortcut.handler->udata, NULL
            );

            for (int32_t k = 0; shortcut.default_keybinds[k] != NULL; k++)
                // Shouldn't fail
                ret = config_get_keybind(
                    controller, action, shortcut.default_keybinds[k]
                );
        }
        return OK;
    }

    for (int i = 0; i < len; i++)
    {
        struct shortcut shortcut = shortcuts[i];
        toml_datum_t    t_shortcut = toml_seek(tab, shortcut.name);

        if (config_verify_type(
                t_shortcut, STRING_OR_ARRAY, "%s.%s", table, shortcut.name
            ) == FAIL)
            return FAIL;

        int ret;
        g_autoptr(GtkShortcutAction) action = gtk_callback_action_new(
            shortcut.handler->callback, shortcut.handler->udata, NULL
        );

        if (t_shortcut.type == TOML_STRING)
            ret = config_get_keybind(controller, action, t_shortcut.u.s);
        else
        {
            for (int32_t k = 0; k < t_shortcut.u.arr.size; k++)
            {
                toml_datum_t t_keybind = t_shortcut.u.arr.elem[k];

                ret = config_verify_type(
                    t_keybind, TOML_STRING, "%s.%s[%d]", table, shortcut.name, k
                );
                if (ret == FAIL)
                    break;

                ret = config_get_keybind(controller, action, t_keybind.u.s);
                if (ret == FAIL)
                    break;
            }
            if (ret == FAIL)
                return FAIL;
        }
    }

    return OK;
}
