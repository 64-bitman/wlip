#include "base64.h"
#include "ipc_client.h"
#include "log.h"
#include "util.h"
#include <errno.h> // IWYU pragma: keep
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

static bool JSON = false;

// clang-format off
static int subcommand_list(struct ipc_client *client, int argc, char **argv);
static int subcommand_set(struct ipc_client *client, int argc, char **argv);
// clang-format on

int
main(int argc, char **argv)
{
    static const struct option options[] = {
        {"version", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"json", no_argument, 0, 'j'},
        {NULL, 0, 0, 0}
    };

    int c;
    int idx;

    // Parse global command line flags
    while ((c = getopt_long(argc, argv, "+vhj", options, &idx)) != -1)
    {
        switch (c)
        {
        case 'v':
            return EXIT_SUCCESS;
        case 'h':
            return EXIT_SUCCESS;
        case 'j':
            JSON = true;
            break;
        default:
            return EXIT_FAILURE;
        }
    }

    if (optind >= argc)
    {
        log_error("Missing subcommand");
        return EXIT_FAILURE;
    }

    struct ipc_client client;

    if (ipc_client_init(&client) == FAIL)
        return EXIT_FAILURE;

    const char *subcmd = argv[optind++];
    int         sub_argc = argc - optind + 1;
    char      **sub_argv = argv + optind - 1;
    int         ret = EXIT_FAILURE;

    optind = 1;

    if (strcmp(subcmd, "list") == 0)
        ret = subcommand_list(&client, sub_argc, sub_argv);
    else if (strcmp(subcmd, "set") == 0)
        ret = subcommand_set(&client, sub_argc, sub_argv);
    else
        log_error("Unknown subcommand '%s'", subcmd);

    ipc_client_uninit(&client);

    return ret;
}

static bool
is_error(struct json_object *resp)
{
    const char *type = get_json_string(resp, "type");

    return type == NULL || strcmp(type, "error") == 0;
}

static void
output_error(struct json_object *err)
{
    const char *err_type = get_json_string(err, "error_type");

    if (err_type != NULL && strcmp(err_type, "id") != 0)
    {
        const char *desc = get_json_string(err, "desc");

        if (desc != NULL)
            log_error("%s", desc);
    }
}

/*
 * Do a roundtrip and get the data for the mime type from the entry "id".
 * Returns NULL on failure.
 */
static uint8_t *
get_mime_type(
    struct ipc_client *client, int64_t id, const char *mime_type, int *len
)
{
    struct json_object *req = json_object_new_object();
    struct json_object *resp;
    uint8_t            *buf = NULL;

    if (req == NULL)
        return NULL;

    add_json_integer(req, "id", id, true);
    add_json_string(req, "mime_type", mime_type, true);

    resp = ipc_client_roundtrip(client, "get_mime_type", req);

    if (resp == NULL)
        return NULL;
    if (is_error(resp))
    {
        output_error(resp);
        goto exit;
    }

    const char *data = get_json_string(resp, "data");
    int         datalen;

    if (data == NULL)
        goto exit;
    datalen = get_json_string_len(resp, "data");
    if (datalen <= 0)
        goto exit;

    // Decode base64 string
    unsigned int buflen = b64d_size((unsigned char *)data, datalen);
    buf = malloc(buflen);

    if (buf == NULL)
    {
        log_error("Error allocating %d bytes", buflen);
        goto exit;
    }

    b64_decode((unsigned char *)data, datalen, (unsigned char *)buf);

    *len = buflen;
exit:
    json_object_put(resp);
    return buf;
}

static int
subcommand_list(struct ipc_client *client, int argc, char **argv)
{
    static const struct option options[] = {
        {"start", required_argument, 0, 's'},
        {"max", required_argument, 0, 'm'},
        {"id", required_argument, 0, 'i'},
        {"fuzzel", no_argument, 0, 'f'},
        {NULL, 0, 0, 0}
    };

    int c;
    int idx;

    int64_t start = 0, max = INT64_MAX, id = -1;
    bool    fuzzel = false;

    // Parse global command line flags
    while ((c = getopt_long(argc, argv, "+s:m:i:f", options, &idx)) != -1)
    {
        switch (c)
        {
        case 's':
            start = strtoll(optarg, NULL, 10);
            break;
        case 'm':
            max = strtoll(optarg, NULL, 10);
            break;
        case 'i':
            id = strtoll(optarg, NULL, 10);
            if (id < 0)
                return EXIT_FAILURE;
            break;
        case 'f':
            fuzzel = true;
            break;
        default:
            return EXIT_FAILURE;
        }
    }

    if (start < 0 || max <= 0)
        return EXIT_FAILURE;

    if (id != -1)
        max = 1;

    for (int64_t i = start; i < max; i++)
    {
        struct json_object *req = json_object_new_object();

        if (req == NULL)
            return EXIT_FAILURE;

        if (id != -1)
            add_json_integer(req, "id", id, true);
        else
            add_json_integer(req, "index", i, true);

        struct json_object *resp =
            ipc_client_roundtrip(client, "get_entry", req);

        if (resp == NULL)
            return EXIT_FAILURE;

        if (is_error(resp))
        {
            json_object_put(resp);
            break;
        }

        int64_t id;

        if (get_json_integer(resp, "id", &id) == FAIL)
            goto next;

        // Delete internal stuff before outputting
        json_object_object_del(resp, "serial");
        json_object_object_del(resp, "type");

        if (JSON)
        {
            const char *str =
                json_object_to_json_string_ext(resp, JSON_C_TO_STRING_PLAIN);
            printf("%s\n", str);
        }
        else if (fuzzel)
        {
            struct json_object *arr =
                json_object_object_get(resp, "mime_types");

            if (!json_object_is_type(arr, json_type_array))
                goto next;

            const char *mime_type = find_mime_type(arr, MIMETYPE_CLASS_TEXT);
            char       *data;
            int         len;

            if (mime_type != NULL)
                data = (char *)get_mime_type(client, id, mime_type, &len);
            else
            {
                data = strdup("<binary data>");
                len = strlen("<binary data>");
            }

            if (data != NULL)
            {
                // Remove any newlines and replace with space
                for (int i = 0; i < len; i++)
                    if (data[i] == '\n')
                        data[i] = ' ';

                printf("%" PRId64 "\t%.*s\n", id, len, data);
                free(data);
            }
        }
        else
        {
            int64_t id;
            if (get_json_integer(resp, "id", &id) == OK)
                printf("%" PRId64 "\n", id);
        }

next:
        json_object_put(resp);
    }

    return EXIT_SUCCESS;
}

static int
subcommand_set(struct ipc_client *client, int argc, char **argv)
{
    static const struct option options[] = {
        {"id", required_argument, 0, 'i'}, {NULL, 0, 0, 0}
    };

    int c;
    int idx;

    int64_t id = -1;

    // Parse global command line flags
    while ((c = getopt_long(argc, argv, "+i:I:", options, &idx)) != -1)
    {
        switch (c)
        {
        case 'i':
            id = strtoll(optarg, NULL, 10);
            if (id < 0)
                return EXIT_FAILURE;
            break;
        default:
            return EXIT_FAILURE;
        }
    }

    if (id == -1)
    {
        log_error("--id not provided");
        return EXIT_FAILURE;
    }

    struct json_object *req = json_object_new_object();

    if (req == NULL)
        return EXIT_FAILURE;

    add_json_integer(req, "id", id, true);

    struct json_object *resp = ipc_client_roundtrip(client, "set_entry", req);

    if (resp == NULL)
        return EXIT_FAILURE;
    if (is_error(resp))
    {
        output_error(resp);
        json_object_put(resp);
        return EXIT_FAILURE;
    }

    json_object_put(resp);
    return EXIT_SUCCESS;
}
