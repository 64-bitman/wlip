#include "base64.h"
#include "util.h"
#include <errno.h> // IWYU pragma: keep
#include <fcntl.h>
#include <getopt.h>
#include <json.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// Should return true to stop reading responses.
typedef bool (*read_callback)(struct json_object *, void *udata);

static const struct option OPTIONS_GLOBAL[] = {
    {"version", no_argument, 0, 'v'},
    {"help", no_argument, 0, 'h'},
    {"json", no_argument, 0, 'j'},
    {NULL, 0, 0, 0}
};

static bool JSON = false;

int        handle_subcommand_list(int argc, char **argv, int fd);
static int connect_to_daemon(void);
static int read_responses(int fd, read_callback callback, void *udata);

int
main(int argc, char **argv)
{
    int c;
    int idx;

    // Parse global command line flags
    while ((c = getopt_long(argc, argv, "+vhj", OPTIONS_GLOBAL, &idx)) != -1)
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
        wlip_log("Missing subcommand");
        return EXIT_FAILURE;
    }

    const char *subcmd = argv[optind++];

    int fd = connect_to_daemon();

    if (fd == -1)
        return EXIT_FAILURE;

    if (strcmp(subcmd, "list") == 0)
        return handle_subcommand_list(argc - optind + 1, argv + optind - 1, fd);
    else
        wlip_log("Unknown subcommand '%s'", subcmd);

    return EXIT_FAILURE;
}

static bool
get_entry_callback(struct json_object *resp, void *udata UNUSED)
{
    if (json_object_object_length(resp) == 0)
        return true;

    if (JSON)
    {
        const char *str =
            json_object_to_json_string_ext(resp, JSON_C_TO_STRING_SPACED);

        printf("%s\n", str);
    }
    else
    {
        // If --json not specified, just print the id of the entry
        struct json_object *mime_types;

        if (json_object_object_get_ex(resp, "mime_types", &mime_types))
        {
            static const char *mime_array[] = {
                "text/plain", "image/png", "image/jpeg"
            };

            for (size_t i = 0; i < N_ELEMENTS(mime_array); i++)
            {
                struct json_object *mime_type;

                if (!json_object_object_get_ex(
                        mime_types, mime_array[i], &mime_type
                    ) ||
                    json_object_is_type(mime_type, json_type_null))
                    continue;

                const char *encoded = json_object_get_string(mime_type);
                int         len = json_object_get_string_len(mime_type);

                int   sz = b64d_size(len);
                char *str = calloc(sz, 1);

                if (str == NULL)
                    continue;

                b64_decode((unsigned char *)encoded, len, (unsigned char *)str);

                printf("%s", str);
                free(str);

                break;
            }
        }
    }

    return false;
}

int
handle_subcommand_list(int argc, char **argv, int fd)
{
    static const struct option options[] = {
        {"start", required_argument, 0, 's'},
        {"number", required_argument, 0, 'n'},
        {"mime_types", required_argument, 0, 'm'},
        {NULL, 0, 0, 0}
    };
    int c;
    int idx;

    int64_t start = 0, n = 1;
    char   *mime_types = NULL;

    optind = 1;

    while ((c = getopt_long(argc, argv, "+s:n:m:", options, &idx)) != -1)
    {
        switch (c)
        {
        case 's':
            start = strtoll(optarg, NULL, 10);
            break;
        case 'n':
            n = strtoll(optarg, NULL, 10);
            break;
        case 'm':
            mime_types = strdup(optarg);
            break;
        default:
            return EXIT_FAILURE;
        }
    }

    struct json_object *req = json_object_new_object();

    if (req == NULL)
        return FAIL;

    add_json_string(req, "type", "get_entry", true);
    add_json_integer(req, "start", start, true);
    add_json_integer(req, "number", n, true);

    if (mime_types == NULL)
        // Set default value
        mime_types = strdup("text/plain,image/png,image/jpeg");

    if (mime_types != NULL)
    {
        // Specify mime types that should also have their contents sent over.
        struct json_object *arr = json_object_new_array();

        if (arr != NULL)
        {
            const char *tok = strtok(mime_types, ",");

            while (tok != NULL)
            {
                struct json_object *j_mt = json_object_new_string(tok);

                if (j_mt != NULL)
                    json_object_array_add(arr, j_mt);

                tok = strtok(NULL, ",");
            }
        }
        free(mime_types);

        json_object_object_add(req, "mime_types", arr);
    }

    if (send_json(fd, req) == FAIL)
    {
        json_object_put(req);
        return EXIT_FAILURE;
    }
    json_object_put(req);

    // Read responses (entries) and print them out until we receive a terminator
    // (empty object "{}").
    if (read_responses(fd, get_entry_callback, NULL) == FAIL)
        return FAIL;
    return OK;
}

/*
 * Connect to the wlip daemon and return an fd for the connection. Returns -1 on
 * error.
 */
static int
connect_to_daemon(void)
{
    const char *path = getenv("WLIP_SOCK");
    char       *tofree = NULL;

    if (path == NULL)
    {
        const char *display = getenv("WAYLAND_DISPLAY");

        if (display == NULL)
        {
            wlip_log("$WAYLAND_DISPLAY not set in environment");
            return -1;
        }

        char *dir = get_base_dir(XDG_RUNTIME_DIR, "wlip");

        tofree = wlip_strdup_printf("%s/%s", dir, display);
        path = tofree;
        free(dir);

        if (path == NULL)
        {
            wlip_err("Error allocating socket path");
            return -1;
        }
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd == -1)
    {
        wlip_err("Error creating socket");
        free(tofree);
        return -1;
    }

    struct sockaddr_un addr;

    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    addr.sun_family = AF_UNIX;
    free(tofree);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        wlip_err("Error connecting to daemon");
        close(fd);
        return -1;
    }

    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) == -1)
    {
        wlip_err("Error making socket connection non blocking");
        close(fd);
        return -1;
    }

    return fd;
}

/*
 * Read JSON messages from the fd, calling "callback" for each message, until a
 * callback returns true. Returns OK on success and FAIL on failure.
 */
static int
read_responses(int fd, read_callback callback, void *udata)
{
#define BUFSIZE 4096
    static char          buf[BUFSIZE];
    struct json_tokener *tokener = json_tokener_new();
    int                  ret = OK;

    if (tokener == NULL)
    {
        wlip_err("Error allocating JSON tokener");
        return FAIL;
    }

    struct pollfd pfd = {.fd = fd, .events = POLLIN};

    while (true)
    {
        char   *ptr = buf;
        ssize_t r = read(fd, buf, BUFSIZE);

        if (r == -1)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                int p = poll(&pfd, 1, -1);

                if (p == -1)
                {
                    wlip_err("Error polling connection");
                    goto exit;
                }
                continue;
            }

            wlip_err("Error reading from connection");
            ret = FAIL;
            goto exit;
        }

        while (r > 0)
        {
            enum json_tokener_error j_err;
            struct json_object     *root;

            root = json_tokener_parse_ex(tokener, ptr, r);
            j_err = json_tokener_get_error(tokener);

            if (j_err == json_tokener_success)
            {
                bool res = callback(root, udata);

                json_object_put(root);
                if (res)
                    goto exit;

                size_t off = json_tokener_get_parse_end(tokener);
                ptr += off;
                r -= off;
            }
            else
            {
                if (j_err != json_tokener_continue)
                {
                    wlip_log(
                        "Error parsing JSON message: %s",
                        json_tokener_error_desc(j_err)
                    );
                    ret = FAIL;
                    goto exit;
                }
                // Need to read more data
                break;
            }
        }
    }
exit:
    json_tokener_free(tokener);
#undef IPC_BUFSIZE
    return ret;
}
