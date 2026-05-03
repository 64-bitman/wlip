#pragma once

#include <json.h>
#include <poll.h>

// Note that callback takes ownership of "resp"
typedef void (*request_callback)(struct json_object *resp, void *udata);
struct ipc_message
{
    struct json_object *req; // If NULL, then request has already been sent.
    const char         *data;
    size_t              remaining;

    request_callback callback;
    void            *udata;

    int64_t serial;

    struct ipc_message *next;
};

typedef void (*event_callback)(struct json_object *event, void *udata);
struct ipc_client
{
    int fd;
    int events;

    event_callback event_callback;
    void          *event_udata;

    struct json_tokener *tokener;
    int64_t              serial_gen;

    // Pending requests waiting for a response
    struct ipc_message *pending_requests;

    // Requests that have not been fully sent yet
    struct ipc_message *requests;
    struct ipc_message *requests_end;
};

// clang-format off
int ipc_client_init(struct ipc_client *client);
void ipc_client_uninit(struct ipc_client *client);
int ipc_client_queue_request(struct ipc_client *client, struct json_object *obj, request_callback callback, void *udata);
void ipc_client_prepare(struct ipc_client *client, struct pollfd *pfd);
int ipc_client_check(struct ipc_client *client, int revents);
struct json_object *ipc_client_roundtrip(struct ipc_client *client, const char *type, struct json_object *req);

void ipc_request_free(struct ipc_message *req);

const char *ipc_get_error_desc(struct json_object *resp);
// clag-format off
