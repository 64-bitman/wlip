#pragma once

#include "event.h"
#include <json.h>
#include <pthread.h>
#include <stdbool.h>

struct ipc_request;
struct ipc_event;
typedef void (*ipc_request_callback)(struct ipc_request *req, void *udata);
typedef void (*ipc_event_callback)(struct ipc_event *req, void *udata);

enum ipc_request_type
{
    IPC_REQUEST_LISTEN_EVENT_STREAM, // "listen_event_stream"
    IPC_REQUEST_GET_ENTRY,           // "get_entry"
    IPC_REQUEST_LOAD_MIMETYPE_DATA,  // "load_mimetype_data"
    IPC_REQUEST_GET_HISTORY_SIZE,    // "get_history_size"
};

struct ipc_request
{
    enum ipc_request_type type;

    ipc_request_callback callback; // May be NULL
    void                *callback_udata;

    bool  is_error;
    char *errmsg; // May be NULL

    struct ipc_request *next;
};

struct ipc_request_listen_event_stream
{
    struct ipc_request base;

    // Arguments
    bool enable;

    // Return fields
    bool success;
};

struct ipc_request_get_entry
{
    struct ipc_request base;

    // Arguments
    int64_t pos;

    // Return fields
    int64_t id;
    int64_t creation_time;
    int64_t update_time;
    bool    starred;
    bool    current;
    char  **mime_types; // If "n_mime_types" is zero, then this is NULL.
    int     n_mime_types;
};

struct ipc_request_load_mimetype_data
{
    struct ipc_request base;

    // Arguments
    int64_t id;
    char   *mimetype;

    // Return fields
    uint8_t *data;
    uint     len;
};

struct ipc_request_get_history_size
{
    struct ipc_request base;

    // Return fields
    int64_t size;
};

enum ipc_event_type
{
    IPC_EVENT_ENTRY_ADDED,   // "entry_added"
    IPC_EVENT_ENTRY_DELETED, // "entry_deleted"
    IPC_EVENT_ENTRY_STATE,   // "entry_state"
    IPC_EVENT_ENTRY_UPDATED, // "entry_updated"
};

struct ipc_event
{
    enum ipc_event_type type;
    struct ipc_event   *next;
};

struct ipc_event_entry_added
{
    struct ipc_event base;

    int64_t id;
};

struct ipc_event_entry_deleted
{
    struct ipc_event base;

    int64_t id;
    int64_t pos;
};

struct ipc_event_entry_updated
{
    struct ipc_event base;

    int64_t id;

    bool    starred;
    int64_t update_time;
    bool    current;

    uint starred_specified : 1;
    uint update_time_specified : 1;
    uint current_specified : 1;
};

struct ipc_client
{
    struct eventloop *loop;
    char             *path;
    pthread_t         main_thread;
    pthread_t         ipc_thread;

    pthread_mutex_t     req_mut;
    struct ipc_request *req_first;
    struct ipc_request *req_last;

    pthread_mutex_t     resp_mut;
    struct ipc_request *resp_first;
    struct ipc_request *resp_last;

    pthread_mutex_t   event_mut;
    struct ipc_event *event_first;
    struct ipc_event *event_last;

    bool            stop;
    pthread_mutex_t stop_mut;

    ipc_event_callback event_callback; // May be NULL
    void              *callback_udata;
};

// clang-format off
int ipc_client_init(struct ipc_client *client, struct eventloop *loop, ipc_event_callback event_callback, void *udata);
void ipc_client_uninit(struct ipc_client *client);
struct ipc_request *ipc_request_new(enum ipc_request_type type, ipc_request_callback callback, void *udata);
void ipc_client_request(struct ipc_client *client, struct ipc_request *req);
// clang-format on
