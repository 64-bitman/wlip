#pragma once

#include "ipc-handle.h"
#include <glib-object.h>
#include <glib.h>
#include <stdbool.h>

typedef enum
{
    CONTENT_TYPE_TEXT,
    CONTENT_TYPE_IMAGE,
    CONTENT_TYPE_BINARY
} ContentType;

#define CLIPBOARD_TYPE_ENTRY (clipboard_entry_get_type())
G_DECLARE_FINAL_TYPE(ClipboardEntry, clipboard_entry, CLIPBOARD, ENTRY, GObject)

// clang-format off
ClipboardEntry *clipboard_entry_new(IPCHandle *ipc_handle);
void clipboard_entry_refresh(ClipboardEntry *self, uint index, GCancellable *cancel);
void clipboard_entry_load_mime_type_async(ClipboardEntry *self, const char *mime_type, GCancellable *cancellable, GAsyncReadyCallback callback, void *udata);
GBytes *clipboard_entry_load_mime_type_finish(ClipboardEntry *self, GAsyncResult *result, GError **error);

bool clipboard_entry_is_loaded(ClipboardEntry *self);
ContentType clipboard_entry_get_content_type(ClipboardEntry *self);
const char *clipboard_entry_get_display_mime_type(ClipboardEntry *self);
int clipboard_entry_get_mime_type_data(ClipboardEntry *self, const char *mime_type, GBytes **store);
int64_t clipboard_entry_get_creation_time(ClipboardEntry *self);
int clipboard_entry_get_id(ClipboardEntry *self, int64_t *id);
// clang-format on
