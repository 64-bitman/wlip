#pragma once

#include "ipc-handle.h"
#include <glib-object.h>
#include <glib.h>

#define CLIPBOARD_TYPE_ENTRY (clipboard_entry_get_type())
G_DECLARE_FINAL_TYPE(ClipboardEntry, clipboard_entry, CLIPBOARD, ENTRY, GObject)

// clang-format off
ClipboardEntry *clipboard_entry_new(IPCHandle *ipc_handle);
void clipboard_entry_refresh(ClipboardEntry *self, uint index);
void clipboard_load_mime_type_async(ClipboardEntry *self, const char *mime_type, GCancellable *cancellable, GAsyncReadyCallback callback, void *udata);
GBytes *clipboard_load_mime_type_finish(ClipboardEntry *self, GAsyncResult *result, GError **error);
// clang-format on
