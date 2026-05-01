#include <glib-object.h>

#define CLIPBOARD_TYPE_ENTRY (clipboard_entry_get_type())
G_DECLARE_FINAL_TYPE(ClipboardEntry, clipboard_entry, CLIPBOARD, ENTRY, GObject)

// clang-format off
// clang-format on
