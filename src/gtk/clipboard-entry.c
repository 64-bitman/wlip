#include "clipboard-entry.h"
#include <glib-object.h>
#include <glib.h>
#include <gtk-4.0/gtk/gtk.h>

struct _ClipboardEntry
{
    GObject parent;

    int64_t id;
    int64_t creation_time;
    int64_t update_time;
    bool    starred;

    char      **mime_types;
    const char *display_mime_type;
};

G_DEFINE_TYPE(ClipboardEntry, clipboard_entry, G_TYPE_OBJECT)

static void
clipboard_entry_class_init(ClipboardEntryClass *class)
{
}

static void
clipboard_entry_init(ClipboardEntry *entry)
{
}
