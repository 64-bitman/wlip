#pragma once

#include <glib-object.h>
#include <glib.h>
#include <gtk-4.0/gtk/gtk.h>

typedef struct _ClipboardEntry ClipboardEntry;
G_DECLARE_FINAL_TYPE(ClipboardEntry, clipboard_entry, CLIPBOARD, ENTRY, GObject)
