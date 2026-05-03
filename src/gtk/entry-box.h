#pragma once

#include "clipboard-entry.h"
#include <glib-object.h>
#include <glib.h>
#include <gtk-4.0/gtk/gtk.h>

#define ENTRY_TYPE_BOX (entry_box_get_type())
G_DECLARE_FINAL_TYPE(EntryBox, entry_box, ENTRY, BOX, GtkWidget)

// clang-format off
GtkWidget *entry_box_new(void);
void entry_box_set(EntryBox *self, ClipboardEntry *entry, uint position);
// clang-format on
