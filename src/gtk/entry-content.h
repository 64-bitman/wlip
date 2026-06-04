#pragma once

#include <glib-object.h>
#include <glib.h>
#include <gtk-4.0/gtk/gtk.h>

#define ENTRY_TYPE_CONTENT (entry_content_get_type())
G_DECLARE_FINAL_TYPE(EntryContent, entry_content, ENTRY, CONTENT, GtkWidget)

// clang-format off
GtkWidget *entry_content_new(void);
void entry_content_set_child(EntryContent *self, GtkWidget *child);
// clang-format on
