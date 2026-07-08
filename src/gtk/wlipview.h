#pragma once

#include "wlipdaemon.h"
#include "wliplist.h"
#include <glib-object.h>
#include <gtk/gtk.h>

#define WLIP_TYPE_VIEW_ITEM (wlip_view_item_get_type())
G_DECLARE_FINAL_TYPE(WlipViewItem, wlip_view_item, WLIP, VIEW_ITEM, GtkWidget)

#define WLIP_TYPE_VIEW (wlip_view_get_type())
G_DECLARE_FINAL_TYPE(WlipView, wlip_view, WLIP, VIEW, GtkWidget)

// clang-format off
GtkWidget *wlip_view_new(WlipDaemon *daemon, WlipList *list);
// clang-format on
