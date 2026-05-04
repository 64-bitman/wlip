#include "entry-box.h"
#include "clipboard-entry.h"
#include "log.h"
#include "util.h"
#include <glib-object.h>
#include <glib.h>
#include <glycin-2/glycin.h>
#include <glycin-gtk4-2/glycin-gtk4.h>
#include <gtk-4.0/gtk/gtk.h>

struct _EntryBox
{
    GtkWidget parent;

    GtkWidget *root_box;

    GtkWidget *header_box;
    // These are in header_box, aligned horizontally in columns
    GtkWidget *position_number;
    GtkWidget *timestamp_label;
    uint       timer_id;

    // Used to cancel IPC operation
    GCancellable   *cancel;
    ClipboardEntry *entry;
    uint            handler_id;

    // Used to cancel image loading operation
    GCancellable *image_cancel;

    GtkListItem *item;

    GtkWidget *content; // Can be GtkLabel or GtkPicture
};

G_DEFINE_FINAL_TYPE(EntryBox, entry_box, GTK_TYPE_WIDGET)

static void
entry_box_dispose(GObject *object)
{
    EntryBox *ebox = ENTRY_BOX(object);

    // Should be NULL since any IPC operation should be finished already.
    g_assert(ebox->cancel == NULL);

    g_clear_object(&ebox->entry);
    g_clear_object(&ebox->item);
    g_clear_pointer(&ebox->root_box, gtk_widget_unparent);

    G_OBJECT_CLASS(entry_box_parent_class)->dispose(object);
}

static void
entry_box_class_init(EntryBoxClass *class)
{
    GObjectClass   *gobject_class = G_OBJECT_CLASS(class);
    GtkWidgetClass *widget_class = GTK_WIDGET_CLASS(class);

    gobject_class->dispose = entry_box_dispose;

    gtk_widget_class_set_layout_manager_type(widget_class, GTK_TYPE_BIN_LAYOUT);
}

static void
entry_box_init(EntryBox *self)
{
    self->root_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_parent(self->root_box, GTK_WIDGET(self));
    gtk_widget_add_css_class(self->root_box, "entry");

    self->header_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_set_homogeneous(GTK_BOX(self->header_box), TRUE);
    gtk_box_append(GTK_BOX(self->root_box), self->header_box);
    gtk_widget_add_css_class(self->header_box, "entry-header");

    self->position_number = gtk_label_new(NULL);
    gtk_box_append(GTK_BOX(self->header_box), self->position_number);
    gtk_widget_set_halign(self->position_number, GTK_ALIGN_START);
    gtk_widget_add_css_class(self->position_number, "entry-position");

    self->timestamp_label = gtk_label_new(NULL);
    gtk_box_append(GTK_BOX(self->header_box), self->timestamp_label);
    gtk_widget_set_halign(self->timestamp_label, GTK_ALIGN_END);
    gtk_widget_add_css_class(self->timestamp_label, "entry-timestamp");

    self->content = NULL;
}

GtkWidget *
entry_box_new(void)
{
    return g_object_new(ENTRY_TYPE_BOX, NULL);
}

static void
entry_box_set_content(EntryBox *self, GtkWidget *content, bool focus)
{
    g_assert(ENTRY_IS_BOX(self));
    g_assert(content == NULL || GTK_IS_WIDGET(content));

    if (self->content != NULL)
        gtk_box_remove(GTK_BOX(self->root_box), self->content);
    self->content = content;
    if (content != NULL)
    {
        gtk_box_append(GTK_BOX(self->root_box), self->content);
        gtk_widget_add_css_class(self->content, "content");
    }

    if (self->item != NULL)
    {
        gtk_list_item_set_activatable(self->item, focus);
        gtk_list_item_set_focusable(self->item, focus);
        gtk_list_item_set_selectable(self->item, focus);
    }

    // Allow bigger entry for images
    if (GTK_IS_PICTURE(content))
        gtk_widget_set_size_request(self->root_box, -1, 400);
    else
        gtk_widget_set_size_request(self->root_box, -1, 100);
}

static void
cancel_and_unref(GCancellable **cancel)
{
    if (*cancel != NULL)
    {
        g_cancellable_cancel(*cancel);
        g_object_unref(*cancel);
        *cancel = NULL;
    }
}

static void
next_frame_callback(GlyImage *image, GAsyncResult *result, EntryBox *ebox)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GlyFrame) frame =
        gly_image_next_frame_finish(image, result, &error);

    g_object_unref(image);
    if (frame == NULL)
    {
        if (error->code != G_IO_ERROR_CANCELLED)
            log_warn("Error loading frame: %s", error->message);
    }
    else
    {
        g_autoptr(GdkTexture) texture = gly_gtk_frame_get_texture(frame);
        GtkWidget *picture =
            gtk_picture_new_for_paintable(GDK_PAINTABLE(texture));

        entry_box_set_content(ebox, picture, true);
    }

    g_clear_object(&ebox->image_cancel);
    g_object_unref(ebox);
}

static void
load_image_callback(GlyLoader *loader, GAsyncResult *result, EntryBox *ebox)
{
    g_autoptr(GError) error = NULL;
    GlyImage *image = gly_loader_load_finish(loader, result, &error);

    g_object_unref(loader);
    if (image == NULL)
    {
        if (error->code != G_IO_ERROR_CANCELLED)
            log_warn("Error loading image: %s", error->message);
        g_clear_object(&ebox->image_cancel);
        g_object_unref(ebox);
        return;
    }

    gly_image_next_frame_async(
        image,
        ebox->image_cancel,
        (GAsyncReadyCallback)next_frame_callback,
        ebox
    );
}

static void
entry_box_update_timestamp(EntryBox *ebox)
{
    g_assert(ENTRY_IS_BOX(ebox));

    g_autoptr(GDateTime) now = g_date_time_new_now_local();
    g_autoptr(GDateTime) since = g_date_time_new_from_unix_local_usec(
        clipboard_entry_get_creation_time(ebox->entry) * 1000 // Creation time
                                                              // is in ms
    );

    GTimeSpan diff = g_date_time_difference(now, since);

    int64_t total_minutes = diff / G_TIME_SPAN_MINUTE;
    char   *str;

    if (total_minutes < 1)
        str = g_strdup("just now");
    else
    {
        int64_t days = total_minutes / (60 * 24);
        int64_t hours = total_minutes % (60 * 24) / 60;
        int64_t minutes = total_minutes % 60;

        if (days > 0 && hours == 0 && minutes == 0)
            str = g_strdup_printf("%ld day%s ago", days, days == 1 ? "" : "s");
        else if (days > 0 && minutes == 0)
            str = g_strdup_printf(
                "%ld day%s %ld hr ago", days, days == 1 ? "" : "s", hours
            );
        else if (days > 0)
            str = g_strdup_printf(
                "%ld day%s %ld hr %ld min ago",
                days,
                days == 1 ? "" : "s",
                hours,
                minutes
            );
        else if (hours == 0)
            str = g_strdup_printf("%ld min ago", minutes);
        else if (minutes == 0)
            str = g_strdup_printf("%ld hr ago", hours);
        else
            str = g_strdup_printf("%ld hr %ld min ago", hours, minutes);
    }

    gtk_label_set_text(GTK_LABEL(ebox->timestamp_label), str);
    g_free(str);
}

static gboolean
timestamp_callback(EntryBox *ebox)
{
    entry_box_update_timestamp(ebox);
    return G_SOURCE_CONTINUE;
}

/*
 * Set the content of the entry box to given data. Returns OK on success, LOAD
 * if content is being loaded asynchronously and FAIL on failure.
 */
static int
entry_box_set_content_data(EntryBox *self, GBytes *bytes)
{
    g_assert(ENTRY_IS_BOX(self));
    g_assert(self->entry != NULL);
    g_assert(bytes != NULL);

    if (self->timer_id == 0)
    {
        // Add timer for timestamp label
        self->timer_id = g_timeout_add_full(
            G_PRIORITY_LOW,
            60000, // 60 seconds
            (GSourceFunc)timestamp_callback,
            g_object_ref(self),
            g_object_unref
        );
        entry_box_update_timestamp(self);
    }

    size_t         len;
    const uint8_t *data = g_bytes_get_data(bytes, &len);

    switch (clipboard_entry_get_content_type(self->entry))
    {
    case CONTENT_TYPE_TEXT:
    {
        char      *tmp = g_strndup((char *)data, len);
        GtkWidget *insc = gtk_inscription_new(tmp);
        g_free(tmp);

        gtk_inscription_set_nat_lines(GTK_INSCRIPTION(insc), 5);
        gtk_inscription_set_min_lines(GTK_INSCRIPTION(insc), 5);
        gtk_inscription_set_text_overflow(
            GTK_INSCRIPTION(insc), GTK_INSCRIPTION_OVERFLOW_ELLIPSIZE_END
        );
        gtk_inscription_set_yalign(GTK_INSCRIPTION(insc), 0);

        entry_box_set_content(self, insc, true);
        return OK;
    }
    case CONTENT_TYPE_IMAGE:
    {
        GlyLoader *loader = gly_loader_new_for_bytes(bytes);

        cancel_and_unref(&self->image_cancel);
        self->image_cancel = g_cancellable_new();

        gly_loader_load_async(
            loader,
            self->image_cancel,
            (GAsyncReadyCallback)load_image_callback,
            g_object_ref(self)
        );
        return LOAD;
    }
    default:
        break;
    }
    return FAIL;
}

static void
entry_box_loading(EntryBox *self)
{
    GtkWidget *spinner = gtk_spinner_new();

    gtk_spinner_start(GTK_SPINNER(spinner));
    entry_box_set_content(self, spinner, false);
}

static void
entry_box_binary(EntryBox *self)
{
    entry_box_set_content(self, gtk_label_new("<Binary data>"), true);
}

static void
load_mime_type_callback(
    ClipboardEntry *entry, GAsyncResult *result, EntryBox *ebox
)
{
    g_autoptr(GError) error = NULL;
    GBytes *data = clipboard_entry_load_mime_type_finish(entry, result, &error);

    if (data == NULL)
    {
        if (error->code != G_IO_ERROR_CANCELLED)
            log_warn("Error loading mime type data: %s", error->message);
        goto exit;
    }

    int ret = entry_box_set_content_data(ebox, data);

    if (ret == FAIL)
        entry_box_binary(ebox);
    else if (ret == LOAD)
        entry_box_loading(ebox);
    g_bytes_unref(data);

exit:
    g_clear_object(&ebox->cancel);
    g_object_unref(ebox);
}

/*
 * Update the content of the entr ybox, if the content data is available,
 * otherwise fetch it.
 */
static void
entry_box_update_content(EntryBox *self)
{
    ClipboardEntry *entry = self->entry;
    const char     *display = clipboard_entry_get_display_mime_type(entry);
    GBytes         *bytes;

    if (display == NULL)
        goto binary;
    if (clipboard_entry_get_mime_type_data(entry, display, &bytes) == FAIL)
        goto loading;
    if (bytes == NULL)
    {
        // Mime type not loaded
        if (self->cancel == NULL)
            self->cancel = g_cancellable_new();
        clipboard_entry_load_mime_type_async(
            entry,
            display,
            self->cancel,
            (GAsyncReadyCallback)load_mime_type_callback,
            g_object_ref(self)
        );
        goto loading;
    }

    int ret = entry_box_set_content_data(self, bytes);

    if (ret == FAIL)
        goto binary;
    else if (ret == LOAD)
        goto loading;

    return;
loading:
    entry_box_loading(self);
    return;
binary:
    entry_box_binary(self);
}

static void
entry_refresh_callback(ClipboardEntry *entry, EntryBox *ebox)
{
    g_assert(ebox->entry == entry);

    entry_box_update_content(ebox);
}

/*
 * Set/overwrite the ClipboardEntry that this entry box should display. If entry
 * is NULL, then make the entry box empty. Note that if "entry" is not NULL,
 * then "item" must also be not NULL, and vice versa.
 */
void
entry_box_set(
    EntryBox *self, ClipboardEntry *entry, GtkListItem *item, uint pos
)
{
    g_assert(ENTRY_IS_BOX(self));
    g_assert(entry == NULL || CLIPBOARD_IS_ENTRY(entry));
    g_assert(
        (entry == NULL && item == NULL) || (entry != NULL && item != NULL)
    );

    // Cancel previous loads only if we're switching to a different entry
    if (entry != self->entry)
    {
        cancel_and_unref(&self->cancel);
        cancel_and_unref(&self->image_cancel);
    }
    if (self->entry != NULL)
    {
        g_signal_handler_disconnect(self->entry, self->handler_id);
        g_object_unref(self->entry);
    }
    if (self->item != NULL)
        g_object_unref(self->item);

    if (entry == NULL)
    {
        self->entry = NULL;
        self->item = NULL;
        if (self->timer_id != 0)
        {
            g_source_remove(self->timer_id);
            self->timer_id = 0;
        }
        entry_box_set_content(self, NULL, false);
        return;
    }
    self->handler_id = g_signal_connect_object(
        entry,
        "refresh",
        G_CALLBACK(entry_refresh_callback),
        self,
        G_CONNECT_DEFAULT
    );
    self->entry = g_object_ref(entry);
    self->item = g_object_ref(item);

    static char buf[65];

    sprintf(buf, "%u", pos);
    gtk_label_set_text(GTK_LABEL(self->position_number), buf);

    if (!clipboard_entry_is_loaded(self->entry))
    {
        if (self->cancel == NULL)
            self->cancel = g_cancellable_new();
        clipboard_entry_refresh(self->entry, pos, self->cancel);
        entry_box_loading(self);
    }
    else
        entry_box_update_content(self);
}
