#include "entry-box.h"
#include "clipboard-entry.h"
#include "log.h"
#include "util.h"
#include <glib-object.h>
#include <glib.h>
#include <gtk-4.0/gtk/gtk.h>

struct _EntryBox
{
    GtkWidget parent;

    GtkWidget *root_box;

    GtkWidget *header_box;
    // These are in header_box, aligned horizontally in columns
    GtkWidget *position_number;
    GtkWidget *timestamp_label;

    GCancellable   *cancel;
    ClipboardEntry *entry;
    uint            handler_id;

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
    gtk_widget_set_size_request(self->root_box, -1, 200);

    self->header_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_set_homogeneous(GTK_BOX(self->header_box), TRUE);
    gtk_widget_set_margin_start(self->header_box, 10);
    gtk_widget_set_margin_end(self->header_box, 10);
    gtk_widget_set_margin_top(self->header_box, 10);
    gtk_widget_set_margin_bottom(self->header_box, 10);
    gtk_box_append(GTK_BOX(self->root_box), self->header_box);

    self->position_number = gtk_label_new(NULL);
    gtk_box_append(GTK_BOX(self->header_box), self->position_number);
    gtk_widget_set_halign(self->position_number, GTK_ALIGN_START);

    self->timestamp_label = gtk_label_new(NULL);
    gtk_box_append(GTK_BOX(self->header_box), self->timestamp_label);
    gtk_widget_set_halign(self->timestamp_label, GTK_ALIGN_END);

    self->content = NULL;
}

GtkWidget *
entry_box_new(void)
{
    return g_object_new(ENTRY_TYPE_BOX, NULL);
}

static void
entry_box_set_content(EntryBox *self, GtkWidget *content)
{
    g_assert(ENTRY_IS_BOX(self));
    g_assert(content == NULL || GTK_IS_WIDGET(content));

    if (self->content != NULL)
        gtk_box_remove(GTK_BOX(self->root_box), self->content);
    self->content = content;
    if (content != NULL)
        gtk_box_append(GTK_BOX(self->root_box), self->content);
}

static void
entry_box_cancel(EntryBox *self)
{
    g_assert(ENTRY_IS_BOX(self));
    if (self->cancel != NULL)
    {
        g_cancellable_cancel(self->cancel);
        g_object_unref(self->cancel);
        self->cancel = NULL;
    }
}

/*
 * Set the content of the entry box to given data. Returns OK on success and
 * FAIL on failure.
 */
static int
entry_box_set_content_data(EntryBox *self, GBytes *bytes)
{
    g_assert(ENTRY_IS_BOX(self));
    g_assert(self->entry != NULL);
    g_assert(bytes != NULL);

    size_t         len;
    const uint8_t *data = g_bytes_get_data(bytes, &len);

    switch (clipboard_entry_get_content_type(self->entry))
    {
    case CONTENT_TYPE_TEXT:
    {
        char      *tmp = g_strndup((char *)data, len);
        GtkWidget *label = gtk_label_new(tmp);

        g_free(tmp);

        gtk_label_set_wrap(GTK_LABEL(label), TRUE);
        gtk_label_set_wrap_mode(GTK_LABEL(label), PANGO_WRAP_WORD_CHAR);

        GtkScrolledWindow *scr = GTK_SCROLLED_WINDOW(gtk_scrolled_window_new());

        gtk_scrolled_window_set_policy(
            scr, GTK_POLICY_NEVER, GTK_POLICY_ALWAYS
        );
        gtk_scrolled_window_set_max_content_height(scr, 500);
        gtk_scrolled_window_set_propagate_natural_height(scr, TRUE);
        gtk_scrolled_window_set_child(scr, label);

        entry_box_set_content(self, GTK_WIDGET(scr));

        return OK;
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
    entry_box_set_content(self, spinner);
}

static void
entry_box_binary(EntryBox *self)
{
    entry_box_set_content(self, gtk_label_new("<Binary data>"));
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

    if (entry_box_set_content_data(ebox, data) == FAIL)
        entry_box_binary(ebox);
    g_bytes_unref(data);

exit:
    g_clear_object(&ebox->cancel);
    g_object_unref(ebox);
}

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
        self->cancel = g_cancellable_new();
        clipboard_entry_load_mime_type_async(
            entry,
            display,
            self->cancel,
            (GAsyncReadyCallback)load_mime_type_callback,
            g_object_ref(self)
        );
    }

    if (entry_box_set_content_data(self, bytes) == FAIL)
        goto binary;

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
 * is NULL, then make the entry box empty.
 */
void
entry_box_set(EntryBox *self, ClipboardEntry *entry, uint pos)
{
    g_assert(ENTRY_IS_BOX(self));
    g_assert(entry == NULL || CLIPBOARD_IS_ENTRY(entry));

    entry_box_cancel(self);
    if (self->entry != NULL)
    {
        g_signal_handler_disconnect(self->entry, self->handler_id);
        g_object_unref(self->entry);
    }

    if (entry == NULL)
    {
        self->entry = NULL;
        entry_box_set_content(self, NULL);
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

    static char buf[65];

    sprintf(buf, "%u", pos);
    gtk_label_set_text(GTK_LABEL(self->position_number), buf);

    if (!clipboard_entry_is_loaded(self->entry))
    {
        clipboard_entry_refresh(self->entry, pos);
        entry_box_loading(self);
    }
    else
        entry_box_update_content(self);
}
