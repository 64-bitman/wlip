#include "entry-content.h"
#include "util.h"
#include <glib-object.h>
#include <glib.h>
#include <gtk-4.0/gtk/gtk.h>

/*
 * Widget for displaying some content within it, for a clipboard entry. We
 * create our own custom widget so that we can manually handle sizing.
 */
struct _EntryContent
{
    GtkWidget parent;

    GtkWidget *child;
};

G_DEFINE_FINAL_TYPE(EntryContent, entry_content, GTK_TYPE_WIDGET)

// clang-format off
static void entry_content_measure(GtkWidget *widget, GtkOrientation orientation, int for_size, int *min, int *nat, int *min_baseline, int *nat_baseline);
static GtkSizeRequestMode entry_content_get_request_mode(GtkWidget *widget);
static void entry_content_size_allocate(GtkWidget *widget, int width, int height, int baseline);
// clang-format on

static void
entry_content_dispose(GObject *object)
{
    EntryContent *content = ENTRY_CONTENT(object);

    g_clear_pointer(&content->child, gtk_widget_unparent);

    G_OBJECT_CLASS(entry_content_parent_class)->dispose(object);
}

static void
entry_content_class_init(EntryContentClass *class)
{
    GObjectClass   *gobject_class = G_OBJECT_CLASS(class);
    GtkWidgetClass *widget_class = GTK_WIDGET_CLASS(class);

    gobject_class->dispose = entry_content_dispose;
    widget_class->measure = entry_content_measure;
    widget_class->get_request_mode = entry_content_get_request_mode;
    widget_class->size_allocate = entry_content_size_allocate;
}

static void
entry_content_init(EntryContent *self UNUSED)
{
}

GtkWidget *
entry_content_new(void)
{
    return g_object_new(ENTRY_TYPE_CONTENT, NULL);
}

void
entry_content_set_child(EntryContent *self, GtkWidget *child)
{
    if (self->child != NULL)
        gtk_widget_unparent(self->child);
    if (child != NULL)
    {
        gtk_widget_set_parent(child, GTK_WIDGET(self));
        self->child = child;
    }
    else
        self->child = NULL;
}

static void
entry_content_measure(
    GtkWidget     *widget,
    GtkOrientation orientation,
    int            for_size,
    int           *min,
    int           *nat,
    int           *min_baseline,
    int           *nat_baseline
)
{
    EntryContent *self = ENTRY_CONTENT(widget);

    gtk_widget_measure(
        self->child, orientation, for_size, min, nat, min_baseline, nat_baseline
    );

    if (orientation == GTK_ORIENTATION_VERTICAL)
    {
        *min = MIN(*min, 100);
        *nat = MIN(*nat, 400);
    }
}

static GtkSizeRequestMode
entry_content_get_request_mode(GtkWidget *widget UNUSED)
{
    return GTK_SIZE_REQUEST_HEIGHT_FOR_WIDTH;
}

static void
entry_content_size_allocate(
    GtkWidget *widget, int width, int height, int baseline
)
{
    EntryContent *self = ENTRY_CONTENT(widget);

    gtk_widget_allocate(self->child, width, MIN(height, 400), baseline, NULL);
}
