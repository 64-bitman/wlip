#include "buffer.h"
#include "log.h"
#include "util.h"
#include <sys/mman.h>
#include <unistd.h>

// clang-format off
static void buffer_event_release(void *udata, struct wl_buffer *proxy);

static const struct wl_buffer_listener buffer_listener = {
    .release = buffer_event_release
};
// clang-format on

int
buffer_init(struct buffer *buffer, uint32_t w, uint32_t h, struct wl_shm *shm)
{
    int fd = memfd_create("buffer", MFD_CLOEXEC);

    if (fd == -1)
    {
        log_errerror("Error creating buffer");
        return FAIL;
    }

    int32_t stride = cairo_format_stride_for_width(CAIRO_FORMAT_ARGB32, w);
    size_t  sz = stride * h;

    if (ftruncate(fd, sz) == -1)
    {
        log_errerror("Error setting buffer length");
        close(fd);
        return FAIL;
    }

    void *data = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (data == MAP_FAILED)
    {
        log_errerror("mmap() error");
        close(fd);
        return FAIL;
    }

    struct wl_shm_pool *shm_pool = wl_shm_create_pool(shm, fd, sz);

    buffer->buffer = wl_shm_pool_create_buffer(
        shm_pool, 0, w, h, stride, WL_SHM_FORMAT_ARGB8888
    );
    buffer->csurf = cairo_image_surface_create_for_data(
        data, CAIRO_FORMAT_ARGB32, w, h, stride
    );
    buffer->cr = cairo_create(buffer->csurf);

    wl_buffer_add_listener(buffer->buffer, &buffer_listener, buffer);

    buffer->data = data;
    buffer->sz = sz;

    buffer->width = w;
    buffer->height = h;

    buffer->busy = false;

    wl_shm_pool_destroy(shm_pool);
    close(fd);

    return OK;
}

static void
buffer_event_release(void *udata, struct wl_buffer *proxy UNUSED)
{
    struct buffer *buffer = udata;

    buffer->busy = false;
}

void
buffer_uninit(struct buffer *buffer)
{
    if (buffer->cr != NULL)
        cairo_destroy(buffer->cr);
    if (buffer->csurf != NULL)
        cairo_surface_destroy(buffer->csurf);
    if (buffer->buffer != NULL)
        wl_buffer_destroy(buffer->buffer);
    if (buffer->data != NULL)
        munmap(buffer->data, buffer->sz);
    memset(buffer, 0, sizeof(*buffer));
}

/*
 * Return the next non busy buffer to render into. If there are no available
 * buffers, return NULL. If the given width or height does not match the buffer,
 * then create a new buffer.
 */
struct buffer *
buffer_get_next(
    struct buffer buffers[2], struct wl_shm *shm, uint32_t w, uint32_t h
)
{
    struct buffer *buffer = NULL;

    for (int i = 0; i < 2; i++)
    {
        if (!buffers[i].busy)
        {
            buffer = buffers + i;
            break;
        }
    }

    if (buffer == NULL)
        return NULL;

    if (buffer->buffer != NULL && (buffer->width != w || buffer->height != h))
        buffer_uninit(buffer);

    if (buffer->buffer == NULL && buffer_init(buffer, w, h, shm) == FAIL)
        return NULL;

    return buffer;
}
