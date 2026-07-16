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
buffer_pool_init(
    struct buffer_pool *pool, uint32_t w, uint32_t h, struct wl_shm *shm
)
{
    int fd = memfd_create("buffer", MFD_CLOEXEC);

    if (fd == -1)
    {
        log_errerror("Error creating buffer");
        return FAIL;
    }

    int32_t stride = cairo_format_stride_for_width(CAIRO_FORMAT_ARGB32, w);
    size_t  sz = stride * h;
    size_t  total_sz = sz * 2;

    if (total_sz > INT32_MAX)
    {
        log_errerror("Total size of buffers exceeds INT32_MAX");
        close(fd);
        return FAIL;
    }

    if (ftruncate(fd, total_sz) == -1)
    {
        log_errerror("Error setting buffer length");
        close(fd);
        return FAIL;
    }

    void *data =
        mmap(NULL, total_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (data == MAP_FAILED)
    {
        log_errerror("mmap() error");
        return FAIL;
    }

    struct wl_shm_pool *shm_pool = wl_shm_create_pool(shm, fd, total_sz);

    for (int i = 0; i < 2; i++)
    {
        struct buffer *buffer = pool->buffers + i;
        int32_t        off = (int32_t)sz * i;

        buffer->buffer = wl_shm_pool_create_buffer(
            shm_pool, off, w, h, stride, WL_SHM_FORMAT_ARGB8888
        );
        buffer->csurf = cairo_image_surface_create_for_data(
            data + off, CAIRO_FORMAT_ARGB32, w, h, stride
        );
        buffer->cr = cairo_create(buffer->csurf);

        wl_buffer_add_listener(buffer->buffer, &buffer_listener, buffer);

        buffer->busy = false;
    }

    pool->data = data;
    pool->sz = total_sz;

    pool->width = w;
    pool->height = h;
    pool->cur = pool->buffers;

    wl_shm_pool_destroy(shm_pool);
    close(fd);

    return OK;
}

void
buffer_pool_uninit(struct buffer_pool *pool)
{
    for (int i = 0; i < 2; i++)
    {
        struct buffer *buffer = pool->buffers + i;

        cairo_destroy(buffer->cr);
        cairo_surface_destroy(buffer->csurf);
        wl_buffer_destroy(buffer->buffer);
    }

    munmap(pool->data, pool->sz);
}

static void
buffer_event_release(void *udata, struct wl_buffer *proxy UNUSED)
{
    struct buffer *buffer = udata;

    buffer->busy = false;
}
