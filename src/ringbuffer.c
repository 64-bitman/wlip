#include "ringbuffer.h"
#include "util.h"
#include <assert.h>
#include <sys/uio.h>

/*
 * Initialize ringbuffer_T for use with the given buffer. "size" must be a power
 * of 2 and the actual usable size will be minus one byte.
 */
void
ringbuffer_init(ringbuffer_T *rb, char_u *buf, uint32_t size)
{
    assert(rb != NULL);
    assert(buf != NULL);
    assert((size & (size - 1)) == 0);

    rb->buf = rb->head = rb->tail = buf;
    rb->size = size;
    rb->len = 0;
}

/*
 * Read data from the file descriptor into the buffer. Will attempt to read as
 * much data as possible (so fd should be non blocking). Returns -1 on error and
 * 0 on EOF. Returns -2 if buffer is full.
 */
ssize_t
ringbuffer_read(ringbuffer_T *rb, int fd)
{
    assert(rb != NULL);
    assert(fd >= 0);

    if (rb->len == rb->size - 1)
    {
        return -2;
    }

    struct iovec iov[2];
    int iovlen = 1;

    uint32_t head_offset = rb->head - rb->buf;
    uint32_t tail_offset = rb->tail - rb->buf;

    iov[0].iov_base = rb->tail;
    if (rb->head <= rb->tail)
    {
        // Want to keep one byte free so that we can distingush from empty vs
        // full buffer.
        iov[0].iov_len = MIN(rb->size - tail_offset - 1, rb->size - 1);

        if (head_offset > 0)
        {
            // Extra space behind the head
            iovlen++;
            iov[1].iov_base = rb->buf;
            iov[1].iov_len = head_offset;
        }
    }
    else
        iov[0].iov_len = rb->head - rb->tail;

    ssize_t r = readv(fd, iov, iovlen);

    if (r == -1)
        return -1;
    else if (r == 0)
        return 0;

    // Push tail forwards
    uint32_t new_tail = (tail_offset + r) & (rb->size - 1);

    rb->tail = rb->buf + new_tail;
    rb->len += r;
    assert(rb->head != rb->tail);

    return r;
}

/*
 * Get the data of the ring buffer as two split buffers in order from head to
 * tail. If the ring buffer is contiguous, then region2 will be set to NULL. If
 * buffer is empty, then all are set to NULL.
 */
void
ringbuffer_get(
    ringbuffer_T *rb, const char_u **region1, uint32_t *len1,
    const char_u **region2, uint32_t *len2
)
{
    assert(rb != NULL);
    assert(region1 != NULL);
    assert(region2 != NULL);

    if (rb->len == 0)
    {
        *region1 = *region2 = NULL;
        return;
    }

    uint32_t head_offset = rb->head - rb->buf;
    uint32_t tail_offset = rb->tail - rb->buf;

    *region1 = rb->head;
    if (head_offset < tail_offset)
    {
        *len1 = rb->len;
        *region2 = NULL;
        return;
    }
    else
    {
        *len1 = rb->size - head_offset - 1;
        *region2 = rb->buf;
        *len2 = tail_offset + 1;
    }
}

/*
 * Consume "n" bytes in the ring buffer, and update it accordingly.
 */
void
ringbuffer_consume(ringbuffer_T *rb, uint32_t n)
{
    assert(rb != NULL);

    if (n == 0)
        return;

    // Truncate "n" if it larger than the length
    if (n > rb->len)
        n = rb->len;

    uint32_t new_head = ((rb->head - rb->buf) + n) & (rb->size - 1);

    rb->head = rb->buf + new_head;
    rb->len -= n;
}

// vim: ts=4 sw=4 sts=4 et
