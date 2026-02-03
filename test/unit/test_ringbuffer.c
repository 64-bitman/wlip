#include "ringbuffer.h"
#include "unity.h"
#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>

void
setUp(void)
{
}

void
tearDown(void)
{
}

/*
 * Test if ring buffer reads correctly.
 */
static void
test_ringbuffer_read(void)
{
    int fds[2];

    TEST_ASSERT_EQUAL_INT(0, pipe(fds));

    int r_fd = fds[0], w_fd = fds[1];
    char buf[16];
    ringbuffer_T rb;

    fcntl(r_fd, F_SETFL, fcntl(r_fd, F_GETFL, 0) | O_NONBLOCK);
    ringbuffer_init(&rb, (uint8_t *)buf, 16);

    dprintf(
        w_fd, "Hello world! One, Two, Three, Four, Five, Six, Seven, Eight, "
              "Nine, Ten.\n"
    );

    const char *region1, *region2;
    uint32_t len1, len2;

    ringbuffer_read(&rb, r_fd);
    TEST_ASSERT_EQUAL_STRING("Hello world! On", buf);
    ringbuffer_get(
        &rb, (const uint8_t **)&region1, &len1, (const uint8_t **)&region2, &len2
    );
    TEST_ASSERT_EQUAL_STRING("Hello world! On", region1);
    TEST_ASSERT_NULL(region2);
    TEST_ASSERT_EQUAL_UINT32(rb.size - 1, rb.len);

    ringbuffer_consume(&rb, 10);
    ringbuffer_get(
        &rb, (const uint8_t **)&region1, &len1, (const uint8_t **)&region2, &len2
    );
    TEST_ASSERT_EQUAL_STRING("d! On", region1);
    TEST_ASSERT_NULL(region2);

    ringbuffer_read(&rb, r_fd);
    TEST_ASSERT_EQUAL_STRING("e, Two, Thd! On", buf);
    ringbuffer_get(
        &rb, (const uint8_t **)&region1, &len1, (const uint8_t **)&region2, &len2
    );
    TEST_ASSERT_EQUAL_STRING("d! On", region1);
    TEST_ASSERT_EQUAL_STRING_LEN("e, Two, Th", region2, 10);

    ringbuffer_consume(&rb, 100);
    ringbuffer_get(
        &rb, (const uint8_t **)&region1, &len1, (const uint8_t **)&region2, &len2
    );
    TEST_ASSERT_NULL(region1);
    TEST_ASSERT_NULL(region2);

    while (ringbuffer_read(&rb, r_fd) != -1)
        ringbuffer_consume(&rb, 15);

    close(fds[0]);
    close(fds[1]);
}

int
main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_ringbuffer_read);

    return UNITY_END();
}

// vim: ts=4 sw=4 sts=4 et
