#include "loop.h"
#include "unity.h"
#include "util.h"
#include <signal.h>
#include <stdbool.h>

void
setUp(void)
{
}

void
tearDown(void)
{
    loop_reset();
}

static bool
timer_cb(void *udata)
{
    int64_t *start = udata;
    int64_t elapsed = (get_montonictime_us() / 1000) - *start;

    TEST_ASSERT_GREATER_OR_EQUAL_INT64(100, elapsed);
    TEST_ASSERT_LESS_THAN_INT64(200, elapsed);

    return true;
}

static bool
timer_cb2(void *udata)
{
    int *id = udata;

    TEST_ASSERT_FALSE(loop_timer_active(*id));

    raise(SIGTERM);

    return false;
}

/*
 * Test if timers work correctly in event loop
 */
static void
test_loop_timer(void)
{
    int64_t start = get_montonictime_us() / 1000;

    int id = loop_add_timer(100, timer_cb, &start);
    int id2 = loop_add_timer(200, timer_cb2, &id);

    loop_run();

    int64_t elapsed = (get_montonictime_us() / 1000) - start;
    TEST_ASSERT_GREATER_OR_EQUAL_INT64(200, elapsed);

    TEST_ASSERT_TRUE(loop_timer_active(id2));
    loop_timer_stop(id2);
    TEST_ASSERT_FALSE(loop_timer_active(id2));
}

static char buf[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
static char res[10] = {0};

static bool
prepare_cb(struct pollfd *pfd, int *timeout UNUSED, void *udata UNUSED)
{
    write(pfd->fd, buf, sizeof(buf));

    return true;
}

static bool
check_cb(struct pollfd *pfd, void *udata UNUSED)
{
    read(pfd->fd, res, 10);
    raise(SIGTERM);

    return true;
}

/*
 * Test if polling fds work correctly in event loop
 */
static void
test_loop_fd(void)
{
    int fds[2];

    TEST_ASSERT_EQUAL_INT(0, pipe(fds));

    loop_add_fd(fds[0], POLLIN, NULL, check_cb, NULL);
    loop_add_fd(fds[1], POLLOUT, prepare_cb, NULL, NULL);

    loop_run();

    TEST_ASSERT_EQUAL_CHAR_ARRAY(buf, res, 10);

    close(fds[0]);
    close(fds[1]);
}

int
main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_loop_timer);
    RUN_TEST(test_loop_fd);

    return UNITY_END();
}

// vim: ts=4 sw=4 sts=4 et
