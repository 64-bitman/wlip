#include "array.h"
#include "unity.h"

void
setUp(void)
{
}

void
tearDown(void)
{
}

/*
 * Test if array is resized properly
 */
static void
test_array_grow(void)
{
    array_T arr;

    array_init(&arr, sizeof(char *), 10);

    // Should grow by "grow_len" items
    array_grow(&arr, 2);
    TEST_ASSERT_EQUAL_UINT32(10, arr.alloc_len);

    // Should grow by 200 items
    for (int i = 0; i < 10; i++)
        ((char **)arr.data)[i] = "hello";
    arr.len = 10;

    array_grow(&arr, 200);
    TEST_ASSERT_EQUAL_UINT32(210, arr.alloc_len);

    for (int i = 0; i < 200; i++)
        ((char **)arr.data)[i] = "hello2";

    array_clear(&arr);
}

/*
 * Test array_append()
 */
static void
test_array_append(void)
{
    array_T arr;

    array_init(&arr, sizeof(char), 8);

    array_append(&arr, "hello %s!", "world");
    array_append(&arr, "Testing %d, %d, %d", 1, 2, 3);
    array_append(&arr, "Hello", 1, 2, 3);

    array_appendc(&arr, 'c');
    array_appendc(&arr, 'o');
    array_appendc(&arr, 'd');

    TEST_ASSERT_EQUAL_STRING("hello world!Testing 1, 2, 3Hellocod", arr.data);

    array_clear(&arr);
}

int
main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_array_grow);
    RUN_TEST(test_array_append);

    return UNITY_END();
}

// vim: ts=4 sw=4 sts=4 et
