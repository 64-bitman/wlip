#include "clipboard.h"
#include "database.h"
#include "unity.h"
#include <sqlite3.h>

void
setUp(void)
{
    clipboard_new("Default");
    clipboard_new("Secondary");
}

void
tearDown(void)
{
    free_clipboards();
    database_uninit();
}

/*
 * Test if entry can be serialized and deserialized correctly.
 */
static void
test_entry_operation(void)
{
}

int
main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_entry_operation);

    return UNITY_END();
}

// vim: ts=4 sw=4 sts=4 et
