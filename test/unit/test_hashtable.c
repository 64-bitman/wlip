#include "alloc.h"
#include "hashtable.h"
#include "unity.h"
#include "util.h"
#include <stddef.h>
#include <stdlib.h>
#include <sys/random.h>

void
setUp(void)
{
}

void
tearDown(void)
{
}

typedef struct
{
    int val;
    char key[100];
} item_T;

/*
 * Test add, lookup, and remove operations on hash table
 */
static void
test_hashtable_basic(void)
{
    hashtable_T table;

    hashtable_init(&table, 0);

    // Testing adding
    for (int i = 0; i < 200; i++)
    {
        item_T *item = wlip_malloc(sizeof(item_T));

        wlip_snprintf(item->key, 100, "%d", i);

        item->val = i;

        hash_T hash = hash_get(item->key);
        hashbucket_T *b = hashtable_lookup(&table, item->key, hash);

        hashtable_add(&table, b, item->key, hash);
    }

    TEST_ASSERT_EQUAL_UINT32(200, table.len);
    TEST_ASSERT_EQUAL_UINT32(0, table.tombstones_len);

    char buf[100];

    // Test lookup
    for (int i = 0; i < 200; i++)
    {
        wlip_snprintf(buf, 100, "%d", i);
        hashbucket_T *b = hashtable_lookup(&table, buf, hash_get(buf));
        item_T *item = HB_GET(b, item_T, key);

        TEST_ASSERT_EQUAL_INT(item->val, i);
    }

    // Test removing
    for (int i = 0; i < 20; i++)
    {
        wlip_snprintf(buf, 100, "%d", i);
        char *s = hashtable_remove(&table, buf, 0);

        TEST_ASSERT_EQUAL_STRING(buf, s);

        wlip_free(HBKEY_GET(s, item_T, key));
    }

    TEST_ASSERT_EQUAL_UINT32(20, table.tombstones_len);

    hashtable_clear_all(&table, offsetof(item_T, key));
}

/*
 * Test if hash table resizes correctly and also rehashes correctly
 */
static void
test_hashtable_resize(void)
{
    hashtable_T table;

    hashtable_init(&table, 0);

    for (int i = 0; i < 20000; i++)
    {
        char *key = wlip_strdup_printf("%d", i);
        hash_T hash = hash_get(key);
        hashbucket_T *b = hashtable_lookup(&table, key, hash);

        hashtable_add(&table, b, key, hash);
    }

    TEST_ASSERT_EQUAL_UINT32(32768, table.alloc_len);

    // Remove a bunch of entries and add a bunch back again to see if table
    // shrinks.
    for (int i = 0; i < 15000; i++)
    {
        char *key = wlip_strdup_printf("%d", i);

        wlip_free(hashtable_remove(&table, key, 0));
        wlip_free(key);
    }

    TEST_ASSERT_EQUAL_UINT32(16384, table.alloc_len);

    hashtable_clear_all(&table, 0);
}

/*
 * Test hash table iterator
 */
static void
test_hashtable_iter(void)
{
    hashtable_T table;

    hashtable_init(&table, 0);

    for (int i = 0; i < 10; i++)
    {
        char *key = wlip_strdup_printf("%d", i);
        hash_T hash = hash_get(key);
        hashbucket_T *b = hashtable_lookup(&table, key, hash);

        hashtable_add(&table, b, key, hash);
    }

    hashtableiter_T iter = HASHTABLEITER_INIT(&table);

    for (int i = 0; i < 10; i++)
    {
        char *key = hashtableiter_next(&iter, 0);

        TEST_ASSERT_NOT_NULL(key);

        long d = strtol(key, NULL, 10);

        TEST_ASSERT_GREATER_THAN_INT(d, 10);
        TEST_ASSERT_LESS_OR_EQUAL_INT(d, 0);

        hashtableiter_remove(&iter);
        wlip_free(key);
    }

    hashtable_clear_all(&table, 0);
}

/*
 * Test if hash table works with arbitrary binary keys
 */
static void
test_hashtable_binary(void)
{
    hashtable_T table;

    hashtable_init(&table, 16);

    uint8_t buf[16];
    getrandom(buf, 16, 0);

    hash_T hash = hash_get_len(buf, 16);
    hashbucket_T *b = hashtable_lookup_bin(&table, buf, hash);

    hashtable_add_bin(&table, b, buf, hash);

    b = hashtable_lookup_bin(&table, buf, hash);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(buf, b->key, 16);

    hashtable_remove_bin(&table, buf, 0);
    b = hashtable_lookup_bin(&table, buf, hash);
    TEST_ASSERT_EQUAL_PTR(&TOMBSTONE_MARKER, b->key);
    hashtable_clear(&table);
}

int
main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_hashtable_basic);
    RUN_TEST(test_hashtable_resize);
    RUN_TEST(test_hashtable_iter);
    RUN_TEST(test_hashtable_binary);

    return UNITY_END();
}

// vim: ts=4 sw=4 sts=4 et
