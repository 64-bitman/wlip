#include "hashtable.h"
#include "alloc.h"
#include <assert.h>
#include <stdbool.h>
#include <string.h>

#define FNV_OFFSET_BASIS 0x811c9dc5
#define FNV_PRIME 0x01000193

static const char *TOMBSTONE_MARKER = "";

/*
 * Generate a hash for the given string
 */
hash_T
hash_get(const char *key)
{
    hash_T hash = FNV_OFFSET_BASIS;

    // FNV-1a hash function
    for (uint8_t c = *(uint8_t *)key; c != 0; c = *(uint8_t *)(++key))
    {
        hash ^= (hash_T)c;
        hash *= FNV_PRIME;
    }
    return hash;
}

/*
 * Initialize the given hash table and pre allocate memory for it
 */
void
hashtable_init(hashtable_T *self)
{
    assert(self != NULL);

    self->buckets = wlip_calloc(HASHTABLE_INITIAL_LEN, sizeof(hashbucket_T));
    self->len = 0;
    self->tombstones_len = 0;
    self->alloc_len = HASHTABLE_INITIAL_LEN;
    self->no_resize = false;
}

/*
 * Free memory holding the hash table items. Does not free the hash table
 * struct itself.
 */
void
hashtable_clear(hashtable_T *self)
{
    assert(self != NULL);

    wlip_free(self->buckets);
}

/*
 * Same as hashtable_clear(), but also frees any items as well. "offset" must be
 * the offset of the key member within the item struct.
 */
void
hashtable_clear_all(hashtable_T *self, uint32_t offset)
{
    assert(self != NULL);

    hashtableiter_T iter = HASHTABLEITER_INIT(self);
    void *item;

    while ((item = hashtableiter_next(&iter, offset)) != NULL)
        wlip_free(item);

    hashtable_clear(self);
}

/*
 * Free the hashtable memory block and call "func" on all occupied buckets.
 * "offset" is same as in hashtable_clear_all().
 */
void
hashtable_clear_func(hashtable_T *self, hb_free_func func, uint32_t offset)
{
    assert(self != NULL);
    assert(func != NULL);

    hashtableiter_T iter = HASHTABLEITER_INIT(self);
    void *item;

    while ((item = hashtableiter_next(&iter, offset)) != NULL)
        func(item);

    hashtable_clear(self);
}

/*
 * Get a bucket from the hash table for the given key. If the key does not exist
 * in the hash table, then an empty bucket will be returned, which may be
 * populated and passed to hashtable_add().
 */
hashbucket_T *
hashtable_lookup(hashtable_T *self, const char *key, hash_T hash)
{
    assert(self != NULL);
    assert(key != NULL);

    uint32_t idx = hash & (self->alloc_len - 1);
    hashbucket_T *bucket = self->buckets + idx;
    hashbucket_T *first_tomb = NULL; // Used when key does not exist, use the
                                     // first tombstone (if any).

    while (bucket->key != NULL)
    {
        if (bucket->key != NULL && strcmp(bucket->key, key) == 0)
            return bucket;
        else if (first_tomb == NULL && *bucket->key == 0)
            first_tomb = bucket;

        // Make sure to wrap around
        idx = (idx + 1) & (self->alloc_len - 1);
        bucket = self->buckets + idx;
    }

    return first_tomb != NULL ? first_tomb : bucket;
}

/*
 * Resize the hash table depending on load. Returns true if resized, otherfalse
 * false.
 */
static void
hashtable_resize(hashtable_T *self)
{
    assert(self != NULL);
    
    if (self->no_resize)
        return;

    uint32_t new_alloc;

    // Increase size at a load of 50%, rehash when full load is 70%, and shrink
    // when load is 20%.
    if (self->len * 10 >= self->alloc_len * 5)
        new_alloc = self->alloc_len * 2;
    else if ((self->len + self->tombstones_len) * 10 >= self->alloc_len * 7)
        new_alloc = self->alloc_len;
    else if (self->alloc_len > HASHTABLE_INITIAL_LEN &&
             self->len * 10 <= self->alloc_len * 2)
        new_alloc = self->alloc_len / 2;
    else
        return;

    hashbucket_T *old_buckets = self->buckets;
    uint32_t old_len = self->alloc_len;
    uint32_t found = 0;

    self->alloc_len = new_alloc;
    self->tombstones_len = 0;
    self->buckets = wlip_calloc(self->alloc_len, sizeof(hashbucket_T));

    for (uint32_t i = 0; i < old_len && self->len > found; i++)
    {
        hashbucket_T *old = old_buckets + i;

        if (HB_ISEMPTY(old))
            continue;

        hashbucket_T *new = hashtable_lookup(self, old->key, old->hash);

        new->key = old->key;
        new->hash = old->hash;
        found++;
    }

    wlip_free(old_buckets);
    return;
}

/*
 * Add a bucket to the hash table. The bucket must be initially empty. "key" may
 * not be an empty string.
 */
void
hashtable_add(hashtable_T *self, hashbucket_T *bucket, char *key, hash_T hash)
{
    assert(self != NULL);
    assert(HB_ISEMPTY(bucket));
    assert(key != NULL);
    assert(*key != 0);

    if (bucket->key != NULL && *bucket->key == 0)
        self->tombstones_len--;

    bucket->hash = hash;
    bucket->key = key;
    self->len++;
    hashtable_resize(self);
}

/*
 * Remove a bucket from the hash table. Returns true if resized.
 */
void
hashtable_remove_bucket(hashtable_T *self, hashbucket_T *bucket)
{
    assert(self != NULL);
    assert(bucket != NULL);
    assert(!HB_ISEMPTY(bucket));

    bucket->key = (char *)TOMBSTONE_MARKER;
    self->tombstones_len++;
    self->len--;

    hashtable_resize(self);
}

/*
 * Same as hashtable_remove_bucket(), but takes care of calculating hash and
 * finding the bucket. Returns the actual key in the item if found, else NULL.
 */
char *
hashtable_remove(hashtable_T *self, const char *key)
{
    assert(self != NULL);
    assert(key != NULL);

    hash_T hash = hash_get(key);
    hashbucket_T *bucket = hashtable_lookup(self, key, hash);

    if (HB_ISEMPTY(bucket))
        return NULL;

    char *item_key = bucket->key;

    hashtable_remove_bucket(self, bucket);

    return item_key;
}

/*
 * Return the next item in the hash table. Returns NULL if there are no more
 * occupied buckets. "offset" must be the offset of the key member within the
 * item struct.
 */
void *
hashtableiter_next(hashtableiter_T *self, uint32_t offset)
{
    assert(self != NULL);

    if (self->found >= self->ht->len)
    {
        // We may have disabled resizing
        hashtable_resize(self->ht);
        return NULL;
    }

    hashbucket_T *bucket = self->ht->buckets + self->i;

    while (HB_ISEMPTY(bucket))
    {
        if (++self->i >= self->ht->alloc_len)
        {
            hashtable_resize(self->ht);
            return NULL;
        }
        bucket = self->ht->buckets + self->i;
    }
    self->found++;
    self->i++;
    return bucket->key - offset;
}

/*
 * Remove the current bucket that the hashtableiter is on from the hash table.
 * Note that freeing the key must happen AFTER this function call.
 */
void
hashtableiter_remove(hashtableiter_T *self)
{
    assert(self != NULL);

    hashbucket_T *bucket = self->ht->buckets + self->i - 1;
    self->found--;
    self->ht->no_resize = true;
    hashtable_remove_bucket(self->ht, bucket);
    self->ht->no_resize = false;
}

// vim: ts=4 sw=4 sts=4 et
