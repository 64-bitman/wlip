#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint32_t hash_T;

typedef struct
{
    hash_T hash; // Cached hash number
    char *key;   // Pointer to key, which is inside the actual struct of the
                 // item. An offset is used to get the item struct. If an empty
                 // string, then bucket is a tombstone.
} hashbucket_T;

typedef void (*hb_free_func)(void *);

// Check if bucket is empty (is able to be used)
#define HB_ISEMPTY(hb) ((hb)->key == NULL || *((hb)->key) == 0)

// Get the item struct from a bucket or key from bucket
#define HBKEY_GET(key, s, keyname) ((s *)((key) - offsetof(s, keyname)))
#define HB_GET(hb, s, keyname) HBKEY_GET(hb->key, s, keyname)

// Hash table implementation. Uses FNV-1a hash function and open addressed
// linear probing.
typedef struct
{
    hashbucket_T *buckets;
    uint32_t len;            // Number of used items
    uint32_t tombstones_len; // Number of tombstones
    uint32_t alloc_len;      // Allocated length, always a power of 2
    bool no_resize;          // Don't resize when removing, adding.
} hashtable_T;

// Struct to iterate through a hash table
typedef struct
{
    hashtable_T *ht;
    uint32_t found; // Number of occupied buckets found so far
    uint32_t i;     // Current index
} hashtableiter_T;

#define HASHTABLE_INITIAL_LEN 16

#define HASHTABLEITER_INIT(ht) {ht, 0, 0}

hash_T hash_get(const char *key);

void hashtable_init(hashtable_T *self);
void hashtable_clear(hashtable_T *self);
void hashtable_clear_all(hashtable_T *self, uint32_t offset);
void
hashtable_clear_func(hashtable_T *self, hb_free_func func, uint32_t offset);

hashbucket_T *hashtable_lookup(hashtable_T *self, const char *key, hash_T hash);
void
hashtable_add(hashtable_T *self, hashbucket_T *bucket, char *key, hash_T hash);
void hashtable_remove_bucket(hashtable_T *self, hashbucket_T *bucket);
char *hashtable_remove(hashtable_T *self, const char *key);

void *hashtableiter_next(hashtableiter_T *self, uint32_t offset);
void hashtableiter_remove(hashtableiter_T *self);

// vim: ts=4 sw=4 sts=4 et
