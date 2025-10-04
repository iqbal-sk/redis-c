#pragma once
#include "common.h"

typedef struct Entry {
    char *key; size_t klen;
    char *val; size_t vlen;
    int64_t expires_at_ms; // 0 => no expiry
    struct Entry *next;
} Entry;

typedef struct DB {
    Entry **buckets;
    size_t nbuckets;
} DB;

int db_init(DB *db, size_t nbuckets);
void db_free(DB *db);

void db_set(DB *db, const char *key, size_t klen, const char *val, size_t vlen, int64_t expires_at_ms);
int db_get(DB *db, const char *key, size_t klen, const char **out_val, size_t *out_vlen);
void db_del(DB *db, const char *key, size_t klen);

int64_t now_ms(void);

