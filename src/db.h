#pragma once
#include "common.h"

typedef enum { OBJ_STRING = 0, OBJ_LIST = 1 } ObjType;

typedef struct ListNode {
    struct ListNode *prev, *next;
    char *val; size_t vlen;
} ListNode;

typedef struct List {
    ListNode *head, *tail;
    size_t len;
} List;

typedef struct Entry {
    char *key; size_t klen;
    ObjType type;
    union {
        struct { char *ptr; size_t len; } str;
        List list;
    } data;
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

// Lists
int db_list_rpush(DB *db, const char *key, size_t klen, const char *elem, size_t elen, size_t *out_len, int *wrongtype);
int db_list_lpush(DB *db, const char *key, size_t klen, const char *elem, size_t elen, size_t *out_len, int *wrongtype);
int db_list_range_count(DB *db, const char *key, size_t klen, long start, long stop, size_t *out_n, int *wrongtype);
typedef int (*db_emit_cb)(void *ctx, const char *val, size_t vlen);
int db_list_range_emit(DB *db, const char *key, size_t klen, long start, long stop, db_emit_cb emit, void *ctx, int *wrongtype);
