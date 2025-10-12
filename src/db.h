#pragma once
#include "common.h"

typedef enum
{
    OBJ_STRING = 0,
    OBJ_LIST = 1,
    OBJ_STREAM = 2
} ObjType;

typedef struct ListNode
{
    struct ListNode *prev, *next;
    char *val;
    size_t vlen;
} ListNode;

typedef struct List
{
    ListNode *head, *tail;
    size_t len;
} List;

typedef struct Entry
{
    char *key;
    size_t klen;
    ObjType type;
    union
    {
        struct
        {
            char *ptr;
            size_t len;
        } str;
        List list;
        struct Stream {
            struct StreamEntry *head, *tail;
            size_t len;
        } stream;
    } data;
    int64_t expires_at_ms; // 0 => no expiry
    struct Entry *next;
} Entry;

typedef struct DB
{
    Entry **buckets;
    size_t nbuckets;
} DB;

int db_init(DB *db, size_t nbuckets);
void db_free(DB *db);

void db_set(DB *db, const char *key, size_t klen, const char *val, size_t vlen, int64_t expires_at_ms);
int db_get(DB *db, const char *key, size_t klen, const char **out_val, size_t *out_vlen);
void db_del(DB *db, const char *key, size_t klen);
// Query the type of a key. Sets *found=1 and *out_type when present and not expired,
// otherwise sets *found=0. Returns 0 on success.
int db_type(DB *db, const char *key, size_t klen, ObjType *out_type, int *found);

int64_t now_ms(void);

// Lists
int db_list_rpush(DB *db, const char *key, size_t klen, const char *elem, size_t elen, size_t *out_len, int *wrongtype);
int db_list_lpush(DB *db, const char *key, size_t klen, const char *elem, size_t elen, size_t *out_len, int *wrongtype);
int db_list_lpop(DB *db, const char *key, size_t klen, char **out_val, size_t *out_vlen, int *wrongtype);
int db_list_range_count(DB *db, const char *key, size_t klen, long start, long stop, size_t *out_n, int *wrongtype);
typedef int (*db_emit_cb)(void *ctx, const char *val, size_t vlen);
int db_list_range_emit(DB *db, const char *key, size_t klen, long start, long stop, db_emit_cb emit, void *ctx, int *wrongtype);
int db_list_length(DB *db, const char *key, size_t klen, size_t *out_len, int *wrongtype);

// Streams
int db_stream_xadd(DB *db, const char *key, size_t klen,
                   const char *id, size_t idlen,
                   const char **fkeys, const size_t *fklen,
                   const char **fvals, const size_t *fvlen,
                   size_t npairs,
                   int *wrongtype,
                   // Optional out params: point to the stored ID buffer for the new entry
                   const char **out_id, size_t *out_idlen);

// Streams read helpers (XRANGE)
typedef int (*db_stream_emit_cb)(void *ctx,
                                 const char *id, size_t idlen,
                                 const char **fkeys, const size_t *fklen,
                                 const char **fvals, const size_t *fvlen,
                                 size_t npairs);
int db_stream_xrange_count(DB *db, const char *key, size_t klen,
                           uint64_t start_ms, uint64_t start_seq,
                           uint64_t end_ms, uint64_t end_seq,
                           size_t *out_n, int *wrongtype);
int db_stream_xrange_emit(DB *db, const char *key, size_t klen,
                          uint64_t start_ms, uint64_t start_seq,
                          uint64_t end_ms, uint64_t end_seq,
                          db_stream_emit_cb emit, void *ctx,
                          int *wrongtype);

// Get last entry ID of a stream (tail). Sets *found=1 and outputs ms/seq.
// If key missing or stream empty, sets *found=0. Returns 0 on success.
int db_stream_last_id(DB *db, const char *key, size_t klen,
                      uint64_t *out_ms, uint64_t *out_seq,
                      int *found, int *wrongtype);
