#include "db.h"
#include <sys/time.h>

static unsigned long hash_bytes(const char *s, size_t len)
{
    unsigned long h = 5381;
    for (size_t i = 0; i < len; i++)
        h = ((h << 5) + h) + (unsigned char)s[i]; // h*33 + c
    return h;
}

int db_init(DB *db, size_t nbuckets)
{
    db->nbuckets = nbuckets;
    db->buckets = (Entry **)calloc(nbuckets, sizeof(Entry *));
    return db->buckets ? 0 : -1;
}

void db_free(DB *db)
{
    if (!db || !db->buckets) return;
    for (size_t i = 0; i < db->nbuckets; i++)
    {
        Entry *e = db->buckets[i];
        while (e)
        {
            Entry *n = e->next;
            free(e->key);
            free(e->val);
            free(e);
            e = n;
        }
    }
    free(db->buckets);
    db->buckets = NULL;
    db->nbuckets = 0;
}

int64_t now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + (int64_t)(tv.tv_usec / 1000);
}

static Entry *db_find(DB *db, const char *key, size_t klen, unsigned long *out_bucket, Entry **out_prev)
{
    unsigned long b = hash_bytes(key, klen) % db->nbuckets;
    if (out_bucket) *out_bucket = b;
    Entry *prev = NULL;
    for (Entry *e = db->buckets[b]; e; e = e->next)
    {
        if (e->klen == klen && memcmp(e->key, key, klen) == 0)
        {
            if (out_prev) *out_prev = prev;
            return e;
        }
        prev = e;
    }
    if (out_prev) *out_prev = prev;
    return NULL;
}

void db_del(DB *db, const char *key, size_t klen)
{
    unsigned long b = 0; Entry *prev = NULL;
    Entry *e = db_find(db, key, klen, &b, &prev);
    if (!e) return;
    if (prev) prev->next = e->next; else db->buckets[b] = e->next;
    free(e->key);
    free(e->val);
    free(e);
}

void db_set(DB *db, const char *key, size_t klen, const char *val, size_t vlen, int64_t expires_at_ms)
{
    unsigned long b = 0; Entry *prev = NULL;
    Entry *e = db_find(db, key, klen, &b, &prev);
    if (e)
    {
        char *nval = malloc(vlen);
        if (!nval) return;
        memcpy(nval, val, vlen);
        free(e->val);
        e->val = nval;
        e->vlen = vlen;
        e->expires_at_ms = expires_at_ms;
        return;
    }
    // New entry
    Entry *ne = (Entry *)calloc(1, sizeof(Entry));
    if (!ne) return;
    ne->key = (char *)malloc(klen);
    ne->val = (char *)malloc(vlen);
    if (!ne->key || (!ne->val && vlen > 0))
    {
        free(ne->key); free(ne->val); free(ne);
        return;
    }
    memcpy(ne->key, key, klen);
    memcpy(ne->val, val, vlen);
    ne->klen = klen;
    ne->vlen = vlen;
    ne->expires_at_ms = expires_at_ms;
    ne->next = db->buckets[b];
    db->buckets[b] = ne;
}

int db_get(DB *db, const char *key, size_t klen, const char **out_val, size_t *out_vlen)
{
    unsigned long b = 0; Entry *prev = NULL;
    Entry *e = db_find(db, key, klen, &b, &prev);
    if (!e) return -1;
    if (e->expires_at_ms > 0 && now_ms() >= e->expires_at_ms)
    {
        // Expired: delete eagerly
        if (prev) prev->next = e->next; else db->buckets[b] = e->next;
        free(e->key); free(e->val); free(e);
        return -1;
    }
    *out_val = e->val;
    *out_vlen = e->vlen;
    return 0;
}
