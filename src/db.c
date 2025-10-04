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

static void list_free(List *lst)
{
    ListNode *n = lst->head;
    while (n)
    {
        ListNode *nx = n->next;
        free(n->val);
        free(n);
        n = nx;
    }
    lst->head = lst->tail = NULL;
    lst->len = 0;
}

void db_free(DB *db)
{
    if (!db || !db->buckets)
        return;
    for (size_t i = 0; i < db->nbuckets; i++)
    {
        Entry *e = db->buckets[i];
        while (e)
        {
            Entry *n = e->next;
            free(e->key);
            if (e->type == OBJ_STRING)
            {
                free(e->data.str.ptr);
            }
            else if (e->type == OBJ_LIST)
            {
                list_free(&e->data.list);
            }
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
    if (out_bucket)
        *out_bucket = b;
    Entry *prev = NULL;
    for (Entry *e = db->buckets[b]; e; e = e->next)
    {
        if (e->klen == klen && memcmp(e->key, key, klen) == 0)
        {
            if (out_prev)
                *out_prev = prev;
            return e;
        }
        prev = e;
    }
    if (out_prev)
        *out_prev = prev;
    return NULL;
}

void db_del(DB *db, const char *key, size_t klen)
{
    unsigned long b = 0;
    Entry *prev = NULL;
    Entry *e = db_find(db, key, klen, &b, &prev);
    if (!e)
        return;
    if (prev)
        prev->next = e->next;
    else
        db->buckets[b] = e->next;
    free(e->key);
    if (e->type == OBJ_STRING)
        free(e->data.str.ptr);
    else if (e->type == OBJ_LIST)
        list_free(&e->data.list);
    free(e);
}

void db_set(DB *db, const char *key, size_t klen, const char *val, size_t vlen, int64_t expires_at_ms)
{
    unsigned long b = 0;
    Entry *prev = NULL;
    Entry *e = db_find(db, key, klen, &b, &prev);
    if (e)
    {
        char *nval = malloc(vlen);
        if (!nval)
            return;
        memcpy(nval, val, vlen);
        if (e->type == OBJ_STRING)
        {
            free(e->data.str.ptr);
        }
        else if (e->type == OBJ_LIST)
        {
            list_free(&e->data.list);
        }
        e->type = OBJ_STRING;
        e->data.str.ptr = nval;
        e->data.str.len = vlen;
        e->expires_at_ms = expires_at_ms;
        return;
    }
    // New entry
    Entry *ne = (Entry *)calloc(1, sizeof(Entry));
    if (!ne)
        return;
    ne->key = (char *)malloc(klen);
    ne->data.str.ptr = (char *)malloc(vlen);
    if (!ne->key || (!ne->data.str.ptr && vlen > 0))
    {
        free(ne->key);
        free(ne->data.str.ptr);
        free(ne);
        return;
    }
    memcpy(ne->key, key, klen);
    memcpy(ne->data.str.ptr, val, vlen);
    ne->klen = klen;
    ne->type = OBJ_STRING;
    ne->data.str.len = vlen;
    ne->expires_at_ms = expires_at_ms;
    ne->next = db->buckets[b];
    db->buckets[b] = ne;
}

int db_get(DB *db, const char *key, size_t klen, const char **out_val, size_t *out_vlen)
{
    unsigned long b = 0;
    Entry *prev = NULL;
    Entry *e = db_find(db, key, klen, &b, &prev);
    if (!e)
        return -1;
    if (e->expires_at_ms > 0 && now_ms() >= e->expires_at_ms)
    {
        // Expired: delete eagerly
        if (prev)
            prev->next = e->next;
        else
            db->buckets[b] = e->next;
        free(e->key);
        if (e->type == OBJ_STRING)
            free(e->data.str.ptr);
        else if (e->type == OBJ_LIST)
            list_free(&e->data.list);
        free(e);
        return -1;
    }
    if (e->type != OBJ_STRING)
        return -1; // wrong type for GET (treat as missing for now)
    *out_val = e->data.str.ptr;
    *out_vlen = e->data.str.len;
    return 0;
}

int db_list_rpush(DB *db, const char *key, size_t klen, const char *elem, size_t elen, size_t *out_len, int *wrongtype)
{
    if (wrongtype)
        *wrongtype = 0;
    unsigned long b = 0;
    Entry *prev = NULL;
    Entry *e = db_find(db, key, klen, &b, &prev);
    if (!e)
    {
        // Create new list and add one element
        Entry *ne = (Entry *)calloc(1, sizeof(Entry));
        if (!ne)
            return -1;
        ne->key = (char *)malloc(klen);
        if (!ne->key)
        {
            free(ne);
            return -1;
        }
        memcpy(ne->key, key, klen);
        ne->klen = klen;
        ne->type = OBJ_LIST;
        ne->expires_at_ms = 0;
        ne->data.list.head = ne->data.list.tail = NULL;
        ne->data.list.len = 0;

        ListNode *node = (ListNode *)calloc(1, sizeof(ListNode));
        if (!node)
        {
            free(ne->key);
            free(ne);
            return -1;
        }
        node->val = (char *)malloc(elen);
        if (!node->val && elen > 0)
        {
            free(node);
            free(ne->key);
            free(ne);
            return -1;
        }
        if (elen > 0)
            memcpy(node->val, elem, elen);
        node->vlen = elen;
        node->prev = ne->data.list.tail;
        node->next = NULL;
        ne->data.list.head = ne->data.list.tail = node;
        ne->data.list.len = 1;

        ne->next = db->buckets[b];
        db->buckets[b] = ne;
        if (out_len)
            *out_len = 1;
        return 0;
    }
    // Existing key
    if (e->type != OBJ_LIST)
    {
        if (wrongtype)
            *wrongtype = 1;
        return -1;
    }
    // Append one element to list
    ListNode *node = (ListNode *)calloc(1, sizeof(ListNode));
    if (!node)
        return -1;
    node->val = (char *)malloc(elen);
    if (!node->val && elen > 0)
    {
        free(node);
        return -1;
    }
    if (elen > 0)
        memcpy(node->val, elem, elen);
    node->vlen = elen;
    node->prev = e->data.list.tail;
    node->next = NULL;
    if (e->data.list.tail)
        e->data.list.tail->next = node;
    else
        e->data.list.head = node;
    e->data.list.tail = node;
    e->data.list.len++;
    if (out_len)
        *out_len = e->data.list.len;
    return 0;
}

int db_list_lpush(DB *db, const char *key, size_t klen, const char *elem, size_t elen, size_t *out_len, int *wrongtype)
{
    if (wrongtype)
        *wrongtype = 0;
    unsigned long b = 0;
    Entry *prev = NULL;
    Entry *e = db_find(db, key, klen, &b, &prev);
    if (!e)
    {
        // Create new list and add one element at head
        Entry *ne = (Entry *)calloc(1, sizeof(Entry));
        if (!ne)
            return -1;
        ne->key = (char *)malloc(klen);
        if (!ne->key)
        {
            free(ne);
            return -1;
        }
        memcpy(ne->key, key, klen);
        ne->klen = klen;
        ne->type = OBJ_LIST;
        ne->expires_at_ms = 0;
        ne->data.list.head = ne->data.list.tail = NULL;
        ne->data.list.len = 0;

        ListNode *node = (ListNode *)calloc(1, sizeof(ListNode));
        if (!node)
        {
            free(ne->key);
            free(ne);
            return -1;
        }
        node->val = (char *)malloc(elen);
        if (!node->val && elen > 0)
        {
            free(node);
            free(ne->key);
            free(ne);
            return -1;
        }
        if (elen > 0)
            memcpy(node->val, elem, elen);
        node->vlen = elen;
        node->prev = NULL;
        node->next = ne->data.list.head;
        ne->data.list.head = ne->data.list.tail = node;
        ne->data.list.len = 1;

        ne->next = db->buckets[b];
        db->buckets[b] = ne;
        if (out_len)
            *out_len = 1;
        return 0;
    }
    // Existing key
    if (e->type != OBJ_LIST)
    {
        if (wrongtype)
            *wrongtype = 1;
        return -1;
    }
    // Prepend one element to list
    ListNode *node = (ListNode *)calloc(1, sizeof(ListNode));
    if (!node)
        return -1;
    node->val = (char *)malloc(elen);
    if (!node->val && elen > 0)
    {
        free(node);
        return -1;
    }
    if (elen > 0)
        memcpy(node->val, elem, elen);
    node->vlen = elen;
    node->prev = NULL;
    node->next = e->data.list.head;
    if (e->data.list.head)
        e->data.list.head->prev = node;
    else
        e->data.list.tail = node;
    e->data.list.head = node;
    e->data.list.len++;
    if (out_len)
        *out_len = e->data.list.len;
    return 0;
}

static size_t list_len(const List *lst)
{
    return lst->len;
}

int db_list_range_count(DB *db, const char *key, size_t klen, long start, long stop, size_t *out_n, int *wrongtype)
{
    if (wrongtype)
        *wrongtype = 0;
    if (out_n)
        *out_n = 0;
    unsigned long b = 0;
    Entry *prev = NULL;
    Entry *e = db_find(db, key, klen, &b, &prev);
    if (!e)
    {
        if (out_n)
            *out_n = 0;
        return 0;
    }
    if (e->type != OBJ_LIST)
    {
        if (wrongtype)
            *wrongtype = 1;
        return -1;
    }
    size_t len = list_len(&e->data.list);
    long s = start;
    long t = stop;
    if (s < 0)
        s = (long)len + s;
    if (t < 0)
        t = (long)len + t;
    if (s < 0)
        s = 0;
    if (t < 0)
        t = 0; // out-of-range negatives treated as 0
    if ((size_t)s >= len)
    {
        if (out_n)
            *out_n = 0;
        return 0;
    }
    if ((size_t)t >= len)
        t = (long)len - 1;
    if (s > t)
    {
        if (out_n)
            *out_n = 0;
        return 0;
    }
    if (out_n)
        *out_n = (size_t)(t - s + 1);
    return 0;
}

int db_list_range_emit(DB *db, const char *key, size_t klen, long start, long stop, db_emit_cb emit, void *ctx, int *wrongtype)
{
    if (wrongtype)
        *wrongtype = 0;
    if (!emit)
        return 0;
    unsigned long b = 0;
    Entry *prev = NULL;
    Entry *e = db_find(db, key, klen, &b, &prev);
    if (!e)
        return 0;
    if (e->type != OBJ_LIST)
    {
        if (wrongtype)
            *wrongtype = 1;
        return -1;
    }
    size_t len = e->data.list.len;
    long s = start;
    long t = stop;
    if (s < 0)
        s = (long)len + s;
    if (t < 0)
        t = (long)len + t;
    if (s < 0)
        s = 0;
    if (t < 0)
        t = 0;
    if ((size_t)s >= len)
        return 0;
    if ((size_t)t >= len)
        t = (long)len - 1;
    if (s > t)
        return 0;

    // Walk to start index
    ListNode *n = e->data.list.head;
    long idx = 0;
    while (n && idx < s)
    {
        n = n->next;
        idx++;
    }
    while (n && idx <= t)
    {
        if (emit(ctx, n->val, n->vlen) != 0)
            return -1;
        n = n->next;
        idx++;
    }
    return 0;
}

int db_list_length(DB *db, const char *key, size_t klen, size_t *out_len, int *wrongtype)
{
    if (wrongtype)
        *wrongtype = 0;
    if (out_len)
        *out_len = 0;
    unsigned long b = 0;
    Entry *prev = NULL;
    Entry *e = db_find(db, key, klen, &b, &prev);
    if (!e)
    {
        if (out_len)
            *out_len = 0;
        return 0;
    }
    if (e->type != OBJ_LIST)
    {
        if (wrongtype)
            *wrongtype = 1;
        return -1;
    }
    if (out_len)
        *out_len = list_len(&e->data.list);
    return 0;
}