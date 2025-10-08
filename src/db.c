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

typedef struct StreamField
{
    char *key; size_t klen;
    char *val; size_t vlen;
    struct StreamField *next;
} StreamField;

typedef struct StreamEntry
{
    char *id; size_t idlen;
    StreamField *fields;
    struct StreamEntry *next;
} StreamEntry;

static void stream_entry_free(StreamEntry *e)
{
    if (!e) return;
    free(e->id);
    StreamField *f = e->fields;
    while (f)
    {
        StreamField *nx = f->next;
        free(f->key);
        free(f->val);
        free(f);
        f = nx;
    }
    free(e);
}

static void stream_free(struct Stream *st)
{
    if (!st) return;
    StreamEntry *e = st->head;
    while (e)
    {
        StreamEntry *nx = e->next;
        stream_entry_free(e);
        e = nx;
    }
    st->head = st->tail = NULL;
    st->len = 0;
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
            else if (e->type == OBJ_STREAM)
            {
                stream_free(&e->data.stream);
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
    else if (e->type == OBJ_STREAM)
        stream_free(&e->data.stream);
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
        else if (e->type == OBJ_STREAM)
        {
            stream_free(&e->data.stream);
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
        else if (e->type == OBJ_STREAM)
            stream_free(&e->data.stream);
        free(e);
        return -1;
    }
    if (e->type != OBJ_STRING)
        return -1; // wrong type for GET (treat as missing for now)
    *out_val = e->data.str.ptr;
    *out_vlen = e->data.str.len;
    return 0;
}

int db_stream_xadd(DB *db, const char *key, size_t klen,
                   const char *id, size_t idlen,
                   const char **fkeys, const size_t *fklen,
                   const char **fvals, const size_t *fvlen,
                   size_t npairs,
                   int *wrongtype,
                   const char **out_id, size_t *out_idlen)
{
    if (wrongtype) *wrongtype = 0;
    if (out_id) *out_id = NULL;
    if (out_idlen) *out_idlen = 0;
    // Validate provided ID or auto sequence/time: "*" or "<ms>-<seq|*>"
    // Parse new id ms and seq (if explicit) or mark auto flags.
    uint64_t new_ms = 0, new_seq = 0; int auto_seq = 0; int auto_all = 0;
    if (idlen == 1 && id[0] == '*')
    {
        auto_all = 1;
        new_ms = (uint64_t)now_ms();
        new_seq = 0;
    }
    else
    {
        size_t dash = (size_t)-1;
        for (size_t i = 0; i < idlen; i++)
        {
            if (id[i] == '-') { dash = i; break; }
        }
        if (dash == (size_t)-1)
            return -1; // invalid format
        if (dash == 0) return -1; // empty ms
        // parse ms
        for (size_t i = 0; i < dash; i++)
        {
            char ch = id[i];
            if (ch < '0' || ch > '9') return -1;
            new_ms = new_ms * 10ULL + (uint64_t)(ch - '0');
        }
        // parse seq or '*'
        size_t seq_start = dash + 1;
        if (seq_start >= idlen) return -1;
        if (id[seq_start] == '*' && seq_start + 1 == idlen)
        {
            auto_seq = 1;
        }
        else
        {
            for (size_t i = seq_start; i < idlen; i++)
            {
                char ch = id[i];
                if (ch < '0' || ch > '9') return -1;
                new_seq = new_seq * 10ULL + (uint64_t)(ch - '0');
            }
            if (new_ms == 0 && new_seq == 0)
                return -2; // must be greater than 0-0
        }
    }
    unsigned long b = 0; Entry *prev = NULL;
    Entry *e = db_find(db, key, klen, &b, &prev);
    if (!e)
    {
        // create stream entry
        Entry *ne = (Entry*)calloc(1, sizeof(Entry));
        if (!ne) return -1;
        ne->key = (char*)malloc(klen);
        if (!ne->key && klen > 0) { free(ne); return -1; }
        if (klen > 0) memcpy(ne->key, key, klen);
        ne->klen = klen;
        ne->type = OBJ_STREAM;
        ne->expires_at_ms = 0;
        ne->data.stream.head = ne->data.stream.tail = NULL;
        ne->data.stream.len = 0;
        ne->next = db->buckets[b];
        db->buckets[b] = ne;
        e = ne;
    }
    else if (e->type != OBJ_STREAM)
    {
        if (wrongtype) *wrongtype = 1;
        return -1;
    }

    // Compute/validate against last id if present
    uint64_t last_ms = 0, last_seq = 0; int have_last = 0;
    if (e->data.stream.tail)
    {
        have_last = 1;
        const char *lid = e->data.stream.tail->id;
        size_t lidlen = e->data.stream.tail->idlen;
        size_t dash = 0; while (dash < lidlen && lid[dash] != '-') dash++;
        for (size_t i = 0; i < dash; i++) last_ms = last_ms * 10ULL + (uint64_t)(lid[i] - '0');
        for (size_t i = dash + 1; i < lidlen; i++) last_seq = last_seq * 10ULL + (uint64_t)(lid[i] - '0');
    }
    if (!auto_seq && !auto_all)
    {
        if (have_last)
        {
            if (new_ms < last_ms || (new_ms == last_ms && new_seq <= last_seq))
                return -3;
        }
    }
    else if (auto_seq)
    {
        if (have_last)
        {
            if (new_ms < last_ms)
                return -3;
            if (new_ms == last_ms)
                new_seq = last_seq + 1;
            else
                new_seq = (new_ms == 0 ? 1 : 0);
        }
        else
        {
            new_seq = (new_ms == 0 ? 1 : 0);
        }
    }
    else /* auto_all */
    {
        if (have_last)
        {
            if (new_ms < last_ms)
            {
                // keep monotonic order if clock went backwards
                new_ms = last_ms;
                new_seq = last_seq + 1;
            }
            else if (new_ms == last_ms)
            {
                new_seq = last_seq + 1;
            }
            else
            {
                new_seq = 0; // first seq for this millisecond
            }
        }
        else
        {
            new_seq = 0; // empty stream, start at 0
        }
    }

    // Allocate new stream entry
    StreamEntry *se = (StreamEntry*)calloc(1, sizeof(StreamEntry));
    if (!se) return -1;
    // Build stored ID buffer
    if (auto_seq || auto_all)
    {
        char tmp[64];
        int n = snprintf(tmp, sizeof(tmp), "%llu-%llu",
                         (unsigned long long)new_ms,
                         (unsigned long long)new_seq);
        if (n <= 0 || (size_t)n >= sizeof(tmp)) { free(se); return -1; }
        se->idlen = (size_t)n;
        se->id = (char*)malloc(se->idlen);
        if (!se->id) { free(se); return -1; }
        memcpy(se->id, tmp, se->idlen);
    }
    else
    {
        se->id = (char*)malloc(idlen);
        if (!se->id && idlen > 0) { free(se); return -1; }
        if (idlen > 0) memcpy(se->id, id, idlen);
        se->idlen = idlen;
    }
    se->fields = NULL; se->next = NULL;

    // Build fields list (in order)
    StreamField *head = NULL, *tail = NULL;
    for (size_t i = 0; i < npairs; i++)
    {
        StreamField *sf = (StreamField*)calloc(1, sizeof(StreamField));
        if (!sf) { stream_entry_free(se); return -1; }
        sf->key = (char*)malloc(fklen[i]);
        sf->val = (char*)malloc(fvlen[i]);
        if ((fklen[i] > 0 && !sf->key) || (fvlen[i] > 0 && !sf->val))
        {
            free(sf->key); free(sf->val); free(sf);
            stream_entry_free(se);
            return -1;
        }
        if (fklen[i] > 0) memcpy(sf->key, fkeys[i], fklen[i]);
        if (fvlen[i] > 0) memcpy(sf->val, fvals[i], fvlen[i]);
        sf->klen = fklen[i]; sf->vlen = fvlen[i]; sf->next = NULL;
        if (!head) head = tail = sf; else { tail->next = sf; tail = sf; }
    }
    se->fields = head;

    // Append to stream
    if (!e->data.stream.tail)
        e->data.stream.head = e->data.stream.tail = se;
    else
    {
        e->data.stream.tail->next = se;
        e->data.stream.tail = se;
    }
    e->data.stream.len++;
    if (out_id) *out_id = se->id;
    if (out_idlen) *out_idlen = se->idlen;
    return 0;
}

int db_type(DB *db, const char *key, size_t klen, ObjType *out_type, int *found)
{
    if (found) *found = 0;
    unsigned long b = 0;
    Entry *prev = NULL;
    Entry *e = db_find(db, key, klen, &b, &prev);
    if (!e)
        return 0;
    if (e->expires_at_ms > 0 && now_ms() >= e->expires_at_ms)
    {
        // Expired: delete eagerly and report not found
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
        return 0;
    }
    if (found) *found = 1;
    if (out_type) *out_type = e->type;
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

int db_list_lpop(DB *db, const char *key, size_t klen, char **out_val, size_t *out_vlen, int *wrongtype)
{
    if (wrongtype) *wrongtype = 0;
    if (out_val) *out_val = NULL;
    if (out_vlen) *out_vlen = 0;

    unsigned long b = 0; Entry *prev = NULL;
    Entry *e = db_find(db, key, klen, &b, &prev);
    if (!e)
        return 1; // not found
    if (e->type != OBJ_LIST)
    {
        if (wrongtype) *wrongtype = 1;
        return -1;
    }

    ListNode *head = e->data.list.head;
    if (!head)
        return 1; // empty list

    // Detach head
    e->data.list.head = head->next;
    if (e->data.list.head) e->data.list.head->prev = NULL; else e->data.list.tail = NULL;
    e->data.list.len--;

    // Take ownership of value buffer; free node
    char *val = head->val;
    size_t vlen = head->vlen;
    free(head);

    // Optionally delete key if list becomes empty (not required, but tidy)
    if (e->data.list.len == 0)
    {
        // Re-find prev may be stale if we modified structure minimally, but key position unchanged
        // Use stored b and prev gathered earlier to delete e safely
        if (prev) prev->next = e->next; else db->buckets[b] = e->next;
        free(e->key);
        // list is already empty
        free(e); // no string to free
    }

    if (out_val) *out_val = val;
    if (out_vlen) *out_vlen = vlen;
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
