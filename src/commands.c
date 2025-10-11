#include "commands.h"
#include "server.h"

static Server *g_srv = NULL;

void commands_set_server(Server *srv)
{
    g_srv = srv;
}

static int emit_bulk_write(void *ctx, const char *val, size_t vlen)
{
    int fd_local = *(int *)ctx;
    char h[64];
    int l = snprintf(h, sizeof(h), "$%zu\r\n", vlen);
    if (l <= 0 || (size_t)l >= sizeof(h))
        return -1;
    if (send_all(fd_local, h, (size_t)l) != 0)
        return -1;
    if (send_all(fd_local, val, vlen) != 0)
        return -1;
    if (send_all(fd_local, "\r\n", 2) != 0)
        return -1;
    return 0;
}

// Lightweight arg slice
typedef struct Arg
{
    const char *ptr;
    size_t len;
} Arg;

typedef int (*cmd_handler)(int fd, Conn *c, DB *db, const Arg *args, size_t nargs);

static int handle_ping(int fd, Conn *c, DB *db, const Arg *args, size_t nargs)
{
    UNUSED(c);
    UNUSED(db);
    if (nargs == 0)
        return reply_simple(fd, "PONG");
    // Redis ECHO-like PING <message> returns bulk, but our prior impl handled no-arg only.
    // Keep behavior: if extra args, treat as unknown usage.
    return reply_simple(fd, "PONG");
}

static int handle_echo(int fd, Conn *c, DB *db, const Arg *args, size_t nargs)
{
    UNUSED(c);
    UNUSED(db);
    if (nargs != 1)
        return reply_error(fd, "ERR wrong number of arguments for 'ECHO'");
    return reply_bulk(fd, args[0].ptr, args[0].len);
}

static int handle_set(int fd, Conn *c, DB *db, const Arg *args, size_t nargs)
{
    UNUSED(c);
    if (nargs < 2)
        return reply_error(fd, "ERR wrong number of arguments for 'SET'");
    const char *kptr = args[0].ptr;
    size_t ksz = args[0].len;
    const char *vptr = args[1].ptr;
    size_t vsz = args[1].len;
    int64_t expires_at = 0;
    size_t i = 2;
    while (i + 1 < nargs)
    {
        const Arg *oname = &args[i];
        const Arg *oval = &args[i + 1];
        // Only EX/PX supported
        if (oname->len == 2 && ascii_casecmp_n(oname->ptr, "EX", 2) == 0)
        {
            int64_t sec = 0;
            if (parse_i64_ascii(oval->ptr, oval->len, &sec) != 0 || sec <= 0)
                return reply_error(fd, "ERR syntax error");
            expires_at = now_ms() + sec * 1000;
        }
        else if (oname->len == 2 && ascii_casecmp_n(oname->ptr, "PX", 2) == 0)
        {
            int64_t ms = 0;
            if (parse_i64_ascii(oval->ptr, oval->len, &ms) != 0 || ms <= 0)
                return reply_error(fd, "ERR syntax error");
            expires_at = now_ms() + ms;
        }
        else
        {
            return reply_error(fd, "ERR syntax error");
        }
        i += 2;
    }
    db_set(db, kptr, ksz, vptr, vsz, expires_at);
    return reply_simple(fd, "OK");
}

static int handle_get(int fd, Conn *c, DB *db, const Arg *args, size_t nargs)
{
    UNUSED(c);
    if (nargs != 1)
        return reply_error(fd, "ERR wrong number of arguments for 'GET'");
    const char *vptr = NULL;
    size_t vsz = 0;
    if (db_get(db, args[0].ptr, args[0].len, &vptr, &vsz) == 0)
        return reply_bulk(fd, vptr, vsz);
    return reply_null_bulk(fd);
}

static int handle_type(int fd, Conn *c, DB *db, const Arg *args, size_t nargs)
{
    UNUSED(c);
    if (nargs != 1)
        return reply_error(fd, "ERR wrong number of arguments for 'TYPE'");
    ObjType t = OBJ_STRING;
    int found = 0;
    if (db_type(db, args[0].ptr, args[0].len, &t, &found) != 0)
        return -1;
    if (!found)
        return reply_simple(fd, "none");
    if (t == OBJ_STRING)
        return reply_simple(fd, "string");
    if (t == OBJ_LIST)
        return reply_simple(fd, "list");
    if (t == OBJ_STREAM)
        return reply_simple(fd, "stream");
    return reply_simple(fd, "none");
}

static int handle_llen(int fd, Conn *c, DB *db, const Arg *args, size_t nargs)
{
    UNUSED(c);
    if (nargs != 1)
        return reply_error(fd, "ERR wrong number of arguments for 'LLEN'");
    size_t llen = 0;
    int wrongtype = 0;
    int rc = db_list_length(db, args[0].ptr, args[0].len, &llen, &wrongtype);
    if (rc != 0 && wrongtype)
        return reply_error(fd, "WRONGTYPE Operation against a key holding the wrong kind of value");
    return reply_int(fd, (long long)llen);
}

static int handle_lpop(int fd, Conn *c, DB *db, const Arg *args, size_t nargs)
{
    UNUSED(c);
    if (nargs < 1 || nargs > 2)
        return reply_error(fd, "ERR wrong number of arguments for 'LPOP'");
    if (nargs == 1)
    {
        int wrongtype = 0;
        char *v = NULL;
        size_t vlen = 0;
        int rc = db_list_lpop(db, args[0].ptr, args[0].len, &v, &vlen, &wrongtype);
        if (rc < 0 && wrongtype)
            return reply_error(fd, "WRONGTYPE Operation against a key holding the wrong kind of value");
        if (rc != 0 || !v)
            return reply_null_bulk(fd);
        int wrc = reply_bulk(fd, v, vlen);
        free(v);
        return wrc;
    }
    // nargs == 2: LPOP key count
    int64_t cnt = 0;
    if (parse_i64_ascii(args[1].ptr, args[1].len, &cnt) != 0 || cnt <= 0)
        return reply_error(fd, "ERR value is not an integer or out of range");
    size_t cap = (size_t)cnt;
    char **vals = (char **)calloc(cap, sizeof(char *));
    size_t *vls = (size_t *)calloc(cap, sizeof(size_t));
    if (!vals || !vls)
    {
        free(vals);
        free(vls);
        return -1;
    }
    size_t popped = 0;
    int wrongtype = 0;
    for (long i = 0; i < cnt; i++)
    {
        char *v = NULL;
        size_t vlen = 0;
        int rc = db_list_lpop(db, args[0].ptr, args[0].len, &v, &vlen, &wrongtype);
        if (rc < 0 && wrongtype)
        {
            for (size_t j = 0; j < popped; j++)
                free(vals[j]);
            free(vals);
            free(vls);
            return reply_error(fd, "WRONGTYPE Operation against a key holding the wrong kind of value");
        }
        if (rc != 0 || !v)
            break;
        vals[popped] = v;
        vls[popped] = vlen;
        popped++;
    }
    int rc = reply_array_header(fd, popped);
    if (rc != 0)
    {
        for (size_t j = 0; j < popped; j++)
            free(vals[j]);
        free(vals);
        free(vls);
        return -1;
    }
    for (size_t i = 0; i < popped; i++)
    {
        if (reply_bulk(fd, vals[i], vls[i]) != 0)
        {
            for (size_t j = 0; j < popped; j++)
                free(vals[j]);
            free(vals);
            free(vls);
            return -1;
        }
    }
    for (size_t j = 0; j < popped; j++)
        free(vals[j]);
    free(vals);
    free(vls);
    return 0;
}

static int handle_rpush(int fd, Conn *c, DB *db, const Arg *args, size_t nargs)
{
    UNUSED(c);
    if (nargs < 2)
        return reply_error(fd, "ERR wrong number of arguments for 'RPUSH'");
    const char *kptr = args[0].ptr;
    size_t ksz = args[0].len;
    size_t newlen = 0;
    int wrongtype = 0;
    for (size_t i = 1; i < nargs; i++)
    {
        if (db_list_rpush(db, kptr, ksz, args[i].ptr, args[i].len, &newlen, &wrongtype) != 0)
            return reply_error(fd, "ERR rpush failed");
        if (wrongtype)
            return reply_error(fd, "WRONGTYPE Operation against a key holding the wrong kind of value");
    }
    return reply_int(fd, (long long)newlen);
}

static int handle_lpush(int fd, Conn *c, DB *db, const Arg *args, size_t nargs)
{
    UNUSED(c);
    if (nargs < 2)
        return reply_error(fd, "ERR wrong number of arguments for 'LPUSH'");
    const char *kptr = args[0].ptr;
    size_t ksz = args[0].len;
    size_t newlen = 0;
    int wrongtype = 0;
    for (size_t i = 1; i < nargs; i++)
    {
        if (db_list_lpush(db, kptr, ksz, args[i].ptr, args[i].len, &newlen, &wrongtype) != 0)
            return reply_error(fd, "ERR lpush failed");
        if (wrongtype)
            return reply_error(fd, "WRONGTYPE Operation against a key holding the wrong kind of value");
    }
    return reply_int(fd, (long long)newlen);
}

static int handle_lrange(int fd, Conn *c, DB *db, const Arg *args, size_t nargs)
{
    UNUSED(c);
    if (nargs != 3)
        return reply_error(fd, "ERR wrong number of arguments for 'LRANGE'");
    int64_t s64 = 0, e64 = 0;
    if (parse_i64_ascii(args[1].ptr, args[1].len, &s64) != 0 ||
        parse_i64_ascii(args[2].ptr, args[2].len, &e64) != 0)
        return reply_error(fd, "ERR value is not an integer or out of range");
    size_t cnt = 0;
    int wrongtype = 0;
    if (db_list_range_count(db, args[0].ptr, args[0].len, (long)s64, (long)e64, &cnt, &wrongtype) != 0)
    {
        if (wrongtype)
            return reply_error(fd, "WRONGTYPE Operation against a key holding the wrong kind of value");
        // else treat as empty
        cnt = 0;
    }
    if (reply_array_header(fd, cnt) != 0)
        return -1;
    if (cnt == 0)
        return 0;
    int fd_ctx = fd;
    wrongtype = 0;
    if (db_list_range_emit(db, args[0].ptr, args[0].len, (long)s64, (long)e64, emit_bulk_write, &fd_ctx, &wrongtype) != 0)
        return -1;
    return 0;
}

static int handle_xadd(int fd, Conn *c, DB *db, const Arg *args, size_t nargs)
{
    UNUSED(c);
    // XADD key id field value [field value ...]
    if (nargs < 3)
        return reply_error(fd, "ERR wrong number of arguments for 'XADD'");
    const char *kptr = args[0].ptr; size_t ksz = args[0].len;
    const char *idptr = args[1].ptr; size_t idsz = args[1].len;
    size_t rem = nargs - 2;
    if (rem < 2 || (rem % 2) != 0)
        return reply_error(fd, "ERR wrong number of arguments for 'XADD'");

    // Validate ID format quickly to provide tailored errors;
    // allow explicit (ms-seq), auto-seq (ms-*), and full auto (*).
    {
        if (!(idsz == 1 && idptr[0] == '*'))
        {
            size_t dash = (size_t)-1;
            for (size_t i = 0; i < idsz; i++)
                if (idptr[i] == '-') { dash = i; break; }
            if (dash == (size_t)-1)
                return reply_error(fd, "ERR xadd failed");
            uint64_t ms = 0, seq = 0; int ok = 1; int star = 0;
            if (dash == 0 || dash + 1 >= idsz) ok = 0;
            for (size_t i = 0; ok && i < dash; i++)
            {
                char ch = idptr[i];
                if (ch < '0' || ch > '9') ok = 0; else ms = ms * 10ULL + (uint64_t)(ch - '0');
            }
            if (ok)
            {
                if (dash + 1 == idsz - 1 && idptr[dash + 1] == '*')
                {
                    star = 1;
                }
                else
                {
                    for (size_t i = dash + 1; ok && i < idsz; i++)
                    {
                        char ch = idptr[i];
                        if (ch < '0' || ch > '9') ok = 0; else seq = seq * 10ULL + (uint64_t)(ch - '0');
                    }
                }
            }
            if (!ok)
                return reply_error(fd, "ERR xadd failed");
            if (!star && ms == 0 && seq == 0)
                return reply_error(fd, "ERR The ID specified in XADD must be greater than 0-0");
        }
    }

    size_t npairs = rem / 2;
    const char **fkeys = (const char **)calloc(npairs, sizeof(char *));
    const char **fvals = (const char **)calloc(npairs, sizeof(char *));
    size_t *fklen = (size_t *)calloc(npairs, sizeof(size_t));
    size_t *fvlen = (size_t *)calloc(npairs, sizeof(size_t));
    if (!fkeys || !fvals || !fklen || !fvlen)
    {
        free(fkeys); free(fvals); free(fklen); free(fvlen);
        return -1;
    }
    for (size_t i = 0; i < npairs; i++)
    {
        fkeys[i] = args[2 + i * 2].ptr; fklen[i] = args[2 + i * 2].len;
        fvals[i] = args[2 + i * 2 + 1].ptr; fvlen[i] = args[2 + i * 2 + 1].len;
    }
    int wrongtype = 0;
    const char *stored_id = NULL; size_t stored_id_len = 0;
    int rc = db_stream_xadd(db, kptr, ksz, idptr, idsz, fkeys, fklen, fvals, fvlen, npairs, &wrongtype, &stored_id, &stored_id_len);
    free(fkeys); free(fvals); free(fklen); free(fvlen);
    if (rc != 0 && wrongtype)
        return reply_error(fd, "WRONGTYPE Operation against a key holding the wrong kind of value");
    if (rc == -2)
        return reply_error(fd, "ERR The ID specified in XADD must be greater than 0-0");
    if (rc == -3)
        return reply_error(fd, "ERR The ID specified in XADD is equal or smaller than the target stream top item");
    if (rc != 0)
        return reply_error(fd, "ERR xadd failed");
    // Reply with the stored (possibly auto-generated) ID
    return reply_bulk(fd, stored_id, stored_id_len);
}

static int parse_stream_qid(const char *s, size_t len, uint64_t *ms, uint64_t *seq, int is_start)
{
    if (!s || len == 0 || !ms || !seq) return -1;
    // Special case: '-' denotes the beginning of the stream, valid only for start
    if (len == 1 && s[0] == '-')
    {
        if (!is_start) return -1;
        *ms = 0; *seq = 0; return 0;
    }
    // Special case: '+' denotes the end of the stream, valid only for end
    if (len == 1 && s[0] == '+')
    {
        if (is_start) return -1;
        *ms = UINT64_MAX; *seq = UINT64_MAX; return 0;
    }
    // Check for '-'
    size_t dash = (size_t)-1;
    for (size_t i = 0; i < len; i++)
    {
        if (s[i] == '-') { dash = i; break; }
    }
    if (dash == (size_t)-1)
    {
        // Only milliseconds part provided
        uint64_t tms = 0; int any = 0;
        for (size_t i = 0; i < len; i++)
        {
            char ch = s[i]; if (ch < '0' || ch > '9') return -1; any = 1; tms = tms * 10ULL + (uint64_t)(ch - '0');
        }
        if (!any) return -1;
        *ms = tms;
        *seq = is_start ? 0ULL : UINT64_MAX;
        return 0;
    }
    if (dash == 0 || dash + 1 >= len) return -1;
    uint64_t tms = 0, tseq = 0; int anyms = 0, anyseq = 0;
    for (size_t i = 0; i < dash; i++)
    {
        char ch = s[i]; if (ch < '0' || ch > '9') return -1; anyms = 1; tms = tms * 10ULL + (uint64_t)(ch - '0');
    }
    for (size_t i = dash + 1; i < len; i++)
    {
        char ch = s[i]; if (ch < '0' || ch > '9') return -1; anyseq = 1; tseq = tseq * 10ULL + (uint64_t)(ch - '0');
    }
    if (!anyms || !anyseq) return -1;
    *ms = tms; *seq = tseq; return 0;
}

static int emit_xrange_entry(void *ctx,
                             const char *id, size_t idlen,
                             const char **fkeys, const size_t *fklen,
                             const char **fvals, const size_t *fvlen,
                             size_t npairs)
{
    int fd = *(int*)ctx;
    // Each entry is an array of 2 elements: id, fields array
    if (reply_array_header(fd, 2) != 0) return -1;
    if (reply_bulk(fd, id, idlen) != 0) return -1;
    size_t fields_cnt = npairs * 2;
    if (reply_array_header(fd, fields_cnt) != 0) return -1;
    for (size_t i = 0; i < npairs; i++)
    {
        if (reply_bulk(fd, fkeys[i], fklen[i]) != 0) return -1;
        if (reply_bulk(fd, fvals[i], fvlen[i]) != 0) return -1;
    }
    return 0;
}

static int handle_xrange(int fd, Conn *c, DB *db, const Arg *args, size_t nargs)
{
    UNUSED(c);
    if (nargs != 3)
        return reply_error(fd, "ERR wrong number of arguments for 'XRANGE'");
    uint64_t start_ms = 0, start_seq = 0, end_ms = 0, end_seq = 0;
    if (parse_stream_qid(args[1].ptr, args[1].len, &start_ms, &start_seq, 1) != 0 ||
        parse_stream_qid(args[2].ptr, args[2].len, &end_ms, &end_seq, 0) != 0)
    {
        return reply_error(fd, "ERR value is not an integer or out of range");
    }
    size_t cnt = 0; int wrongtype = 0;
    if (db_stream_xrange_count(db, args[0].ptr, args[0].len,
                               start_ms, start_seq, end_ms, end_seq,
                               &cnt, &wrongtype) != 0)
    {
        if (wrongtype)
            return reply_error(fd, "WRONGTYPE Operation against a key holding the wrong kind of value");
        // else treat as empty
        cnt = 0;
    }
    if (reply_array_header(fd, cnt) != 0) return -1;
    if (cnt == 0) return 0;
    int fd_ctx = fd; wrongtype = 0;
    if (db_stream_xrange_emit(db, args[0].ptr, args[0].len,
                              start_ms, start_seq, end_ms, end_seq,
                              emit_xrange_entry, &fd_ctx, &wrongtype) != 0)
    {
        if (wrongtype)
            return reply_error(fd, "WRONGTYPE Operation against a key holding the wrong kind of value");
        return -1;
    }
    return 0;
}

static int handle_xread(int fd, Conn *c, DB *db, const Arg *args, size_t nargs)
{
    UNUSED(c);
    // XREAD STREAMS <key> <id>
    if (nargs != 3)
        return reply_error(fd, "ERR wrong number of arguments for 'XREAD'");
    if (!(args[0].len == 7 && ascii_casecmp_n(args[0].ptr, "STREAMS", 7) == 0))
        return reply_error(fd, "ERR syntax error");

    const char *kptr = args[1].ptr; size_t klen = args[1].len;
    // Parse exclusive start id (must be ms-seq)
    uint64_t ms = 0, seq = 0;
    {
        // Require full id with dash
        size_t dash = (size_t)-1;
        for (size_t i = 0; i < args[2].len; i++)
            if (args[2].ptr[i] == '-') { dash = i; break; }
        if (dash == (size_t)-1 || dash == 0 || dash + 1 >= args[2].len)
            return reply_error(fd, "ERR value is not an integer or out of range");
        // parse ms
        for (size_t i = 0; i < dash; i++)
        {
            char ch = args[2].ptr[i];
            if (ch < '0' || ch > '9') return reply_error(fd, "ERR value is not an integer or out of range");
            ms = ms * 10ULL + (uint64_t)(ch - '0');
        }
        for (size_t i = dash + 1; i < args[2].len; i++)
        {
            char ch = args[2].ptr[i];
            if (ch < '0' || ch > '9') return reply_error(fd, "ERR value is not an integer or out of range");
            seq = seq * 10ULL + (uint64_t)(ch - '0');
        }
    }
    // Convert exclusive start (ms,seq) to inclusive start for XRANGE helpers
    uint64_t start_ms = ms, start_seq = seq;
    if (start_seq < UINT64_MAX)
        start_seq++;
    else
    {
        // Move to the next millisecond, if possible
        if (start_ms == UINT64_MAX)
        {
            // No possible entries greater than this id
            return reply_null_array(fd);
        }
        start_ms += 1;
        start_seq = 0;
    }

    int wrongtype = 0;
    size_t cnt = 0;
    if (db_stream_xrange_count(db, kptr, klen,
                               start_ms, start_seq,
                               UINT64_MAX, UINT64_MAX,
                               &cnt, &wrongtype) != 0)
    {
        if (wrongtype)
            return reply_error(fd, "WRONGTYPE Operation against a key holding the wrong kind of value");
        cnt = 0;
    }
    if (cnt == 0)
        return reply_null_array(fd);
    // Outer array of streams (1 stream)
    if (reply_array_header(fd, 1) != 0) return -1;
    // Stream array: [ key, entries ]
    if (reply_array_header(fd, 2) != 0) return -1;
    if (reply_bulk(fd, kptr, klen) != 0) return -1;
    if (reply_array_header(fd, cnt) != 0) return -1;
    int fd_ctx = fd; wrongtype = 0;
    if (db_stream_xrange_emit(db, kptr, klen,
                              start_ms, start_seq,
                              UINT64_MAX, UINT64_MAX,
                              emit_xrange_entry, &fd_ctx, &wrongtype) != 0)
    {
        if (wrongtype)
            return reply_error(fd, "WRONGTYPE Operation against a key holding the wrong kind of value");
        return -1;
    }
    return 0;
}
typedef struct CmdDef
{
    const char *name;
    size_t nlen;
    cmd_handler fn;
} CmdDef;

static const CmdDef kCmds[] = {
    {"PING", 4, handle_ping},
    {"ECHO", 4, handle_echo},
    {"SET", 3, handle_set},
    {"GET", 3, handle_get},
    {"TYPE", 4, handle_type},
    // Lists
    {"LLEN", 4, handle_llen},
    {"LPOP", 4, handle_lpop},
    {"RPUSH", 5, handle_rpush},
    {"LPUSH", 5, handle_lpush},
    {"LRANGE", 6, handle_lrange},
    // Streams
    {"XADD", 4, handle_xadd},
    {"XRANGE", 6, handle_xrange},
    {"XREAD", 5, handle_xread},
};

static const CmdDef *find_cmd(const char *name, size_t nlen)
{
    for (size_t i = 0; i < sizeof(kCmds) / sizeof(kCmds[0]); i++)
    {
        const CmdDef *d = &kCmds[i];
        if (d->nlen == nlen && ascii_casecmp_n(name, d->name, nlen) == 0)
            return d;
    }
    return NULL;
}

int ensure_capacity(Conn *c, size_t need)
{
    if (c->cap >= need)
        return 0;
    size_t ncap = c->cap ? c->cap : 8192;
    while (ncap < need)
        ncap *= 2;
    char *nbuf = realloc(c->buf, ncap);
    if (!nbuf)
        return -1;
    c->buf = nbuf;
    c->cap = ncap;
    return 0;
}

static int skip_bulk_items(const char *p, size_t rem, size_t *pos, long items)
{
    for (long i = 0; i < items; i++)
    {
        if (*pos >= rem || p[*pos] != '$')
            return -1;
        long blen = 0;
        size_t bu = 0;
        if (parse_crlf_int(p + *pos + 1, rem - *pos - 1, &blen, &bu) != 0)
            return -1;
        *pos += 1 + bu;
        if (blen >= 0)
        {
            if ((size_t)blen + 2 > rem - *pos)
                return -1;
            *pos += (size_t)blen + 2;
        }
    }
    return 0;
}

int process_conn(int fd, Conn *c, DB *db)
{
    size_t offset = 0;
    while (1)
    {
        if (c->len - offset < 1)
            break;
        const char *p = c->buf + offset;
        size_t rem = c->len - offset;
        if (p[0] != '*')
        {
            char *eol = memchr(p, '\n', rem);
            if (!eol)
                break;
            offset = (size_t)(eol - (c->buf + offset)) + offset + 1;
            continue;
        }
        if (rem < 2)
            break;
        long arrlen = 0;
        size_t used = 0;
        if (parse_crlf_int(p + 1, rem - 1, &arrlen, &used) != 0)
            break;
        size_t pos = 1 + used;
        if (arrlen < 1)
        {
            offset += pos;
            continue;
        }

        // First bulk is command
        if (pos >= rem || p[pos] != '$')
            break;
        long blen = 0;
        size_t bu = 0;
        if (parse_crlf_int(p + pos + 1, rem - pos - 1, &blen, &bu) != 0)
            break;
        pos += 1 + bu;
        if (blen < 0)
        {
            offset += pos;
            continue;
        }
        if ((size_t)blen + 2 > rem - pos)
            break;
        const char *cmd = p + pos;
        size_t cmdlen = (size_t)blen;
        pos += (size_t)blen;
        if (pos + 2 > rem)
            break;
        if (p[pos] != '\r' || p[pos + 1] != '\n')
        {
            offset += pos + 2;
            continue;
        }
        pos += 2;

        // Dispatch-table path for a subset of commands
        const CmdDef *def = find_cmd(cmd, cmdlen);
        if (def)
        {
            long nargs = arrlen - 1;
            if (nargs < 0)
            {
                offset += pos;
                continue;
            }
            // Collect all bulk args as slices
            Arg *args = NULL;
            if (nargs > 0)
            {
                args = (Arg *)calloc((size_t)nargs, sizeof(Arg));
                if (!args)
                    return -1;
                for (long i = 0; i < nargs; i++)
                {
                    if (pos >= rem || p[pos] != '$')
                    {
                        free(args);
                        args = NULL;
                        goto need_more;
                    }
                    long alen = 0;
                    size_t abu = 0;
                    if (parse_crlf_int(p + pos + 1, rem - pos - 1, &alen, &abu) != 0)
                    {
                        free(args);
                        args = NULL;
                        goto need_more;
                    }
                    pos += 1 + abu;
                    if (alen < 0)
                    {
                        free(args);
                        args = NULL;
                        goto need_more;
                    }
                    if ((size_t)alen + 2 > rem - pos)
                    {
                        free(args);
                        args = NULL;
                        goto need_more;
                    }
                    args[i].ptr = p + pos;
                    args[i].len = (size_t)alen;
                    pos += (size_t)alen;
                    if (pos + 2 > rem)
                    {
                        free(args);
                        args = NULL;
                        goto need_more;
                    }
                    if (p[pos] != '\r' || p[pos + 1] != '\n')
                    {
                        free(args);
                        args = NULL;
                        goto need_more;
                    }
                    pos += 2;
                }
            }
            {
                int rc = def->fn(fd, c, db, args, (size_t)nargs);
                free(args);
                if (rc != 0)
                    return -1;
                offset += pos;
                continue;
            }
        need_more:
            // Not enough bytes to parse all args yet
            if (args)
                free(args);
            break;
        }
        if (0)
        {
        }
        else if (arrlen == 3 && cmdlen == 5 && ascii_casecmp_n(cmd, "BLPOP", 5) == 0)
        {
            // key
            if (pos >= rem || p[pos] != '$')
                break;
            long klen = 0;
            size_t bu1 = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &klen, &bu1) != 0)
                break;
            pos += 1 + bu1;
            if (klen < 0)
            {
                offset += pos;
                continue;
            }
            if ((size_t)klen + 2 > rem - pos)
                break;
            const char *kptr = p + pos;
            size_t ksz = (size_t)klen;
            pos += ksz;
            if (pos + 2 > rem)
                break;
            if (p[pos] != '\r' || p[pos + 1] != '\n')
            {
                offset += pos + 2;
                continue;
            }
            pos += 2;

            // timeout seconds as bulk
            if (pos >= rem || p[pos] != '$')
                break;
            long tlen = 0;
            size_t but = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &tlen, &but) != 0)
                break;
            pos += 1 + but;
            if (tlen < 0)
            {
                offset += pos;
                continue;
            }
            if ((size_t)tlen + 2 > rem - pos)
                break;
            const char *tptr = p + pos;
            size_t tsz = (size_t)tlen;
            pos += tsz;
            if (pos + 2 > rem)
                break;
            if (p[pos] != '\r' || p[pos + 1] != '\n')
            {
                offset += pos + 2;
                continue;
            }
            pos += 2;

            // parse timeout as non-negative seconds, supports fractional (e.g., 0.5)
            int ok = 1;
            int any = 0;
            int seen_dot = 0;
            int frac_digits = 0;
            long long int_part = 0;
            long long frac_part = 0;
            for (size_t i = 0; i < tsz; i++)
            {
                char ch = tptr[i];
                if (ch == '.')
                {
                    if (seen_dot)
                    {
                        ok = 0;
                        break;
                    }
                    seen_dot = 1;
                    continue;
                }
                if (ch == '-')
                {
                    ok = 0;
                    break;
                }
                if (ch < '0' || ch > '9')
                {
                    ok = 0;
                    break;
                }
                any = 1;
                if (!seen_dot)
                {
                    int_part = int_part * 10 + (ch - '0');
                }
                else
                {
                    if (frac_digits < 3)
                    {
                        frac_part = frac_part * 10 + (ch - '0');
                        frac_digits++;
                    }
                    // ignore extra fractional digits beyond millisecond precision
                }
            }
            if (!any)
                ok = 0;
            // convert to milliseconds (truncate beyond 3 decimals)
            long long to_ms = 0;
            if (ok)
            {
                long long scale = 1;
                if (frac_digits == 0)
                    scale = 1000;
                else if (frac_digits == 1)
                    scale = 100;
                else if (frac_digits == 2)
                    scale = 10;
                else
                    scale = 1;
                to_ms = int_part * 1000 + frac_part * scale;
            }
            if (!ok)
            {
                const char err[] = "-ERR value is not an integer or out of range\r\n";
                if (send_all(fd, err, sizeof(err) - 1) != 0)
                    return -1;
                offset += pos;
                continue;
            }

            // Try immediate pop
            int wrongtype = 0;
            char *v = NULL;
            size_t vlen = 0;
            int rc = db_list_lpop(db, kptr, ksz, &v, &vlen, &wrongtype);
            if (rc < 0 && wrongtype)
            {
                const char wt[] = "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n";
                if (send_all(fd, wt, sizeof(wt) - 1) != 0)
                {
                    if (v)
                        free(v);
                    return -1;
                }
                offset += pos;
                if (v)
                    free(v);
                continue;
            }
            if (rc == 0 && v)
            {
                // reply with [key, elem]
                char h[64];
                int hl = snprintf(h, sizeof(h), "*2\r\n");
                if (hl <= 0 || (size_t)hl >= sizeof(h))
                {
                    free(v);
                    return -1;
                }
                if (send_all(fd, h, (size_t)hl) != 0)
                {
                    free(v);
                    return -1;
                }
                hl = snprintf(h, sizeof(h), "$%zu\r\n", ksz);
                if (hl <= 0 || (size_t)hl >= sizeof(h))
                {
                    free(v);
                    return -1;
                }
                if (send_all(fd, h, (size_t)hl) != 0)
                {
                    free(v);
                    return -1;
                }
                if (send_all(fd, kptr, ksz) != 0)
                {
                    free(v);
                    return -1;
                }
                if (send_all(fd, "\r\n", 2) != 0)
                {
                    free(v);
                    return -1;
                }
                hl = snprintf(h, sizeof(h), "$%zu\r\n", vlen);
                if (hl <= 0 || (size_t)hl >= sizeof(h))
                {
                    free(v);
                    return -1;
                }
                if (send_all(fd, h, (size_t)hl) != 0)
                {
                    free(v);
                    return -1;
                }
                if (send_all(fd, v, vlen) != 0)
                {
                    free(v);
                    return -1;
                }
                if (send_all(fd, "\r\n", 2) != 0)
                {
                    free(v);
                    return -1;
                }
                free(v);
                offset += pos;
                continue;
            }

            // Otherwise, register waiter (0 timeout => infinite)
            int64_t deadline = (to_ms == 0) ? 0 : (now_ms() + (int64_t)to_ms);
            if (g_srv)
                server_add_waiter(g_srv, c, fd, kptr, ksz, deadline);
            offset += pos;
            continue;
        }
        else
        {
            const char err[] = "-ERR unknown command\r\n";
            if (send_all(fd, err, sizeof(err) - 1) != 0)
                return -1;
            long to_skip = arrlen - 1;
            if (to_skip > 0)
            {
                if (skip_bulk_items(p, rem, &pos, to_skip) != 0)
                    break;
            }
            offset += pos;
            continue;
        }
    }
    if (offset > 0)
    {
        if (offset < c->len)
            memmove(c->buf, c->buf + offset, c->len - offset);
        c->len -= offset;
    }
    return 0;
}
