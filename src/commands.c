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

        if (arrlen == 1 && cmdlen == 4 && ascii_casecmp_n(cmd, "PING", 4) == 0)
        {
            const char pong[] = "+PONG\r\n";
            if (send_all(fd, pong, sizeof(pong) - 1) != 0)
                return -1;
            offset += pos;
            continue;
        }
        else if (arrlen == 2 && cmdlen == 4 && ascii_casecmp_n(cmd, "ECHO", 4) == 0)
        {
            if (pos >= rem || p[pos] != '$')
                break;
            long arglen = 0;
            size_t abu = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &arglen, &abu) != 0)
                break;
            pos += 1 + abu;
            if (arglen < 0)
            {
                offset += pos;
                continue;
            }
            if ((size_t)arglen + 2 > rem - pos)
                break;
            const char *arg = p + pos;
            size_t argsz = (size_t)arglen;
            pos += argsz;
            if (pos + 2 > rem)
                break;
            if (p[pos] != '\r' || p[pos + 1] != '\n')
            {
                offset += pos + 2;
                continue;
            }
            pos += 2;

            char header[64];
            int hl = snprintf(header, sizeof(header), "$%zu\r\n", argsz);
            if (hl <= 0 || (size_t)hl >= sizeof(header))
                return -1;
            if (send_all(fd, header, (size_t)hl) != 0)
                return -1;
            if (send_all(fd, arg, argsz) != 0)
                return -1;
            if (send_all(fd, "\r\n", 2) != 0)
                return -1;

            offset += pos;
            continue;
        }
        else if (arrlen == 2 && cmdlen == 4 && ascii_casecmp_n(cmd, "LLEN", 4) == 0)
        {
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

            size_t llen = 0;
            int wrongtype = 0;
            if (db_list_length(db, kptr, ksz, &llen, &wrongtype) != 0)
            {
                if (wrongtype)
                {
                    const char wt[] = "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n";
                    if (send_all(fd, wt, sizeof(wt) - 1) != 0)
                        return -1;
                }
                else
                {
                    const char zero[] = ":0\r\n";
                    if (send_all(fd, zero, sizeof(zero) - 1) != 0)
                        return -1;
                }
                offset += pos;
                continue;
            }
            char ibuf[64];
            int il = snprintf(ibuf, sizeof(ibuf), ":%zu\r\n", llen);
            if (il <= 0 || (size_t)il >= sizeof(ibuf))
                return -1;
            if (send_all(fd, ibuf, (size_t)il) != 0)
                return -1;
            offset += pos;
            continue;
        }
        else if (arrlen >= 3 && cmdlen == 3 && ascii_casecmp_n(cmd, "SET", 3) == 0)
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
            // value
            if (pos >= rem || p[pos] != '$')
                break;
            long vlen = 0;
            size_t bu2 = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &vlen, &bu2) != 0)
                break;
            pos += 1 + bu2;
            if (vlen < 0)
            {
                offset += pos;
                continue;
            }
            if ((size_t)vlen + 2 > rem - pos)
                break;
            const char *vptr = p + pos;
            size_t vsz = (size_t)vlen;
            pos += vsz;
            if (pos + 2 > rem)
                break;
            if (p[pos] != '\r' || p[pos + 1] != '\n')
            {
                offset += pos + 2;
                continue;
            }
            pos += 2;

            int64_t expires_at = 0;
            long remaining = arrlen - 3; // options
            while (remaining >= 2)
            {
                if (pos >= rem || p[pos] != '$')
                    break;
                long onamelen = 0;
                size_t buo = 0;
                if (parse_crlf_int(p + pos + 1, rem - pos - 1, &onamelen, &buo) != 0)
                    break;
                pos += 1 + buo;
                if (onamelen < 0)
                {
                    offset += pos;
                    continue;
                }
                if ((size_t)onamelen + 2 > rem - pos)
                    break;
                const char *oname = p + pos;
                size_t onamensz = (size_t)onamelen;
                pos += onamensz;
                if (pos + 2 > rem)
                    break;
                if (p[pos] != '\r' || p[pos + 1] != '\n')
                {
                    offset += pos + 2;
                    continue;
                }
                pos += 2;
                if (pos >= rem || p[pos] != '$')
                    break;
                long oval_len = 0;
                size_t buv = 0;
                if (parse_crlf_int(p + pos + 1, rem - pos - 1, &oval_len, &buv) != 0)
                    break;
                pos += 1 + buv;
                if (oval_len < 0)
                {
                    offset += pos;
                    continue;
                }
                if ((size_t)oval_len + 2 > rem - pos)
                    break;
                const char *oval = p + pos;
                size_t oval_sz = (size_t)oval_len;
                pos += oval_sz;
                if (pos + 2 > rem)
                    break;
                if (p[pos] != '\r' || p[pos + 1] != '\n')
                {
                    offset += pos + 2;
                    continue;
                }
                pos += 2;

                // parse ttl
                long ttl_num = 0;
                int oknum = 1;
                long tmp = 0;
                int neg = 0;
                int any = 0;
                for (size_t i = 0; i < oval_sz; i++)
                {
                    char ch = oval[i];
                    if (i == 0 && ch == '-')
                    {
                        neg = 1;
                        continue;
                    }
                    if (ch < '0' || ch > '9')
                    {
                        oknum = 0;
                        break;
                    }
                    any = 1;
                    tmp = tmp * 10 + (ch - '0');
                }
                if (!any || neg || !oknum)
                    tmp = -1;
                ttl_num = tmp;

                if (onamensz == 2 && ascii_casecmp_n(oname, "EX", 2) == 0)
                {
                    if (ttl_num <= 0)
                    {
                        const char err[] = "-ERR syntax error\r\n";
                        if (send_all(fd, err, sizeof(err) - 1) != 0)
                            return -1;
                        offset += pos;
                        continue;
                    }
                    expires_at = now_ms() + (int64_t)ttl_num * 1000;
                }
                else if (onamensz == 2 && ascii_casecmp_n(oname, "PX", 2) == 0)
                {
                    if (ttl_num <= 0)
                    {
                        const char err[] = "-ERR syntax error\r\n";
                        if (send_all(fd, err, sizeof(err) - 1) != 0)
                            return -1;
                        offset += pos;
                        continue;
                    }
                    expires_at = now_ms() + (int64_t)ttl_num;
                }
                else
                {
                    const char err[] = "-ERR syntax error\r\n";
                    if (send_all(fd, err, sizeof(err) - 1) != 0)
                        return -1;
                    offset += pos;
                    continue;
                }
                remaining -= 2;
            }

            db_set(db, kptr, ksz, vptr, vsz, expires_at);
            const char ok[] = "+OK\r\n";
            if (send_all(fd, ok, sizeof(ok) - 1) != 0)
                return -1;
            offset += pos;
            continue;
        }
        else if (arrlen >= 3 && cmdlen == 5 && ascii_casecmp_n(cmd, "RPUSH", 5) == 0)
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

            // one or more elements
            size_t newlen = 0;
            int wrongtype = 0;
            int had_error = 0;
            long remaining = arrlen - 2;
            for (long i = 0; i < remaining; i++)
            {
                if (pos >= rem || p[pos] != '$')
                {
                    wrongtype = 0;
                    break;
                }
                long elen = 0;
                size_t bu2 = 0;
                if (parse_crlf_int(p + pos + 1, rem - pos - 1, &elen, &bu2) != 0)
                {
                    wrongtype = 0;
                    break;
                }
                pos += 1 + bu2;
                if (elen < 0)
                {
                    offset += pos;
                    continue;
                }
                if ((size_t)elen + 2 > rem - pos)
                {
                    wrongtype = 0;
                    break;
                }
                const char *eptr = p + pos;
                size_t esz = (size_t)elen;
                pos += esz;
                if (pos + 2 > rem)
                {
                    wrongtype = 0;
                    break;
                }
                if (p[pos] != '\r' || p[pos + 1] != '\n')
                {
                    offset += pos + 2;
                    continue;
                }
                pos += 2;

                if (db_list_rpush(db, kptr, ksz, eptr, esz, &newlen, &wrongtype) != 0)
                {
                    // failure (e.g., alloc). We'll send generic error.
                    const char err[] = "-ERR rpush failed\r\n";
                    if (send_all(fd, err, sizeof(err) - 1) != 0)
                        return -1;
                    offset += pos;
                    had_error = 1;
                    break;
                }
                if (wrongtype)
                {
                    const char wt[] = "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n";
                    if (send_all(fd, wt, sizeof(wt) - 1) != 0)
                        return -1;
                    offset += pos;
                    had_error = 1;
                    break;
                }
            }
            if (had_error)
            {
                continue;
            }
            char ibuf[64];
            int il = snprintf(ibuf, sizeof(ibuf), ":%zu\r\n", newlen);
            if (il <= 0 || (size_t)il >= sizeof(ibuf))
                return -1;
            if (send_all(fd, ibuf, (size_t)il) != 0)
                return -1;
            offset += pos;
            continue;
        }
        else if (arrlen >= 3 && cmdlen == 5 && ascii_casecmp_n(cmd, "LPUSH", 5) == 0)
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

            // one or more elements (prepend to list)
            size_t newlen = 0;
            int wrongtype = 0;
            int had_error = 0;
            long remaining = arrlen - 2;
            for (long i = 0; i < remaining; i++)
            {
                if (pos >= rem || p[pos] != '$')
                {
                    wrongtype = 0;
                    break;
                }
                long elen = 0;
                size_t bu2 = 0;
                if (parse_crlf_int(p + pos + 1, rem - pos - 1, &elen, &bu2) != 0)
                {
                    wrongtype = 0;
                    break;
                }
                pos += 1 + bu2;
                if (elen < 0)
                {
                    offset += pos;
                    continue;
                }
                if ((size_t)elen + 2 > rem - pos)
                {
                    wrongtype = 0;
                    break;
                }
                const char *eptr = p + pos;
                size_t esz = (size_t)elen;
                pos += esz;
                if (pos + 2 > rem)
                {
                    wrongtype = 0;
                    break;
                }
                if (p[pos] != '\r' || p[pos + 1] != '\n')
                {
                    offset += pos + 2;
                    continue;
                }
                pos += 2;

                if (db_list_lpush(db, kptr, ksz, eptr, esz, &newlen, &wrongtype) != 0)
                {
                    const char err[] = "-ERR lpush failed\r\n";
                    if (send_all(fd, err, sizeof(err) - 1) != 0)
                        return -1;
                    offset += pos;
                    had_error = 1;
                    break;
                }
                if (wrongtype)
                {
                    const char wt[] = "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n";
                    if (send_all(fd, wt, sizeof(wt) - 1) != 0)
                        return -1;
                    offset += pos;
                    had_error = 1;
                    break;
                }
            }
            if (had_error)
            {
                continue;
            }
            char ibuf[64];
            int il = snprintf(ibuf, sizeof(ibuf), ":%zu\r\n", newlen);
            if (il <= 0 || (size_t)il >= sizeof(ibuf))
                return -1;
            if (send_all(fd, ibuf, (size_t)il) != 0)
                return -1;
            offset += pos;
            continue;
        }
        else if (arrlen == 3 && cmdlen == 4 && ascii_casecmp_n(cmd, "LPOP", 4) == 0)
        {
            // key
            if (pos >= rem || p[pos] != '$')
                break;
            long klen = 0; size_t bu1 = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &klen, &bu1) != 0)
                break;
            pos += 1 + bu1;
            if (klen < 0) { offset += pos; continue; }
            if ((size_t)klen + 2 > rem - pos) break;
            const char *kptr = p + pos; size_t ksz = (size_t)klen;
            pos += ksz;
            if (pos + 2 > rem) break;
            if (p[pos] != '\r' || p[pos + 1] != '\n') { offset += pos + 2; continue; }
            pos += 2;

            // count as bulk
            if (pos >= rem || p[pos] != '$') break;
            long clen = 0; size_t buc = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &clen, &buc) != 0) break;
            pos += 1 + buc;
            if (clen < 0) { offset += pos; continue; }
            if ((size_t)clen + 2 > rem - pos) break;
            const char *cptr = p + pos; size_t csz = (size_t)clen;
            pos += csz;
            if (pos + 2 > rem) break;
            if (p[pos] != '\r' || p[pos + 1] != '\n') { offset += pos + 2; continue; }
            pos += 2;

            // parse positive count
            long cnt = 0; int ok = 1; int any = 0; long tmp = 0; int neg = 0;
            for (size_t i = 0; i < csz; i++)
            {
                char ch = cptr[i];
                if (i == 0 && ch == '-') { neg = 1; continue; }
                if (ch < '0' || ch > '9') { ok = 0; break; }
                any = 1; tmp = tmp * 10 + (ch - '0');
            }
            if (!any) ok = 0; cnt = neg ? -tmp : tmp;
            if (!ok || cnt <= 0)
            {
                const char err[] = "-ERR value is not an integer or out of range\r\n";
                if (send_all(fd, err, sizeof(err) - 1) != 0) return -1;
                offset += pos; continue;
            }

            // pop up to cnt elements
            size_t cap = (size_t)cnt;
            char **vals = (char **)calloc(cap, sizeof(char*));
            size_t *vls = (size_t *)calloc(cap, sizeof(size_t));
            if (!vals || !vls) { free(vals); free(vls); return -1; }

            size_t popped = 0; int wrongtype = 0;
            for (long i = 0; i < cnt; i++)
            {
                char *v = NULL; size_t vlen = 0; int rc = db_list_lpop(db, kptr, ksz, &v, &vlen, &wrongtype);
                if (rc < 0 && wrongtype)
                {
                    const char wt[] = "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n";
                    if (send_all(fd, wt, sizeof(wt) - 1) != 0) { free(vals); free(vls); return -1; }
                    // free collected values
                    for (size_t j = 0; j < popped; j++) free(vals[j]);
                    free(vals); free(vls);
                    offset += pos; wrongtype = 1; break;
                }
                if (rc != 0 || !v)
                {
                    break; // no more elements
                }
                vals[popped] = v; vls[popped] = vlen; popped++;
            }
            if (wrongtype)
                continue;

            // write array response
            char h[64]; int hl = snprintf(h, sizeof(h), "*%zu\r\n", popped);
            if (hl <= 0 || (size_t)hl >= sizeof(h)) { for (size_t j=0;j<popped;j++) free(vals[j]); free(vals); free(vls); return -1; }
            if (send_all(fd, h, (size_t)hl) != 0) { for (size_t j=0;j<popped;j++) free(vals[j]); free(vals); free(vls); return -1; }
            for (size_t i = 0; i < popped; i++)
            {
                if (emit_bulk_write(&fd, vals[i], vls[i]) != 0) { for (size_t j=0;j<popped;j++) free(vals[j]); free(vals); free(vls); return -1; }
            }
            for (size_t j = 0; j < popped; j++) free(vals[j]);
            free(vals); free(vls);
            offset += pos; continue;
        }
        else if (arrlen == 2 && cmdlen == 4 && ascii_casecmp_n(cmd, "LPOP", 4) == 0)
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
            if (rc != 0 || v == NULL)
            {
                const char nullbulk[] = "$-1\r\n";
                if (send_all(fd, nullbulk, sizeof(nullbulk) - 1) != 0)
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

            char header[64];
            int hl = snprintf(header, sizeof(header), "$%zu\r\n", vlen);
            if (hl <= 0 || (size_t)hl >= sizeof(header))
            {
                free(v);
                return -1;
            }
            if (send_all(fd, header, (size_t)hl) != 0)
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
        else if (arrlen == 3 && cmdlen == 5 && ascii_casecmp_n(cmd, "BLPOP", 5) == 0)
        {
            // key
            if (pos >= rem || p[pos] != '$')
                break;
            long klen = 0; size_t bu1 = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &klen, &bu1) != 0)
                break;
            pos += 1 + bu1;
            if (klen < 0) { offset += pos; continue; }
            if ((size_t)klen + 2 > rem - pos) break;
            const char *kptr = p + pos; size_t ksz = (size_t)klen;
            pos += ksz;
            if (pos + 2 > rem) break;
            if (p[pos] != '\r' || p[pos + 1] != '\n') { offset += pos + 2; continue; }
            pos += 2;

            // timeout seconds as bulk
            if (pos >= rem || p[pos] != '$') break;
            long tlen = 0; size_t but = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &tlen, &but) != 0) break;
            pos += 1 + but;
            if (tlen < 0) { offset += pos; continue; }
            if ((size_t)tlen + 2 > rem - pos) break;
            const char *tptr = p + pos; size_t tsz = (size_t)tlen;
            pos += tsz;
            if (pos + 2 > rem) break;
            if (p[pos] != '\r' || p[pos + 1] != '\n') { offset += pos + 2; continue; }
            pos += 2;

            long to_secs = 0; int ok = 1; int any = 0; long tmp = 0; int neg = 0;
            for (size_t i = 0; i < tsz; i++)
            {
                char ch = tptr[i];
                if (i == 0 && ch == '-') { neg = 1; continue; }
                if (ch < '0' || ch > '9') { ok = 0; break; }
                any = 1; tmp = tmp * 10 + (ch - '0');
            }
            if (!any) ok = 0; to_secs = neg ? -tmp : tmp;
            if (!ok || to_secs < 0)
            {
                const char err[] = "-ERR value is not an integer or out of range\r\n";
                if (send_all(fd, err, sizeof(err) - 1) != 0) return -1;
                offset += pos; continue;
            }

            // Try immediate pop
            int wrongtype = 0; char *v = NULL; size_t vlen = 0;
            int rc = db_list_lpop(db, kptr, ksz, &v, &vlen, &wrongtype);
            if (rc < 0 && wrongtype)
            {
                const char wt[] = "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n";
                if (send_all(fd, wt, sizeof(wt) - 1) != 0) { if (v) free(v); return -1; }
                offset += pos; if (v) free(v); continue;
            }
            if (rc == 0 && v)
            {
                // reply with [key, elem]
                char h[64];
                int hl = snprintf(h, sizeof(h), "*2\r\n");
                if (hl <= 0 || (size_t)hl >= sizeof(h)) { free(v); return -1; }
                if (send_all(fd, h, (size_t)hl) != 0) { free(v); return -1; }
                hl = snprintf(h, sizeof(h), "$%zu\r\n", ksz);
                if (hl <= 0 || (size_t)hl >= sizeof(h)) { free(v); return -1; }
                if (send_all(fd, h, (size_t)hl) != 0) { free(v); return -1; }
                if (send_all(fd, kptr, ksz) != 0) { free(v); return -1; }
                if (send_all(fd, "\r\n", 2) != 0) { free(v); return -1; }
                hl = snprintf(h, sizeof(h), "$%zu\r\n", vlen);
                if (hl <= 0 || (size_t)hl >= sizeof(h)) { free(v); return -1; }
                if (send_all(fd, h, (size_t)hl) != 0) { free(v); return -1; }
                if (send_all(fd, v, vlen) != 0) { free(v); return -1; }
                if (send_all(fd, "\r\n", 2) != 0) { free(v); return -1; }
                free(v);
                offset += pos; continue;
            }

            // Otherwise, register waiter (0 timeout => infinite)
            int64_t deadline = (to_secs == 0) ? 0 : (now_ms() + (int64_t)to_secs * 1000);
            if (g_srv)
                server_add_waiter(g_srv, c, fd, kptr, ksz, deadline);
            offset += pos; continue;
        }
        else if (arrlen == 4 && cmdlen == 6 && ascii_casecmp_n(cmd, "LRANGE", 6) == 0)
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

            // start index as bulk
            if (pos >= rem || p[pos] != '$')
                break;
            long slen = 0;
            size_t bus = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &slen, &bus) != 0)
                break;
            pos += 1 + bus;
            if (slen < 0)
            {
                offset += pos;
                continue;
            }
            if ((size_t)slen + 2 > rem - pos)
                break;
            const char *sptr = p + pos;
            size_t ssz = (size_t)slen;
            pos += ssz;
            if (pos + 2 > rem)
                break;
            if (p[pos] != '\r' || p[pos + 1] != '\n')
            {
                offset += pos + 2;
                continue;
            }
            pos += 2;

            // stop index as bulk
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

            // parse start/stop numbers
            long start = 0, stop = 0;
            int ok = 1;
            int any = 0;
            long tmp = 0;
            int neg = 0;
            // start
            tmp = 0;
            neg = 0;
            any = 0;
            for (size_t i = 0; i < ssz; i++)
            {
                char ch = sptr[i];
                if (i == 0 && ch == '-')
                {
                    neg = 1;
                    continue;
                }
                if (ch < '0' || ch > '9')
                {
                    ok = 0;
                    break;
                }
                any = 1;
                tmp = tmp * 10 + (ch - '0');
            }
            if (!any)
                ok = 0;
            start = neg ? -tmp : tmp;
            // stop
            tmp = 0;
            neg = 0;
            any = 0;
            for (size_t i = 0; i < tsz; i++)
            {
                char ch = tptr[i];
                if (i == 0 && ch == '-')
                {
                    neg = 1;
                    continue;
                }
                if (ch < '0' || ch > '9')
                {
                    ok = 0;
                    break;
                }
                any = 1;
                tmp = tmp * 10 + (ch - '0');
            }
            if (!any)
                ok = 0;
            stop = neg ? -tmp : tmp;

            if (!ok)
            {
                const char err[] = "-ERR value is not an integer or out of range\r\n";
                if (send_all(fd, err, sizeof(err) - 1) != 0)
                    return -1;
                offset += pos;
                continue;
            }

            size_t cnt = 0;
            int wrongtype = 0;
            if (db_list_range_count(db, kptr, ksz, start, stop, &cnt, &wrongtype) != 0)
            {
                if (wrongtype)
                {
                    const char wt[] = "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n";
                    if (send_all(fd, wt, sizeof(wt) - 1) != 0)
                        return -1;
                }
                else
                {
                    const char empty[] = "*0\r\n";
                    if (send_all(fd, empty, sizeof(empty) - 1) != 0)
                        return -1;
                }
                offset += pos;
                continue;
            }

            char header[64];
            int hl = snprintf(header, sizeof(header), "*%zu\r\n", cnt);
            if (hl <= 0 || (size_t)hl >= sizeof(header))
                return -1;
            if (send_all(fd, header, (size_t)hl) != 0)
                return -1;

            int fd_ctx = fd;
            wrongtype = 0;
            if (cnt > 0)
            {
                if (db_list_range_emit(db, kptr, ksz, start, stop, emit_bulk_write, &fd_ctx, &wrongtype) != 0)
                {
                    // if fails mid-way, close connection by returning error
                    return -1;
                }
            }
            offset += pos;
            continue;
        }
        else if (arrlen == 2 && cmdlen == 3 && ascii_casecmp_n(cmd, "GET", 3) == 0)
        {
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

            const char *vptr = NULL;
            size_t vsz = 0;
            if (db_get(db, kptr, ksz, &vptr, &vsz) == 0)
            {
                char header[64];
                int hl = snprintf(header, sizeof(header), "$%zu\r\n", vsz);
                if (hl <= 0 || (size_t)hl >= sizeof(header))
                    return -1;
                if (send_all(fd, header, (size_t)hl) != 0)
                    return -1;
                if (send_all(fd, vptr, vsz) != 0)
                    return -1;
                if (send_all(fd, "\r\n", 2) != 0)
                    return -1;
            }
            else
            {
                const char nullbulk[] = "$-1\r\n";
                if (send_all(fd, nullbulk, sizeof(nullbulk) - 1) != 0)
                    return -1;
            }
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
