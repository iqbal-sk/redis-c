#include "commands.h"

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
        if (*pos >= rem || p[*pos] != '$') return -1;
        long blen = 0; size_t bu = 0;
        if (parse_crlf_int(p + *pos + 1, rem - *pos - 1, &blen, &bu) != 0) return -1;
        *pos += 1 + bu;
        if (blen >= 0)
        {
            if ((size_t)blen + 2 > rem - *pos) return -1;
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
            if (!eol) break;
            offset = (size_t)(eol - (c->buf + offset)) + offset + 1;
            continue;
        }
        if (rem < 2) break;
        long arrlen = 0; size_t used = 0;
        if (parse_crlf_int(p + 1, rem - 1, &arrlen, &used) != 0)
            break;
        size_t pos = 1 + used;
        if (arrlen < 1) { offset += pos; continue; }

        // First bulk is command
        if (pos >= rem || p[pos] != '$') break;
        long blen = 0; size_t bu = 0;
        if (parse_crlf_int(p + pos + 1, rem - pos - 1, &blen, &bu) != 0) break;
        pos += 1 + bu;
        if (blen < 0) { offset += pos; continue; }
        if ((size_t)blen + 2 > rem - pos) break;
        const char *cmd = p + pos; size_t cmdlen = (size_t)blen;
        pos += (size_t)blen;
        if (pos + 2 > rem) break;
        if (p[pos] != '\r' || p[pos+1] != '\n') { offset += pos + 2; continue; }
        pos += 2;

        if (arrlen == 1 && cmdlen == 4 && ascii_casecmp_n(cmd, "PING", 4) == 0)
        {
            const char pong[] = "+PONG\r\n";
            if (send_all(fd, pong, sizeof(pong) - 1) != 0) return -1;
            offset += pos; continue;
        }
        else if (arrlen == 2 && cmdlen == 4 && ascii_casecmp_n(cmd, "ECHO", 4) == 0)
        {
            if (pos >= rem || p[pos] != '$') break;
            long arglen = 0; size_t abu = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &arglen, &abu) != 0) break;
            pos += 1 + abu;
            if (arglen < 0) { offset += pos; continue; }
            if ((size_t)arglen + 2 > rem - pos) break;
            const char *arg = p + pos; size_t argsz = (size_t)arglen;
            pos += argsz;
            if (pos + 2 > rem) break;
            if (p[pos] != '\r' || p[pos+1] != '\n') { offset += pos + 2; continue; }
            pos += 2;

            char header[64];
            int hl = snprintf(header, sizeof(header), "$%zu\r\n", argsz);
            if (hl <= 0 || (size_t)hl >= sizeof(header)) return -1;
            if (send_all(fd, header, (size_t)hl) != 0) return -1;
            if (send_all(fd, arg, argsz) != 0) return -1;
            if (send_all(fd, "\r\n", 2) != 0) return -1;

            offset += pos; continue;
        }
        else if (arrlen >= 3 && cmdlen == 3 && ascii_casecmp_n(cmd, "SET", 3) == 0)
        {
            // key
            if (pos >= rem || p[pos] != '$') break;
            long klen = 0; size_t bu1 = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &klen, &bu1) != 0) break;
            pos += 1 + bu1;
            if (klen < 0) { offset += pos; continue; }
            if ((size_t)klen + 2 > rem - pos) break;
            const char *kptr = p + pos; size_t ksz = (size_t)klen;
            pos += ksz;
            if (pos + 2 > rem) break;
            if (p[pos] != '\r' || p[pos+1] != '\n') { offset += pos + 2; continue; }
            pos += 2;
            // value
            if (pos >= rem || p[pos] != '$') break;
            long vlen = 0; size_t bu2 = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &vlen, &bu2) != 0) break;
            pos += 1 + bu2;
            if (vlen < 0) { offset += pos; continue; }
            if ((size_t)vlen + 2 > rem - pos) break;
            const char *vptr = p + pos; size_t vsz = (size_t)vlen;
            pos += vsz;
            if (pos + 2 > rem) break;
            if (p[pos] != '\r' || p[pos+1] != '\n') { offset += pos + 2; continue; }
            pos += 2;

            int64_t expires_at = 0;
            long remaining = arrlen - 3; // options
            while (remaining >= 2)
            {
                if (pos >= rem || p[pos] != '$') break;
                long onamelen = 0; size_t buo = 0;
                if (parse_crlf_int(p + pos + 1, rem - pos - 1, &onamelen, &buo) != 0) break;
                pos += 1 + buo;
                if (onamelen < 0) { offset += pos; continue; }
                if ((size_t)onamelen + 2 > rem - pos) break;
                const char *oname = p + pos; size_t onamensz = (size_t)onamelen;
                pos += onamensz;
                if (pos + 2 > rem) break;
                if (p[pos] != '\r' || p[pos+1] != '\n') { offset += pos + 2; continue; }
                pos += 2;
                if (pos >= rem || p[pos] != '$') break;
                long oval_len = 0; size_t buv = 0;
                if (parse_crlf_int(p + pos + 1, rem - pos - 1, &oval_len, &buv) != 0) break;
                pos += 1 + buv;
                if (oval_len < 0) { offset += pos; continue; }
                if ((size_t)oval_len + 2 > rem - pos) break;
                const char *oval = p + pos; size_t oval_sz = (size_t)oval_len;
                pos += oval_sz;
                if (pos + 2 > rem) break;
                if (p[pos] != '\r' || p[pos+1] != '\n') { offset += pos + 2; continue; }
                pos += 2;

                // parse ttl
                long ttl_num = 0; int oknum = 1;
                long tmp = 0; int neg = 0; int any = 0;
                for (size_t i = 0; i < oval_sz; i++)
                {
                    char ch = oval[i];
                    if (i == 0 && ch == '-') { neg = 1; continue; }
                    if (ch < '0' || ch > '9') { oknum = 0; break; }
                    any = 1; tmp = tmp * 10 + (ch - '0');
                }
                if (!any || neg || !oknum) tmp = -1;
                ttl_num = tmp;

                if (onamensz == 2 && ascii_casecmp_n(oname, "EX", 2) == 0)
                {
                    if (ttl_num <= 0) { const char err[] = "-ERR syntax error\r\n"; if (send_all(fd, err, sizeof(err)-1)!=0) return -1; offset += pos; continue; }
                    expires_at = now_ms() + (int64_t)ttl_num * 1000;
                }
                else if (onamensz == 2 && ascii_casecmp_n(oname, "PX", 2) == 0)
                {
                    if (ttl_num <= 0) { const char err[] = "-ERR syntax error\r\n"; if (send_all(fd, err, sizeof(err)-1)!=0) return -1; offset += pos; continue; }
                    expires_at = now_ms() + (int64_t)ttl_num;
                }
                else
                {
                    const char err[] = "-ERR syntax error\r\n";
                    if (send_all(fd, err, sizeof(err) - 1) != 0) return -1;
                    offset += pos; continue;
                }
                remaining -= 2;
            }

            db_set(db, kptr, ksz, vptr, vsz, expires_at);
            const char ok[] = "+OK\r\n";
            if (send_all(fd, ok, sizeof(ok) - 1) != 0) return -1;
            offset += pos; continue;
        }
        else if (arrlen >= 3 && cmdlen == 5 && ascii_casecmp_n(cmd, "RPUSH", 5) == 0)
        {
            // key
            if (pos >= rem || p[pos] != '$') break;
            long klen = 0; size_t bu1 = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &klen, &bu1) != 0) break;
            pos += 1 + bu1;
            if (klen < 0) { offset += pos; continue; }
            if ((size_t)klen + 2 > rem - pos) break;
            const char *kptr = p + pos; size_t ksz = (size_t)klen;
            pos += ksz;
            if (pos + 2 > rem) break;
            if (p[pos] != '\r' || p[pos+1] != '\n') { offset += pos + 2; continue; }
            pos += 2;

            // one or more elements
            size_t newlen = 0; int wrongtype = 0;
            long remaining = arrlen - 2;
            for (long i = 0; i < remaining; i++)
            {
                if (pos >= rem || p[pos] != '$') { wrongtype = 0; break; }
                long elen = 0; size_t bu2 = 0;
                if (parse_crlf_int(p + pos + 1, rem - pos - 1, &elen, &bu2) != 0) { wrongtype = 0; break; }
                pos += 1 + bu2;
                if (elen < 0) { offset += pos; continue; }
                if ((size_t)elen + 2 > rem - pos) { wrongtype = 0; break; }
                const char *eptr = p + pos; size_t esz = (size_t)elen;
                pos += esz;
                if (pos + 2 > rem) { wrongtype = 0; break; }
                if (p[pos] != '\r' || p[pos+1] != '\n') { offset += pos + 2; continue; }
                pos += 2;

                if (db_list_rpush(db, kptr, ksz, eptr, esz, &newlen, &wrongtype) != 0)
                {
                    // failure (e.g., alloc). We'll send generic error.
                    const char err[] = "-ERR rpush failed\r\n";
                    if (send_all(fd, err, sizeof(err) - 1) != 0) return -1;
                    offset += pos; break;
                }
                if (wrongtype)
                {
                    const char wt[] = "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n";
                    if (send_all(fd, wt, sizeof(wt) - 1) != 0) return -1;
                    offset += pos; break;
                }
            }

            char ibuf[64];
            int il = snprintf(ibuf, sizeof(ibuf), ":%zu\r\n", newlen);
            if (il <= 0 || (size_t)il >= sizeof(ibuf)) return -1;
            if (send_all(fd, ibuf, (size_t)il) != 0) return -1;
            offset += pos; continue;
        }
        else if (arrlen == 2 && cmdlen == 3 && ascii_casecmp_n(cmd, "GET", 3) == 0)
        {
            if (pos >= rem || p[pos] != '$') break;
            long klen = 0; size_t bu1 = 0;
            if (parse_crlf_int(p + pos + 1, rem - pos - 1, &klen, &bu1) != 0) break;
            pos += 1 + bu1;
            if (klen < 0) { offset += pos; continue; }
            if ((size_t)klen + 2 > rem - pos) break;
            const char *kptr = p + pos; size_t ksz = (size_t)klen;
            pos += ksz;
            if (pos + 2 > rem) break;
            if (p[pos] != '\r' || p[pos+1] != '\n') { offset += pos + 2; continue; }
            pos += 2;

            const char *vptr = NULL; size_t vsz = 0;
            if (db_get(db, kptr, ksz, &vptr, &vsz) == 0)
            {
                char header[64];
                int hl = snprintf(header, sizeof(header), "$%zu\r\n", vsz);
                if (hl <= 0 || (size_t)hl >= sizeof(header)) return -1;
                if (send_all(fd, header, (size_t)hl) != 0) return -1;
                if (send_all(fd, vptr, vsz) != 0) return -1;
                if (send_all(fd, "\r\n", 2) != 0) return -1;
            }
            else
            {
                const char nullbulk[] = "$-1\r\n";
                if (send_all(fd, nullbulk, sizeof(nullbulk) - 1) != 0) return -1;
            }
            offset += pos; continue;
        }
        else
        {
            const char err[] = "-ERR unknown command\r\n";
            if (send_all(fd, err, sizeof(err) - 1) != 0) return -1;
            long to_skip = arrlen - 1;
            if (to_skip > 0)
            {
                if (skip_bulk_items(p, rem, &pos, to_skip) != 0)
                    break;
            }
            offset += pos; continue;
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
