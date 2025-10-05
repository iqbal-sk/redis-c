#include "resp.h"

int send_all(int fd, const char *data, size_t len)
{
    size_t off = 0;
    while (off < len)
    {
        ssize_t w = write(fd, data + off, len - off);
        if (w <= 0)
            return -1;
        off += (size_t)w;
    }
    return 0;
}

int parse_crlf_int(const char *s, size_t len, long *out, size_t *consumed)
{
    if (len < 3) return -1; // at least one digit + CRLF
    int neg = 0;
    size_t i = 0;
    if (s[i] == '-') { neg = 1; i++; }
    if (i >= len) return -1;
    long val = 0;
    int any = 0;
    for (; i + 1 < len; i++)
    {
        char ch = s[i];
        if (ch == '\r')
        {
            if (s[i+1] != '\n') return -1;
            i += 2; // include CRLF
            if (!any) return -1;
            *out = neg ? -val : val;
            *consumed = i;
            return 0;
        }
        if (ch < '0' || ch > '9') return -1;
        any = 1;
        val = val * 10 + (ch - '0');
    }
    return -1;
}

int ascii_casecmp_n(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == '\0') return 0;
    }
    return 0;
}

int reply_simple(int fd, const char *s)
{
    char h[256];
    int l = snprintf(h, sizeof(h), "+%s\r\n", s ? s : "");
    if (l <= 0 || (size_t)l >= sizeof(h)) return -1;
    return send_all(fd, h, (size_t)l);
}

int reply_error(int fd, const char *s)
{
    char h[256];
    int l = snprintf(h, sizeof(h), "-%s\r\n", s ? s : "ERR");
    if (l <= 0 || (size_t)l >= sizeof(h)) return -1;
    return send_all(fd, h, (size_t)l);
}

int reply_int(int fd, long long n)
{
    char h[64];
    int l = snprintf(h, sizeof(h), ":%lld\r\n", n);
    if (l <= 0 || (size_t)l >= sizeof(h)) return -1;
    return send_all(fd, h, (size_t)l);
}

int reply_bulk(int fd, const char *data, size_t len)
{
    char h[64];
    int l = snprintf(h, sizeof(h), "$%zu\r\n", len);
    if (l <= 0 || (size_t)l >= sizeof(h)) return -1;
    if (send_all(fd, h, (size_t)l) != 0) return -1;
    if (len > 0 && send_all(fd, data, len) != 0) return -1;
    if (send_all(fd, "\r\n", 2) != 0) return -1;
    return 0;
}

int reply_bulk_cstr(int fd, const char *s)
{
    size_t len = s ? strlen(s) : 0;
    return reply_bulk(fd, s ? s : "", len);
}

int reply_null_bulk(int fd)
{
    static const char nb[] = "$-1\r\n";
    return send_all(fd, nb, sizeof(nb) - 1);
}

int reply_array_header(int fd, size_t count)
{
    char h[64];
    int l = snprintf(h, sizeof(h), "*%zu\r\n", count);
    if (l <= 0 || (size_t)l >= sizeof(h)) return -1;
    return send_all(fd, h, (size_t)l);
}

int reply_null_array(int fd)
{
    static const char na[] = "*-1\r\n";
    return send_all(fd, na, sizeof(na) - 1);
}

int parse_i64_ascii(const char *s, size_t len, int64_t *out)
{
    if (!s || len == 0 || !out) return -1;
    int neg = 0; size_t i = 0; int any = 0;
    if (s[0] == '-') { neg = 1; i = 1; }
    int64_t v = 0;
    for (; i < len; i++)
    {
        char ch = s[i];
        if (ch < '0' || ch > '9') return -1;
        any = 1;
        int digit = ch - '0';
        // basic overflow-safe accumulation for 64-bit signed
        if (v > (INT64_MAX - digit) / 10) return -1;
        v = v * 10 + digit;
    }
    if (!any) return -1;
    *out = neg ? -v : v;
    return 0;
}

int parse_u64_ascii(const char *s, size_t len, uint64_t *out)
{
    if (!s || len == 0 || !out) return -1;
    uint64_t v = 0; int any = 0;
    for (size_t i = 0; i < len; i++)
    {
        char ch = s[i];
        if (ch < '0' || ch > '9') return -1;
        any = 1;
        int digit = ch - '0';
        if (v > (UINT64_MAX - (uint64_t)digit) / 10ULL) return -1;
        v = v * 10ULL + (uint64_t)digit;
    }
    if (!any) return -1;
    *out = v;
    return 0;
}

int parse_double_ascii(const char *s, size_t len, double *out)
{
    if (!s || len == 0 || !out) return -1;
    int neg = 0; size_t i = 0; int any = 0; int seen_dot = 0;
    uint64_t int_part = 0, frac_part = 0; int frac_digits = 0;
    if (s[0] == '-') { neg = 1; i = 1; }
    for (; i < len; i++)
    {
        char ch = s[i];
        if (ch == '.')
        {
            if (seen_dot) return -1;
            seen_dot = 1; continue;
        }
        if (ch < '0' || ch > '9') return -1;
        any = 1;
        if (!seen_dot)
        {
            int_part = int_part * 10ULL + (uint64_t)(ch - '0');
        }
        else
        {
            // accumulate fractional with precision limit to avoid huge exponents
            if (frac_digits < 18)
            {
                frac_part = frac_part * 10ULL + (uint64_t)(ch - '0');
                frac_digits++;
            }
        }
    }
    if (!any) return -1;
    double v = (double)int_part;
    if (seen_dot && frac_digits > 0)
    {
        double denom = 1.0;
        for (int d = 0; d < frac_digits; d++) denom *= 10.0;
        v += ((double)frac_part) / denom;
    }
    *out = neg ? -v : v;
    return 0;
}

int parse_timeout_seconds_to_ms(const char *s, size_t len, int64_t *out_ms)
{
    if (!s || !out_ms) return -1;
    // Only non-negative, up to 3 fractional digits. Truncate beyond milliseconds.
    size_t i = 0; int any = 0; int seen_dot = 0; int frac_digits = 0;
    uint64_t int_part = 0, frac_part = 0;
    for (; i < len; i++)
    {
        char ch = s[i];
        if (ch == '.')
        {
            if (seen_dot) return -1;
            seen_dot = 1; continue;
        }
        if (ch == '-') return -1; // non-negative only
        if (ch < '0' || ch > '9') return -1;
        any = 1;
        if (!seen_dot)
            int_part = int_part * 10ULL + (uint64_t)(ch - '0');
        else if (frac_digits < 3)
        {
            frac_part = frac_part * 10ULL + (uint64_t)(ch - '0');
            frac_digits++;
        }
        else
        {
            // ignore extra fractional digits beyond millisecond precision
        }
    }
    if (!any) return -1;
    uint64_t scale = 1;
    if (frac_digits == 0) scale = 1000;
    else if (frac_digits == 1) scale = 100;
    else if (frac_digits == 2) scale = 10;
    else scale = 1;
    // Check overflow for ms conversion
    if (int_part > (uint64_t)(INT64_MAX / 1000)) return -1;
    int64_t ms = (int64_t)int_part * 1000;
    if (frac_part > (uint64_t)(INT64_MAX - ms) / scale) return -1;
    ms += (int64_t)(frac_part * scale);
    *out_ms = ms;
    return 0;
}
