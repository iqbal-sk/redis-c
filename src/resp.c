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

