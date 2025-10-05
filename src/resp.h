#pragma once
#include "common.h"

int send_all(int fd, const char *data, size_t len);
int parse_crlf_int(const char *s, size_t len, long *out, size_t *consumed);
int ascii_casecmp_n(const char *a, const char *b, size_t n);

// RESP reply helpers
int reply_simple(int fd, const char *s);
int reply_error(int fd, const char *s);
int reply_int(int fd, long long n);
int reply_bulk(int fd, const char *data, size_t len);
int reply_bulk_cstr(int fd, const char *s);
int reply_null_bulk(int fd);
int reply_array_header(int fd, size_t count);
int reply_null_array(int fd);

// Argument parsing helpers (ASCII parsers, no locale)
int parse_i64_ascii(const char *s, size_t len, int64_t *out);
int parse_u64_ascii(const char *s, size_t len, uint64_t *out);
int parse_double_ascii(const char *s, size_t len, double *out);
// Parses a non-negative seconds value that may have up to 3 fractional digits, returns milliseconds
int parse_timeout_seconds_to_ms(const char *s, size_t len, int64_t *out_ms);
