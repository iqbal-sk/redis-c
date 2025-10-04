#pragma once
#include "common.h"

int send_all(int fd, const char *data, size_t len);
int parse_crlf_int(const char *s, size_t len, long *out, size_t *consumed);
int ascii_casecmp_n(const char *a, const char *b, size_t n);

