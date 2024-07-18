#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "internal.h"

void
replace_char_all (const char *input, char *output, char find, char replacement) {
  while (*input != '\0') {
    *output++ = *input == find ? replacement : *input;
    input++;
  }

  *output = '\0';
}

void
replace_all (char *input, const char *find, const char *replacement) {
  char *p = strstr(input, find);

  if (p != NULL) {
    size_t len1 = strlen(find);
    size_t len2 = strlen(replacement);

    if (len1 != len2) {
      memmove(p + len2, p + len1, strlen(p + len1) + 1);
    }

    memcpy(p, replacement, len2);
  }
}

int
hex2chr (char c) {
  switch (c) {
  case '0' ... '9':
    return c - '0';

  case 'a' ... 'f':
    return c - 'a' + 10;

  case 'A' ... 'F':
    return c - 'A' + 10;

  default:
    return 0;
  }
}

void
decode_uri_component (const char *input, char *output) {
  while (*input != '\0') {
    if (input[0] != '%') {
      *output++ = *input++;
      continue;
    }

    *output++ = (char) (hex2chr(input[1]) * 16 + hex2chr(input[2]));
    input += 3;
  }

  *output = '\0';
}

void
decode_uri_form (const char *input, char *output) {
  replace_char_all(input, output, '+', ' ');
  decode_uri_component(output, output);
}

int
math_min (int a, int b) {
  return a < b ? a : b;
}

uint64_t
date_now () {
  struct timeval tv;

  gettimeofday(&tv, NULL);

  return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}
