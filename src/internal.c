#include "internal.h"

int
chr2hex (char c) {
  switch (c) {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      return c - '0';

    case 'a':
    case 'b':
    case 'c':
    case 'd':
    case 'e':
    case 'f':
      return c - 'a';

    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
      return c - 'A';
  }

  return 0;
}

void
decode_uri (char *input, char *output) {
  while (*input != '\0') {
    while ((*input != '%') && (*input != '+')) {
      *output++ = *input++;
      continue;
    }

    if (*input == '+') {
      *output++ = ' ';
      input++;
      continue;
    }

    input++;

    if (*input == '%') {
      *output++ = *input++;
    } else {
      *output++ = (char) chr2hex(input[0]) * 16 + chr2hex(input[1]);
      input++;
    }

    input++;
  }

  *output = '\0';
}
