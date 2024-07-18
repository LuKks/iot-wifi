#ifndef WIFI_INTERNAL_H
#define WIFI_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void
replace_char_all (const char *input, char *output, char find, char replacement);

void
replace_all (char *input, const char *find, const char *replacement);

void
decode_uri_component (const char *input, char *output);

void
decode_uri_form (const char *input, char *output);

int
math_min (int a, int b);

uint64_t
date_now ();

#ifdef __cplusplus
}
#endif

#endif // WIFI_INTERNAL_H
