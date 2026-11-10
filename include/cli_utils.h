#ifndef CLI_UTILS_H
#define CLI_UTILS_H

#include <stdbool.h>
#include <stddef.h>

bool parse_positive_size(const char *text, size_t *result);

bool parse_positive_double(const char *text, double *result);

#endif