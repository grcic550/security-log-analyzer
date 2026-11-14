#include "cli_utils.h"

#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>


bool parse_positive_size(const char *text, size_t *result) {

    if (text == NULL || result == NULL) {
        return false;
    }

    errno = 0;
    char *end;

    unsigned long number = strtoul(text, &end, 10);

    if (text[0] < '0' || text[0] > '9' || errno == ERANGE || end == text || *end != '\0' ||
        number == 0 || number > SIZE_MAX) {
        return false;
    }

    *result = (size_t)number;

    return true;
}

bool parse_positive_double(const char *text, double *result) {

    if (text == NULL || result == NULL) {
        return false;
    }

    errno = 0;
    char *end;

    double number = strtod(text, &end);

    if (text[0] < '0' || text[0] > '9' || errno == ERANGE || end == text || *end != '\0' ||
        !isfinite(number) || number <= 0.0) {
        return false;
    }

    *result = number;
    return true;
}