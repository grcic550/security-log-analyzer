#ifndef CLI_UTILS_H
#define CLI_UTILS_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    DETECTOR_ALL,
    DETECTOR_COUNT,
    DETECTOR_BURST,
    DETECTOR_ACCOUNT_TARGETING
} DetectorMode;

typedef enum {
    LOG_FORMAT_SIMPLE,
    LOG_FORMAT_SSH
} LogFormat;

bool parse_positive_size(const char *text, size_t *result);

bool parse_positive_double(const char *text, double *result);

#endif