#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "detector.h"

typedef struct {
    size_t threshold;
    size_t alert_count;
} DetectorContext;

bool is_suspicious(size_t failed_attempts, size_t threshold) {

    if (threshold == 0) {
        return false;
    }

    if (failed_attempts >= threshold) {
        return true;
    }

    return false;
}
