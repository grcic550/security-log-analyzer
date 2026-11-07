#ifndef DETECTOR_H
#define DETECTOR_H

#include <stdbool.h>
#include <stddef.h>

bool is_suspicious(size_t failed_attempts, size_t threshold);

#endif