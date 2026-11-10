#ifndef DETECTOR_H
#define DETECTOR_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "ip_table.h"

bool is_suspicious(size_t failed_attempts, size_t threshold);
bool has_failure_burst(const time_t *timestamps, size_t count, size_t threshold,
                       double window_seconds);

size_t max_failures_in_window(const time_t *timestamps, size_t count, double window_seconds);
size_t detector_analyze_windows(size_t threshold, double window_seconds);
size_t detector_print_alerts(const IpTable *table, size_t threshold);
#endif