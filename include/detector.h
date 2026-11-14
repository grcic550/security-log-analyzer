#ifndef DETECTOR_H
#define DETECTOR_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "ip_table.h"

typedef struct {
    const char *ip_address;

    time_t window_start;
    time_t window_end;

    size_t failed_attempts;
    size_t distinct_usernames;

} AccountTargetingAlert;

typedef void (*AccountTargetingCallback)(
    const AccountTargetingAlert *alert,
    void *context
);

bool detector_find_account_targeting(
    size_t min_distinct_usernames,
    double window_seconds,
    AccountTargetingCallback callback,
    void *context,
    size_t *alerts_found
);
bool is_suspicious(size_t failed_attempts, size_t threshold);
bool has_failure_burst(const time_t *timestamps, size_t count, size_t threshold,
                       double window_seconds);

size_t max_failures_in_window(const time_t *timestamps, size_t count, double window_seconds);
size_t detector_analyze_windows(size_t threshold, double window_seconds);
size_t detector_print_alerts(const IpTable *table, size_t threshold);
#endif