#ifndef DETECTOR_H
#define DETECTOR_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "entries.h"
#include "ip_table.h"

typedef struct {
    const char *ip_address;

    time_t window_start;
    time_t window_end;

    size_t failed_attempts;
    size_t distinct_usernames;

} AccountTargetingAlert;

typedef struct FailureWindowPeak{
    time_t window_start;
    time_t window_end;
    size_t failed_attempts;
} FailureWindowPeak;

typedef struct {
    const char *ip_address;
    time_t window_start;
    time_t window_end;
    size_t failed_attempts;
} BurstAlert;

typedef struct {
    const char *ip_address;
    size_t failed_attempts;
} CountAlert;

typedef struct {
    size_t count_threshold;
    size_t burst_threshold;
    double burst_window_seconds;
    size_t target_min_usernames;
    double target_window_seconds;
} DetectorConfig;

DetectorConfig detector_config_default(void);
bool detector_config_is_valid(const DetectorConfig *config);

typedef void (*CountAlertCallback)(const CountAlert *alert, void *context);

typedef void (*BurstAlertsCallback)(const BurstAlert *alert, void *context);

typedef void (*AccountTargetingCallback)(const AccountTargetingAlert *alert, void *context);

bool detector_find_burst_alerts_in_store(
    const LogStore *store, size_t threshold, double window_seconds,
    BurstAlertsCallback callback, void *context,
    size_t *alerts_found
);

bool find_peak_failure_window(const time_t *timestamps, size_t count,
                                double window_seconds, FailureWindowPeak *out_peak);

bool detector_find_account_targeting_in_store(const LogStore *store, size_t min_distinct_usernames,
                                              double window_seconds,
                                              AccountTargetingCallback callback, void *context,
                                              size_t *alerts_found);

bool is_suspicious(size_t failed_attempts, size_t threshold);
bool has_failure_burst(const time_t *timestamps, size_t count, size_t threshold,
                       double window_seconds);

size_t max_failures_in_window(const time_t *timestamps, size_t count, double window_seconds);
bool detector_find_count_alerts(
    const IpTable *table, size_t threshold,
    CountAlertCallback callback, void *context,
    size_t *alerts_found
);

#endif