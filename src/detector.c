#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "detector.h"
#include "entries.h"
#include "ip_table.h"

typedef struct {
    size_t threshold;
    size_t alert_count;
} DetectorContext;

typedef struct {
    const char *ip_address;
    time_t timestamp;
} FailedEvent;

typedef struct {
    FailedEvent *events;
    size_t count;
    size_t capacity;
} FailureCollector;

static int compare_failed_events(const void *a, const void *b) {

    const FailedEvent *first = a;
    const FailedEvent *second = b;
    int result = strcmp(first->ip_address, second->ip_address);

    if (result == 0) {

        if (first->timestamp < second->timestamp) {
            return -1;
        }

        if (first->timestamp > second->timestamp) {
            return 1;
        }

        return 0;
    }

    return result;
}

static void collect_failed_event(const LogEventView *event, void *context) {
    FailureCollector *collector = context;

    if (event->result == AUTH_FAILURE) {

        collector->events[collector->count].timestamp = event->timestamp;
        collector->events[collector->count].ip_address = event->ip_address;

        collector->count++;
    }
}

size_t detector_analyze_windows(size_t threshold, double window_seconds) {

    size_t capacity = get_log_count();

    if (capacity == 0) {
        return 0;
    }

    FailedEvent *events = malloc(capacity * sizeof(*events));

    if (events == NULL) {
        fprintf(stderr, "Failed to allocate memory for events!\n");
        return 0;
    }

    FailureCollector collector = {.events = events, .count = 0, .capacity = capacity};

    log_management_foreach(collect_failed_event, &collector);

    if (collector.count == 0) {
        free(events);
        return 0;
    }

    qsort(collector.events, collector.count, sizeof(*collector.events), compare_failed_events);

    time_t *group_timestamps = malloc(collector.count * sizeof(*group_timestamps));

    if (group_timestamps == NULL) {
        fprintf(stderr, "Failed to allocate memory for timestamps group!\n");
        free(events);
        return 0;
    }

    size_t start = 0;
    size_t count = 0;

    while (start < collector.count) {

        size_t end = start + 1;

        while (end < collector.count &&
               strcmp(collector.events[start].ip_address, collector.events[end].ip_address) == 0) {
            end++;
        }

        size_t group_count = end - start;

        for (size_t j = 0; j < group_count; j++) {
            group_timestamps[j] = collector.events[start + j].timestamp;
        }

        size_t max_attempts = max_failures_in_window(group_timestamps, group_count, window_seconds);

        if (threshold > 0 && max_attempts >= threshold) {
            printf("\n[BRUTE FORCE] %s - %zu failures within %g seconds\n",
                   collector.events[start].ip_address, max_attempts, window_seconds);

            count++;
        }

        start = end;
    }

    free(group_timestamps);
    free(events);
    return count;
}

static void detect_ip(const char *ip_address, size_t failed_attempts, void *context) {
    DetectorContext *config = context;

    if (is_suspicious(failed_attempts, config->threshold)) {
        printf("[ALERT] %-20s %zu failed attempts\n", ip_address, failed_attempts);

        config->alert_count++;
    }
}

size_t detector_print_alerts(const IpTable *table, size_t threshold) {
    if (table == NULL || threshold == 0) {
        return 0;
    }

    DetectorContext config = {.threshold = threshold, .alert_count = 0};

    printf("\n==========  SECURITY ALERTS ==========\n");

    ip_table_foreach(table, detect_ip, &config);

    if (config.alert_count == 0) {
        printf("No suspicious IP addresses found.\n");
    }

    return config.alert_count;
}

bool is_suspicious(size_t failed_attempts, size_t threshold) {

    if (threshold == 0) {
        return false;
    }

    return failed_attempts >= threshold;
}

bool has_failure_burst(const time_t *timestamps, size_t count, size_t threshold,
                       double window_seconds) {

    return threshold > 0 && max_failures_in_window(timestamps, count, window_seconds) >= threshold;
}

size_t max_failures_in_window(const time_t *timestamps, size_t count, double window_seconds) {

    if (timestamps == NULL || window_seconds <= 0.0) {
        return 0;
    }

    size_t max_attempts = 0;
    size_t left = 0;

    for (size_t right = 0; right < count; right++) {
        size_t attempts = 0;

        while (difftime(timestamps[right], timestamps[left]) > window_seconds) {
            left++;
        }

        attempts = right - left + 1;

        if (attempts > max_attempts) {
            max_attempts = attempts;
        }
    }
    return max_attempts;
}