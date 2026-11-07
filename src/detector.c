#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "detector.h"
#include "ip_table.h"

typedef struct {
    size_t threshold;
    size_t alert_count;
} DetectorContext;

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

    printf("\n========== SECURITY ALERTS ==========\n");

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
