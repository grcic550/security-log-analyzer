#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

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

typedef struct {
    const char *ip_address;
    const char *username;
    time_t timestamp;
} AccountTargetingEvent;

typedef struct {
    AccountTargetingEvent *events;
    size_t count;
    size_t capacity;
    bool allocation_failed;
} AccountTargetingCollector;

typedef struct UsernameNode {
    const char *username;
    size_t frequency;
    struct UsernameNode *next;
} UsernameNode;

typedef struct {
    UsernameNode **buckets;
    size_t bucket_count;
    size_t distinct_count;
} UsernameFrequencyTable;


static size_t hash_username(
    const char *username,
    size_t bucket_count
){

    unsigned long hash = 5381;
    int c = 0;

    while ((c = (unsigned char)*username++) != 0){
        hash = ((hash << 5) + hash) + (size_t)c;
    }

    return hash % bucket_count;
}

static bool username_frequency_decrement(
    UsernameFrequencyTable *table,
    const char *username
){

    if (table == NULL || username == NULL || 
        table->buckets == NULL || table->bucket_count == 0){
            return false;
    }

    size_t index = hash_username(username, table->bucket_count);

    UsernameNode *current = table->buckets[index];

    while (current != NULL){

        if (strcmp(current->username, username) == 0){

            if (current->frequency == 0){
                return false;
            }

            current->frequency--;

            if (current->frequency == 0){
                table->distinct_count--;
            }

            return true;
        }

        current = current->next;
    }

    return false;
}


static bool username_frequency_increment(
    UsernameFrequencyTable *table,
    const char *username
){
    if (table == NULL || username == NULL || 
        table->buckets == NULL || table->bucket_count == 0){

        return false;
    }

    size_t index = hash_username(username, table->bucket_count);

    UsernameNode *current = table->buckets[index];

    while (current != NULL){

        if (strcmp(current->username, username) == 0){
            
            if (current->frequency == 0){
                table->distinct_count++;
            }

            current->frequency++;
            return true;
        }

        current = current->next;
    }

    UsernameNode *new_node = malloc(sizeof(*new_node));

    if (new_node == NULL){
        return false;
    }

    new_node->frequency = 1;
    new_node->username = username;
    table->distinct_count++;

    new_node->next = table->buckets[index];
    table->buckets[index] = new_node;

    return true;
}

static bool username_frequency_init(
    UsernameFrequencyTable *table,
    size_t bucket_count
) {

    if (table == NULL || bucket_count == 0){
        return false;
    }

    UsernameNode **new_buckets = calloc(bucket_count, sizeof(*new_buckets));

    if (new_buckets == NULL){
        return false;    
    }

    table->buckets = new_buckets;
    table->bucket_count = bucket_count;
    table->distinct_count = 0;

    return true;
}

static void username_frequency_destroy(
    UsernameFrequencyTable *table
){

    if (table == NULL){
        return;
    }

    for (size_t i = 0; i < table->bucket_count; i++){
        
        UsernameNode *current = table->buckets[i];

        while(current != NULL){
            UsernameNode *next = current->next;

            free(current);

            current = next;
        }
    }
    free(table->buckets);
    table->buckets = NULL;
    table->bucket_count = 0;
    table->distinct_count = 0;
}

static int compare_account_targeting_events(
    const void *a,
    const void *b
) {

    const AccountTargetingEvent *first = a;
    const AccountTargetingEvent *second = b;

    int result = strcmp(first->ip_address, second->ip_address);

    if (result == 0){

        if (first->timestamp < second->timestamp){
            return -1;
        }

        if (first->timestamp > second->timestamp){
            return 1;
        }

        return 0;
    }

    return result;
}

static void collect_account_targeting_event(
    const LogEventView *event,
    void *context
) {
    AccountTargetingCollector *collector = context;

    if (collector->allocation_failed){
        return;
    }

    if (event->result == AUTH_FAILURE && event->username != NULL &&
        event->username[0] != '\0'){

        if (collector->count >= collector->capacity){
            
            size_t new_capacity = collector->capacity == 0 ? 8 : 2 * collector->capacity;

            AccountTargetingEvent *temp = realloc(collector->events, new_capacity * sizeof(*temp));

            if (temp == NULL){
                collector->allocation_failed = true;
                return;
            }
            
            collector->events = temp;
            collector->capacity = new_capacity;
        }

        collector->events[collector->count].ip_address = event->ip_address;
        collector->events[collector->count].username = event->username;
        collector->events[collector->count].timestamp = event->timestamp;

        collector->count++;
    }
}

bool detector_find_account_targeting(
    size_t min_distinct_usernames,
    double window_seconds,
    AccountTargetingCallback callback,
    void *context,
    size_t *alerts_found
) {

    if (min_distinct_usernames == 0 ||
        !isfinite(window_seconds) ||
        window_seconds <= 0.0 ||
        callback == NULL ||
        alerts_found == NULL    
    ) {
        return false;
    }

    *alerts_found = 0;
    AccountTargetingCollector collector = {0};

    log_management_foreach(
        collect_account_targeting_event,
        &collector
    );

    if (collector.allocation_failed) {
        free(collector.events);
        return false;
    }

    if (collector.count > 1){
        qsort(
            collector.events,
            collector.count,
            sizeof(*collector.events),
            compare_account_targeting_events
        );
    }

    size_t start = 0;

    while (start < collector.count){
        UsernameFrequencyTable frequencies = {0};

        if (!username_frequency_init(&frequencies, 16)){
            free(collector.events);
            return false;
        }

        size_t end = start + 1;

        while (end < collector.count && strcmp(collector.events[start].ip_address, collector.events[end].ip_address) == 0){
            end++;
        }

        size_t left = start;

        for (size_t right = start; right < end; right++){

            while(difftime(
                collector.events[right].timestamp, 
                collector.events[left].timestamp
            ) > window_seconds){

                if (!username_frequency_decrement(
                    &frequencies,
                    collector.events[left].username
                )){
                    username_frequency_destroy(&frequencies);
                    free(collector.events);
                    return false;
                }

                left++;
            }

            if (!username_frequency_increment(
                &frequencies,
                collector.events[right].username
            )) {
                username_frequency_destroy(&frequencies);
                free(collector.events);
                return false;
            }

            if (frequencies.distinct_count >= min_distinct_usernames){
                AccountTargetingAlert alert = {0};

                alert.ip_address = collector.events[start].ip_address;
                alert.window_start = collector.events[left].timestamp;
                alert.window_end = collector.events[right].timestamp;
                alert.failed_attempts = right - left + 1;
                alert.distinct_usernames = frequencies.distinct_count;

                callback(&alert, context);
                (*alerts_found)++;
                break;
            }
        }
        start = end;

        username_frequency_destroy(&frequencies);
    }

    free(collector.events);
    return true;
}

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