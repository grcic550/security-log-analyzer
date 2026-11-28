#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "detector.h"
#include "entries.h"
#include "ip_table.h"

typedef struct {
    size_t threshold;
    CountAlertCallback callback;
    void *user_context;
    size_t *alerts_found;
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

static size_t hash_username(const char *username, size_t bucket_count) {

    unsigned long hash = 5381;
    int c = 0;

    while ((c = (unsigned char)*username++) != 0) {
        hash = ((hash << 5) + hash) + (size_t)c;
    }

    return hash % bucket_count;
}

static bool username_frequency_decrement(UsernameFrequencyTable *table, const char *username) {

    if (table == NULL || username == NULL || table->buckets == NULL || table->bucket_count == 0) {
        return false;
    }

    size_t index = hash_username(username, table->bucket_count);

    UsernameNode **link = &table->buckets[index];

    while (*link != NULL) {

        UsernameNode *current = *link;

        if (strcmp(current->username, username) == 0) {
            current->frequency--;

            if (current->frequency == 0) {
                *link = current->next;
                free(current);
                table->distinct_count--;
            }

            return true;
        }

        link = &current->next;
    }

    return false;
}

static bool username_frequency_resize(UsernameFrequencyTable *table){

    if (table == NULL || table->buckets == NULL || table->bucket_count == 0 ||
        table->bucket_count > SIZE_MAX / 2){
            return false;
    }

    size_t new_bucket_count = table->bucket_count * 2;

    UsernameNode **new_buckets = calloc(new_bucket_count, sizeof(*new_buckets));

    if (new_buckets == NULL){
        return false;
    }

    for (size_t i = 0; i < table->bucket_count; i++){

        UsernameNode *current = table->buckets[i];

        while (current != NULL){
            UsernameNode *next = current->next;
            size_t new_index = hash_username(current->username, new_bucket_count);

            current->next = new_buckets[new_index];
            new_buckets[new_index] = current;

            current = next;
        }
    }

    free(table->buckets);
    table->buckets = new_buckets;
    table->bucket_count = new_bucket_count;

    return true;
}


static bool username_frequency_increment(UsernameFrequencyTable *table, const char *username) {
    if (table == NULL || username == NULL || table->buckets == NULL || table->bucket_count == 0) {

        return false;
    }

    size_t index = hash_username(username, table->bucket_count);

    UsernameNode *current = table->buckets[index];

    while (current != NULL) {

        if (strcmp(current->username, username) == 0) {

            current->frequency++;
            return true;
        }

        current = current->next;
    }

    if ((double)(table->distinct_count + 1) / (double)table->bucket_count >= 0.75){
        if (!username_frequency_resize(table)){
            return false;
        }

        index = hash_username(username, table->bucket_count);
    }

    UsernameNode *new_node = malloc(sizeof(*new_node));

    if (new_node == NULL) {
        return false;
    }

    new_node->frequency = 1;
    new_node->username = username;
    table->distinct_count++;

    new_node->next = table->buckets[index];
    table->buckets[index] = new_node;

    return true;
}

static bool username_frequency_init(UsernameFrequencyTable *table, size_t bucket_count) {

    if (table == NULL || bucket_count == 0) {
        return false;
    }

    if (bucket_count > SIZE_MAX / 2){
        return false;
    }

    UsernameNode **new_buckets = calloc(bucket_count, sizeof(*new_buckets));

    if (new_buckets == NULL) {
        return false;
    }

    table->buckets = new_buckets;
    table->bucket_count = bucket_count;
    table->distinct_count = 0;

    return true;
}

static void username_frequency_destroy(UsernameFrequencyTable *table) {

    if (table == NULL) {
        return;
    }

    for (size_t i = 0; i < table->bucket_count; i++) {

        UsernameNode *current = table->buckets[i];

        while (current != NULL) {
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

static int compare_account_targeting_events(const void *a, const void *b) {

    const AccountTargetingEvent *first = a;
    const AccountTargetingEvent *second = b;

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

static void collect_account_targeting_event(const LogEventView *event, void *context) {
    AccountTargetingCollector *collector = context;

    if (collector->allocation_failed) {
        return;
    }

    if (event->result == AUTH_FAILURE && event->username != NULL && event->username[0] != '\0') {

        if (collector->count >= collector->capacity) {

            size_t new_capacity = collector->capacity == 0 ? 8 : 2 * collector->capacity;

            AccountTargetingEvent *temp = realloc(collector->events, new_capacity * sizeof(*temp));

            if (temp == NULL) {
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

static bool analyze_account_targeting_episode(
    const AccountTargetingEvent *events,
    size_t ep_start,
    size_t ep_end,
    size_t min_distinct_usernames,
    double window_seconds,
    AccountTargetingCallback callback,
    void *context,
    size_t *alerts_found
){
    UsernameFrequencyTable frequencies = {0};

    if (!username_frequency_init(&frequencies, 16)){
        return false;
    }

    bool found_peak = false;
    AccountTargetingAlert best = {0};
    size_t left = ep_start;

    for (size_t right = ep_start; right < ep_end; right++){
        while (difftime(events[right].timestamp, events[left].timestamp) >
        window_seconds){
            if(!username_frequency_decrement(
                &frequencies,
                events[left].username
            )){
                username_frequency_destroy(&frequencies);
                return false;
            }
            left++;
        }

        if (!username_frequency_increment(
            &frequencies,
            events[right].username
        )){
            username_frequency_destroy(&frequencies);
            return false;
        }

        if (frequencies.distinct_count >= min_distinct_usernames){

            size_t attempts = right - left + 1;
            size_t distinct = frequencies.distinct_count;

            bool is_better = !found_peak ||
                            distinct > best.distinct_usernames ||
                            (distinct == best.distinct_usernames && attempts > best.failed_attempts);
            if (is_better){

                best.ip_address = events[ep_start].ip_address;
                best.window_start = events[left].timestamp;
                best.window_end = events[right].timestamp;
                best.failed_attempts = attempts;
                best.distinct_usernames = distinct;

                found_peak = true;
            }
        }
    }

    if (found_peak){
        callback(&best, context);
        (*alerts_found)++;
    }

    username_frequency_destroy(&frequencies);
    return true;
}

static bool analyze_account_targeting_events(AccountTargetingCollector *collector,
                                             size_t min_distinct_usernames, double window_seconds,
                                             AccountTargetingCallback callback, void *context,
                                             size_t *alerts_found) {

    size_t start = 0;

    while (start < collector->count) {

        size_t end = start + 1;

        while(end < collector->count &&
            strcmp(collector->events[start].ip_address,
                    collector->events[end].ip_address
            ) == 0){

                end++;
        }

        size_t ep_start = start;
        while(ep_start < end){
            size_t ep_end = ep_start + 1;
            while (ep_end < end &&
                    difftime(collector->events[ep_end].timestamp,
                            collector->events[ep_end - 1].timestamp        
                    ) <= window_seconds){

                    ep_end++;
            }

            if (ep_end - ep_start >= min_distinct_usernames){
                if (!analyze_account_targeting_episode(
                    collector->events,
                    ep_start,
                    ep_end,
                    min_distinct_usernames,
                    window_seconds,
                    callback,
                    context,
                    alerts_found
                )){
                    return false;
                }
            }

            ep_start = ep_end;
        }

        start = end;
    }

    return true;
}

bool detector_find_account_targeting_in_store(const LogStore *store, size_t min_distinct_usernames,
                                              double window_seconds,
                                              AccountTargetingCallback callback, void *context,
                                              size_t *alerts_found) {

    if (min_distinct_usernames == 0 || store == NULL || !isfinite(window_seconds) ||
        window_seconds <= 0.0 || alerts_found == NULL || callback == NULL) {
        return false;
    }

    *alerts_found = 0;
    AccountTargetingCollector collector = {0};

    log_store_foreach(store, collect_account_targeting_event, &collector);

    if (collector.allocation_failed) {
        free(collector.events);
        return false;
    }

    if (collector.count > 1) {
        qsort(collector.events, collector.count, sizeof(*collector.events),
              compare_account_targeting_events);
    }

    if (!analyze_account_targeting_events(&collector, min_distinct_usernames, window_seconds,
                                          callback, context, alerts_found)) {
        free(collector.events);
        return false;
    }

    free(collector.events);

    return true;
}

static bool find_peak_burst_in_episode(
    const FailedEvent *events,
    size_t ep_start,
    size_t ep_end,
    double window_seconds,
    FailureWindowPeak *out_peak
){

    if (events == NULL || ep_start >= ep_end || !isfinite(window_seconds) ||
        window_seconds <= 0.0 || out_peak == NULL    
    ){
        return false;
    }

    size_t left = ep_start;
    FailureWindowPeak best = {0};

    for (size_t right = ep_start; right < ep_end; right++){

        while (difftime(events[right].timestamp, events[left].timestamp) > window_seconds){
            left++;
        }

        size_t attempts = right - left + 1;

        if (attempts > best.failed_attempts){
            best.failed_attempts = attempts;
            best.window_start = events[left].timestamp;
            best.window_end = events[right].timestamp;
        }
    }

    *out_peak = best;
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

    if (event->result == AUTH_FAILURE && collector->count < collector->capacity) {

        collector->events[collector->count].timestamp = event->timestamp;
        collector->events[collector->count].ip_address = event->ip_address;

        collector->count++;
    }
}

static void analyze_collected_failures(FailureCollector *collector, size_t threshold,
                                         double window_seconds, BurstAlertsCallback callback, void *context, size_t *alerts_found) {

    if (threshold == 0 || !isfinite(window_seconds) || window_seconds <= 0.0){
        return;
    }

    if (collector->count > 1){
        qsort(collector->events, collector->count, sizeof(*collector->events), compare_failed_events);
    }

    size_t start = 0;

    while (start < collector->count){

        size_t end = start + 1;

        while (end < collector->count && strcmp(
            collector->events[start].ip_address, collector->events[end].ip_address
        ) == 0){
            end++;
        }

        size_t ep_start = start;

        while (ep_start < end){
            size_t ep_end = ep_start + 1;
            
            while(ep_end < end && difftime(
                collector->events[ep_end].timestamp, collector->events[ep_end - 1].timestamp
            ) <= window_seconds){
                ep_end++;
            }

            if (ep_end - ep_start >= threshold){

                FailureWindowPeak peak = {0};
                if(find_peak_burst_in_episode(
                    collector->events,
                    ep_start,
                    ep_end,
                    window_seconds,
                    &peak
                ) && peak.failed_attempts >= threshold){

                    BurstAlert alert = {
                        .ip_address = collector->events[start].ip_address,
                        .window_start = peak.window_start,
                        .window_end = peak.window_end,
                        .failed_attempts = peak.failed_attempts
                    };

                    callback(&alert, context);
                    (*alerts_found)++;
                }
            }
            ep_start = ep_end;
        }
        start = end;
    }
}

bool detector_find_burst_alerts_in_store(
    const LogStore *store, size_t threshold, double window_seconds,
    BurstAlertsCallback callback, void *context,
    size_t *alerts_found
){

    if (store == NULL || threshold == 0 || !isfinite(window_seconds) ||
        window_seconds <= 0.0 || callback == NULL || alerts_found == NULL
    ){
        return false;
    }

    *alerts_found = 0;

    size_t failure_count = log_store_count_by_event(store, AUTH_FAILURE);

    if (failure_count == 0){
        return true;
    }

    if (failure_count > SIZE_MAX / sizeof(FailedEvent)){
        return false;
    }

    FailedEvent *events = malloc(failure_count * sizeof(*events));

    if (events == NULL){
        return false;
    }  

    FailureCollector collector = {
        .events = events,
        .count = 0,
        .capacity = failure_count
    };

    log_store_foreach(
        store,
        collect_failed_event,
        &collector
    );

    analyze_collected_failures(
        &collector,
        threshold,
        window_seconds,
        callback,
        context,
        alerts_found
    );

    free(events);
    return true;
}

static void detect_ip(const char *ip_address, size_t failed_attempts, void *context) {
    DetectorContext *config = context;

    if (is_suspicious(failed_attempts, config->threshold)) {

        CountAlert alert = {
            .ip_address = ip_address,
            .failed_attempts = failed_attempts
        };

        config->callback(&alert, config->user_context);
        (*config->alerts_found)++;
    }
}

bool detector_find_count_alerts(
    const IpTable *table, size_t threshold,
    CountAlertCallback callback, void *context,
    size_t *alerts_found
){

    if (table == NULL || threshold == 0 || callback == NULL || alerts_found == NULL){
        return false;
    }

    *alerts_found = 0;

    DetectorContext config = {
        .threshold = threshold,
        .alerts_found = alerts_found,
        .callback = callback,
        .user_context = context
    };

    ip_table_foreach(
        table,
        detect_ip,
        &config
    );

    return true;
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

    if (timestamps == NULL || !isfinite(window_seconds) || window_seconds <= 0.0) {
        return 0;
    }

    FailureWindowPeak peak = {0};

    if (!find_peak_failure_window(
        timestamps,
        count,
        window_seconds,
        &peak
    )){
        return 0;
    }

    return peak.failed_attempts;
}

bool find_peak_failure_window(
    const time_t *timestamps, size_t count,
    double window_seconds, FailureWindowPeak *out_peak
){

    if (timestamps == NULL || count == 0 ||
        !isfinite(window_seconds) || window_seconds <= 0.0 || out_peak == NULL
    ){
        return false;
    }

    size_t left = 0;
    FailureWindowPeak best = {0};

    for (size_t right = 0; right < count; right++){

        while (difftime(timestamps[right], timestamps[left]) > window_seconds){
            left++;
        }

        size_t attempts = right - left + 1;

        if (attempts > best.failed_attempts){
            best.failed_attempts = attempts;
            best.window_start = timestamps[left];
            best.window_end = timestamps[right];
        }

    }

    *out_peak = best;
    return true;
}

DetectorConfig detector_config_default(void){
    
    DetectorConfig config = {
        .burst_threshold = 3,
        .burst_window_seconds = 60.0,
        .count_threshold = 3,
        .target_min_usernames = 3,
        .target_window_seconds = 60.0
    };

    return config;
}

bool detector_config_is_valid(const DetectorConfig *config){

    if (config == NULL || config->burst_threshold == 0 ||
        config->count_threshold == 0 || config->target_min_usernames == 0||
        !isfinite(config->burst_window_seconds) || !isfinite(config->target_window_seconds) ||
        config->burst_window_seconds <= 0.0 || config->target_window_seconds <= 0.0
    ){
        return false;
    }

    return true;
}

