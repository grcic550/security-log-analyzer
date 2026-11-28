#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "detector.h"
#include "entries.h"

typedef struct {
    size_t alerts_received;
    time_t expected_start;
    time_t expected_end;
    size_t expected_failures;
    size_t expected_distinct;
} AccountTargetingTestContext;

typedef struct {
    bool received_ip20;
    bool received_ip30;
    size_t alerts_received;
} MultipleAlertsTestContext;

typedef struct {
    AccountTargetingAlert alerts[4];
    size_t count;
} RecordedAlertsContext;

typedef struct {
    BurstAlert alerts[4];
    size_t count;
}RecordedBurstAlertsContext;

typedef struct {
    CountAlert alerts[4];
    size_t count;
} RecordedCountAlertContext;

typedef struct {
    BurstAlert alerts[64];
    size_t count;
} BigBurstRecorder;

static void record_big_burst_alert(const BurstAlert *alert, void *context){

    BigBurstRecorder *rec = context;

    assert(alert != NULL);
    assert(rec != NULL);

    if (rec->count < 64){
        rec->alerts[rec->count++] = *alert;
    }
}

static void record_count_alert(const CountAlert *alert, void *context){

    RecordedCountAlertContext *ctx = context;

    assert(alert != NULL);
    assert(ctx != NULL);
    if (ctx->count < 4){
        ctx->alerts[ctx->count++] = *alert;
    }
}

static void record_burst_alert(const BurstAlert *alert, void *context){

    RecordedBurstAlertsContext *rec = context;

    assert(alert != NULL);
    assert(rec != NULL);

    if (rec->count < 4){
        rec->alerts[rec->count++] = *alert;
    }
}

static void test_is_suspicious(void) {

    assert(is_suspicious(0, 3) == false);
    assert(is_suspicious(2, 3) == false);
    assert(is_suspicious(3, 3) == true);
    assert(is_suspicious(10, 3) == true);
    assert(is_suspicious(3, 0) == false);
}

static void test_detection_report(void) {

    IpTable *table = ip_table_create(2);

    assert(table != NULL);

    assert(ip_table_insert(table, "192.168.1.10"));

    assert(ip_table_insert(table, "192.168.1.20"));
    assert(ip_table_insert(table, "192.168.1.20"));
    assert(ip_table_insert(table, "192.168.1.20"));

    RecordedCountAlertContext context = {0};
    size_t alerts_found = 0;

    assert(detector_find_count_alerts(table, 3, record_count_alert, &context, &alerts_found));
    assert(alerts_found == 1);
    assert(context.count == 1);
    assert(strcmp(context.alerts[0].ip_address, "192.168.1.20") == 0);
    assert(context.alerts[0].failed_attempts == 3);

    RecordedCountAlertContext context2 = {0};
    size_t alerts_found2 = 0;

    assert(detector_find_count_alerts(
        table, 
        5,
        record_count_alert,
        &context2,
        &alerts_found2
    ));

    assert(alerts_found2 == 0);
    assert(context2.count == 0);
    
    assert(!detector_find_count_alerts(
        NULL,
        3,
        record_count_alert,
        &context,
        &alerts_found
    ));
    assert(!detector_find_count_alerts(
        table,
        0,
        record_count_alert,
        &context,
        &alerts_found
    ));
    assert(!detector_find_count_alerts(
        table,
        3,
        NULL,
        &context,
        &alerts_found
    ));
    assert(!detector_find_count_alerts(
        table,
        3,
        record_count_alert,
        &context,
        NULL
    ));

    ip_table_destroy(table);
}

static void test_failure_burst(void) {

    time_t timestamps[] = {1000, 1020, 1050, 1300};

    assert(has_failure_burst(timestamps, 4, 3, 60.0));
    assert(!has_failure_burst(timestamps, 4, 4, 60.0));
    assert(!has_failure_burst(timestamps, 4, 3, 40.0));
    assert(has_failure_burst(timestamps, 4, 2, 40.0));
    assert(!has_failure_burst(timestamps, 4, 0, 20.0));
    assert(!has_failure_burst(timestamps, 4, 3, 0.0));
    assert(!has_failure_burst(NULL, 4, 3, 60.0));

    assert(!has_failure_burst(NULL, 2, 2, 60.0));

    time_t timestamps_3[] = {1000, 1060};

    assert(has_failure_burst(timestamps_3, 2, 2, 60.0));
    assert(!has_failure_burst(timestamps_3, 2, 2, 59.0));
}

static void test_failures_in_window(void) {

    time_t timestamps[] = {1000, 1010, 1020, 1030, 1040, 2000};

    assert(max_failures_in_window(timestamps, 6, 60.0) == 5);

    assert(max_failures_in_window(timestamps, 6, 15.0) == 2);

    assert(max_failures_in_window(timestamps, 6, 5.0) == 1);

    assert(max_failures_in_window(timestamps, 6, 0.0) == 0);

    assert(max_failures_in_window(NULL, 6, 60.0) == 0);

    assert(max_failures_in_window(timestamps, 0, 60.0) == 0);

    time_t timestamps2[] = {1000, 1060};

    assert(max_failures_in_window(timestamps2, 2, 60.0) == 2);
}

static void verify_account_targeting_alert(const AccountTargetingAlert *alert, void *context) {
    AccountTargetingTestContext *test = context;

    assert(alert != NULL);
    assert(alert->ip_address != NULL);
    assert(strcmp(alert->ip_address, "192.168.1.20") == 0);

    assert(alert->failed_attempts == test->expected_failures);
    assert(alert->distinct_usernames == test->expected_distinct);
    assert(alert->window_start == test->expected_start);
    assert(alert->window_end == test->expected_end);
    assert(alert->window_start <= alert->window_end);

    test->alerts_received++;
}

static void test_detect_account_targeting(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(
        log_store_add(store, table, (time_t)1000, "192.168.1.20", "root", "server1", AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1010, "192.168.1.20", "admin", "server1",
                         AUTH_FAILURE));

    assert(
        log_store_add(store, table, (time_t)1020, "192.168.1.20", "test", "server1", AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1030, "192.168.1.20", "backup", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1040, "192.168.1.20", "support", "server1",
                         AUTH_FAILURE));

    AccountTargetingTestContext context = {0};
    size_t alerts_found = 0;

    context.expected_distinct = 5;
    context.expected_failures = 5;
    context.expected_start = 1000;
    context.expected_end = 1040;

    assert(detector_find_account_targeting_in_store(store, 5, 60.0, verify_account_targeting_alert,
                                                    &context, &alerts_found));

    assert(alerts_found == 1);
    assert(context.alerts_received == 1);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_account_targeting_same_username(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(
        log_store_add(store, table, (time_t)1000, "192.168.1.20", "root", "server1", AUTH_FAILURE));

    assert(
        log_store_add(store, table, (time_t)1010, "192.168.1.20", "root", "server1", AUTH_FAILURE));

    assert(
        log_store_add(store, table, (time_t)1020, "192.168.1.20", "root", "server1", AUTH_FAILURE));

    assert(
        log_store_add(store, table, (time_t)1030, "192.168.1.20", "root", "server1", AUTH_FAILURE));

    assert(
        log_store_add(store, table, (time_t)1040, "192.168.1.20", "root", "server1", AUTH_FAILURE));

    size_t alerts_found = 0;
    AccountTargetingTestContext context = {0};

    context.expected_distinct = 0;
    context.expected_failures = 5;
    context.expected_start = 1000;
    context.expected_end = 1040;

    assert(detector_find_account_targeting_in_store(store, 5, 60.0, verify_account_targeting_alert,
                                                    &context, &alerts_found));

    assert(alerts_found == 0);
    assert(context.alerts_received == 0);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_account_targeting_outside_window(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(
        log_store_add(store, table, (time_t)1000, "192.168.1.20", "root", "server1", AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1100, "192.168.1.20", "admin", "server1",
                         AUTH_FAILURE));

    assert(
        log_store_add(store, table, (time_t)1200, "192.168.1.20", "test", "server1", AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1300, "192.168.1.20", "backup", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1400, "192.168.1.20", "support", "server1",
                         AUTH_FAILURE));

    size_t alerts_found = 0;
    AccountTargetingTestContext context = {0};

    context.expected_distinct = 5;
    context.expected_failures = 5;
    context.expected_start = 1000;
    context.expected_end = 1400;

    assert(detector_find_account_targeting_in_store(store, 5, 60.0, verify_account_targeting_alert,
                                                    &context, &alerts_found));

    assert(alerts_found == 0);
    assert(context.alerts_received == 0);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_account_targeting_different_IP(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(
        log_store_add(store, table, (time_t)1000, "192.168.1.20", "root", "server1", AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1010, "192.168.1.20", "admin", "server1",
                         AUTH_FAILURE));

    assert(
        log_store_add(store, table, (time_t)1020, "192.168.1.30", "test", "server1", AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1030, "192.168.1.30", "backup", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1040, "192.168.1.30", "support", "server1",
                         AUTH_FAILURE));

    size_t alerts_found = 0;
    AccountTargetingTestContext context = {0};

    context.expected_distinct = 5;
    context.expected_failures = 5;
    context.expected_start = 1000;
    context.expected_end = 1040;

    assert(detector_find_account_targeting_in_store(store, 5, 60.0, verify_account_targeting_alert,
                                                    &context, &alerts_found));

    assert(alerts_found == 0);
    assert(context.alerts_received == 0);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_account_targeting_window_expiration(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(
        log_store_add(store, table, (time_t)1000, "192.168.1.20", "root", "server1", AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1010, "192.168.1.20", "admin", "server1",
                         AUTH_FAILURE));

    assert(
        log_store_add(store, table, (time_t)1020, "192.168.1.20", "test", "server1", AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1100, "192.168.1.20", "backup", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1110, "192.168.1.20", "support", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1120, "192.168.1.20", "deploy", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1130, "192.168.1.20", "postgres", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1140, "192.168.1.20", "guest", "server1",
                         AUTH_FAILURE));

    AccountTargetingTestContext context = {0};
    size_t alerts_found = 0;

    context.expected_distinct = 5;
    context.expected_failures = 5;
    context.expected_start = 1100;
    context.expected_end = 1140;

    assert(detector_find_account_targeting_in_store(store, 5, 60.0, verify_account_targeting_alert,
                                                    &context, &alerts_found));

    assert(alerts_found == 1);
    assert(context.alerts_received == 1);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_account_targeting_out_of_order(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(log_store_add(store, table, (time_t)1040, "192.168.1.20", "support", "server1",
                         AUTH_FAILURE));

    assert(
        log_store_add(store, table, (time_t)1000, "192.168.1.20", "root", "server1", AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1030, "192.168.1.20", "backup", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1010, "192.168.1.20", "admin", "server1",
                         AUTH_FAILURE));

    assert(
        log_store_add(store, table, (time_t)1020, "192.168.1.20", "test", "server1", AUTH_FAILURE));

    AccountTargetingTestContext context = {0};
    size_t alerts_found = 0;

    context.expected_distinct = 5;
    context.expected_failures = 5;
    context.expected_start = 1000;
    context.expected_end = 1040;

    assert(detector_find_account_targeting_in_store(store, 5, 60.0, verify_account_targeting_alert,
                                                    &context, &alerts_found));

    assert(alerts_found == 1);
    assert(context.alerts_received == 1);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void verify_multiple_targeting_alerts(const AccountTargetingAlert *alert, void *context) {

    MultipleAlertsTestContext *test = context;

    assert(test != NULL);
    assert(alert != NULL);
    assert(alert->ip_address != NULL);

    if (strcmp(alert->ip_address, "192.168.1.20") == 0) {
        assert(!test->received_ip20);

        assert(alert->window_start == (time_t)1000);
        assert(alert->window_end == (time_t)1040);
        assert(alert->failed_attempts == 3);
        assert(alert->distinct_usernames == 3);

        test->received_ip20 = true;
    } else if (strcmp(alert->ip_address, "192.168.1.30") == 0) {
        assert(!test->received_ip30);

        assert(alert->window_start == (time_t)1010);
        assert(alert->window_end == (time_t)1050);
        assert(alert->failed_attempts == 3);
        assert(alert->distinct_usernames == 3);

        test->received_ip30 = true;
    } else {
        assert(!"Unexpected IP address in account-targeting alert");
    }

    test->alerts_received++;
}

static void test_account_targeting_multiple_alerts(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(
        log_store_add(store, table, (time_t)1000, "192.168.1.20", "root", "server1", AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1010, "192.168.1.30", "admin", "server1",
                         AUTH_FAILURE));

    assert(
        log_store_add(store, table, (time_t)1020, "192.168.1.20", "test", "server1", AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1030, "192.168.1.30", "backup", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1040, "192.168.1.20", "support", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1050, "192.168.1.30", "guest", "server1",
                         AUTH_FAILURE));

    MultipleAlertsTestContext context = {0};
    size_t alerts_found = 0;

    assert(detector_find_account_targeting_in_store(
        store, 3, 60.0, verify_multiple_targeting_alerts, &context, &alerts_found));

    assert(context.received_ip20);
    assert(context.received_ip30);
    assert(alerts_found == 2);
    assert(context.alerts_received == 2);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_account_targeting_ignores_success(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(
        log_store_add(store, table, (time_t)1000, "192.168.1.20", "root", "server1", AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1010, "192.168.1.20", "admin", "server1",
                         AUTH_SUCCESS));

    assert(
        log_store_add(store, table, (time_t)1020, "192.168.1.20", "test", "server1", AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1030, "192.168.1.20", "backup", "server1",
                         AUTH_SUCCESS));

    assert(log_store_add(store, table, (time_t)1040, "192.168.1.20", "support", "server1",
                         AUTH_FAILURE));

    AccountTargetingTestContext context = {0};
    size_t alerts_found = 0;

    context.expected_distinct = 3;
    context.expected_failures = 3;
    context.expected_start = 1000;
    context.expected_end = 1040;

    assert(detector_find_account_targeting_in_store(store, 3, 60.0, verify_account_targeting_alert,
                                                    &context, &alerts_found));

    assert(alerts_found == 1);
    assert(context.alerts_received == 1);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_account_targeting_window_boundary(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(
        log_store_add(store, table, (time_t)1000, "192.168.1.20", "root", "server1", AUTH_FAILURE));

    assert(log_store_add(store, table, (time_t)1060, "192.168.1.20", "admin", "server1",
                         AUTH_FAILURE));

    AccountTargetingTestContext context = {0};
    size_t alerts_found = 0;

    context.expected_distinct = 2;
    context.expected_failures = 2;
    context.expected_start = 1000;
    context.expected_end = 1060;

    assert(detector_find_account_targeting_in_store(store, 2, 60.0, verify_account_targeting_alert,
                                                    &context, &alerts_found));

    assert(alerts_found == 1);
    assert(context.alerts_received == 1);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_account_targeting_invalid_parameters(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    AccountTargetingTestContext context = {0};
    size_t alerts_found = 0;

    assert(!detector_find_account_targeting_in_store(store, 0, 60.0, verify_account_targeting_alert,
                                                     &context, &alerts_found));

    assert(!detector_find_account_targeting_in_store(store, 3, 0.0, verify_account_targeting_alert,
                                                     &context, &alerts_found));

    assert(!detector_find_account_targeting_in_store(
        store, 3, -60.0, verify_account_targeting_alert, &context, &alerts_found));

    assert(!detector_find_account_targeting_in_store(store, 3, NAN, verify_account_targeting_alert,
                                                     &context, &alerts_found));

    assert(!detector_find_account_targeting_in_store(
        store, 3, INFINITY, verify_account_targeting_alert, &context, &alerts_found));

    assert(
        !detector_find_account_targeting_in_store(store, 3, 60.0, NULL, &context, &alerts_found));

    assert(!detector_find_account_targeting_in_store(store, 3, 60.0, verify_account_targeting_alert,
                                                     &context, NULL));

    log_store_destroy(store);
}

static void test_detector_find_account_targeting_in_store(void) {

    LogStore *store1 = log_store_create();
    assert(store1 != NULL);

    LogStore *store2 = log_store_create();
    assert(store2 != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(log_store_add(store1, table, (time_t)1000, "192.168.1.20", "root", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store1, table, (time_t)1010, "192.168.1.20", "admin", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store1, table, (time_t)1040, "192.168.1.20", "support", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store2, table, (time_t)1110, "192.168.1.20", "root", "server1",
                         AUTH_FAILURE));

    MultipleAlertsTestContext context1 = {0};
    size_t alerts_found1 = 0;

    assert(detector_find_account_targeting_in_store(
        store1, 3, 60.0, verify_multiple_targeting_alerts, &context1, &alerts_found1));

    assert(log_store_get_count(store1) == 3);
    assert(log_store_count_by_event(store1, AUTH_FAILURE) == 3);
    assert(context1.alerts_received == 1);

    MultipleAlertsTestContext context2 = {0};
    size_t alerts_found2 = 0;

    assert(detector_find_account_targeting_in_store(
        store2, 3, 60.0, verify_multiple_targeting_alerts, &context2, &alerts_found2));

    assert(log_store_get_count(store2) == 1);
    assert(log_store_count_by_event(store2, AUTH_FAILURE) == 1);
    assert(context2.alerts_received == 0);

    log_store_destroy(store1);
    log_store_destroy(store2);
    ip_table_destroy(table);
}

static void test_detector_analyze_windows_in_store(void) {

    LogStore *store1 = log_store_create();
    assert(store1 != NULL);

    IpTable *table1 = ip_table_create(2);
    assert(table1 != NULL);

    LogStore *store2 = log_store_create();
    assert(store2 != NULL);

    IpTable *table2 = ip_table_create(2);
    assert(table2 != NULL);

    assert(log_store_add(store1, table1, (time_t)1000, "192.168.1.20", "root", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store1, table1, (time_t)1020, "192.168.1.20", "admin", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store1, table1, (time_t)1040, "192.168.1.20", "support", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store2, table2, (time_t)1000, "912.168.1.20", "backup", "server1",
                         AUTH_FAILURE));

    RecordedBurstAlertsContext rec1 = {0};
    size_t found1 = 0;

    assert(detector_find_burst_alerts_in_store(store1, 3, 60.0, record_burst_alert, &rec1, &found1));
    assert(found1 == 1);
    assert(rec1.count == 1);
    assert(strcmp(rec1.alerts[0].ip_address, "192.168.1.20") == 0);
    assert(rec1.alerts[0].failed_attempts == 3);
    assert(rec1.alerts[0].window_start == 1000);
    assert(rec1.alerts[0].window_end == 1040);

    RecordedBurstAlertsContext rec2 = {0};
    size_t found2 = 0;

    assert(detector_find_burst_alerts_in_store(store2, 3, 60.0, record_burst_alert, &rec2, &found2));
    assert(found2 == 0);
    assert(rec2.count == 0);


    assert(!detector_find_burst_alerts_in_store(
        NULL,
        3,
        60.0,
        record_burst_alert,
        &rec1,
        &found1
    ));
    assert(!detector_find_burst_alerts_in_store(
        store1,
        0,
        60.0,
        record_burst_alert,
        &rec1,
        &found1
    ));
    assert(!detector_find_burst_alerts_in_store(
        store1,
        3,
        0.0,
        record_burst_alert,
        &rec1,
        &found1
    ));
    assert(!detector_find_burst_alerts_in_store(
        store1,
        3,
        NAN,
        record_burst_alert,
        &rec1,
        &found1
    ));
    assert(!detector_find_burst_alerts_in_store(
        store1,
        3,
        60.0,
        NULL,
        &rec1,
        &found1
    ));
    assert(!detector_find_burst_alerts_in_store(
        store1,
        3,
        60.0,
        record_burst_alert,
        &rec1,
        NULL
    ));

    log_store_destroy(store1);
    log_store_destroy(store2);
    ip_table_destroy(table1);
    ip_table_destroy(table2);
}

static void test_account_targeting_peak_not_first_match(void){

    IpTable *table = ip_table_create(8);
    assert(table != NULL);

    LogStore *store = log_store_create();
    assert(store != NULL);

    assert(log_store_add(
        store,
        table,
        (time_t)1000,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)1010,
        "192.168.1.20",
        "admin",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)1020,
        "192.168.1.20",
        "test",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)1030,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)1040,
        "192.168.1.20",
        "backup",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)1050,
        "192.168.1.20",
        "deploy",
        "server1",
        AUTH_FAILURE
    ));

    AccountTargetingTestContext context = {0};
    size_t alerts_found = 0;

    context.expected_distinct = 5;
    context.expected_failures = 6;
    context.expected_start = 1000;
    context.expected_end = 1050;

    assert(detector_find_account_targeting_in_store(
        store,
        3,
        60.0,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(alerts_found == 1);
    assert(context.alerts_received == 1);

    ip_table_destroy(table);
    log_store_destroy(store);
}

static void test_account_targeting_tie_breaks_by_attempts(void){

    IpTable *table = ip_table_create(8);
    assert(table != NULL);

    LogStore *store = log_store_create();
    assert(store != NULL);

    assert(log_store_add(
        store,
        table,
        (time_t)1000,
        "192.168.1.20",
        "a",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)1010,
        "192.168.1.20",
        "b",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)1020,
        "192.168.1.20",
        "c",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)1030,
        "192.168.1.20",
        "a",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)1040,
        "192.168.1.20",
        "b",
        "server1",
        AUTH_FAILURE
    ));

    AccountTargetingTestContext context = {0};
    size_t alerts_found = 0;

    context.expected_distinct = 3;
    context.expected_failures = 5;
    context.expected_start = 1000;
    context.expected_end = 1040;

    assert(detector_find_account_targeting_in_store(
        store,
        3,
        60.0,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(alerts_found == 1);
    assert(context.alerts_received == 1);

    ip_table_destroy(table);
    log_store_destroy(store);
}

static void verify_multiple_episodes_alerts(
    const AccountTargetingAlert *alert,
    void *context
){

    RecordedAlertsContext *test = context;

    if (test->count < 4){
        test->alerts[test->count++] = *alert;
    }
}

static void test_account_targeting_multiple_episodes_same_ip(void){

    IpTable *table = ip_table_create(8);
    assert(table != NULL);

    LogStore *store = log_store_create();
    assert(store != NULL);

    assert(log_store_add(
        store,
        table,
        (time_t)1000,
        "192.168.1.20",
        "a",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)1010,
        "192.168.1.20",
        "b",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)1020,
        "192.168.1.20",
        "c",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)2000,
        "192.168.1.20",
        "d",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)2010,
        "192.168.1.20",
        "e",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)2020,
        "192.168.1.20",
        "f",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)2030,
        "192.168.1.20",
        "g",
        "server1",
        AUTH_FAILURE
    ));

    RecordedAlertsContext context = {0};
    size_t alerts_found = 0;

    assert(detector_find_account_targeting_in_store(
        store,
        3,
        60.0,
        verify_multiple_episodes_alerts,
        &context,
        &alerts_found
    ));

    assert(context.count == 2);
    assert(alerts_found == 2);
    assert(context.alerts[0].window_start == 1000);
    assert(context.alerts[0].window_end == 1020);
    assert(context.alerts[0].distinct_usernames == 3);
    assert(context.alerts[0].failed_attempts == 3);

    assert(context.alerts[1].window_start == 2000);
    assert(context.alerts[1].window_end == 2030);
    assert(context.alerts[1].distinct_usernames == 4);
    assert(context.alerts[1].failed_attempts == 4);

    ip_table_destroy(table);
    log_store_destroy(store);
}

static void test_find_peak_failure_window(void){

    time_t ts1[] = {1000, 1020, 1020, 1060, 1070, 1080, 1090};
    FailureWindowPeak peak = {0};
    assert(find_peak_failure_window(
        ts1,
        7,
        60.0,
        &peak
    ));

    assert(peak.failed_attempts == 5);
    assert(peak.window_start == 1020);
    assert(peak.window_end == 1080);

    time_t ts2[] = {1000, 1010, 1020, 2000, 2010, 2020};

    assert(find_peak_failure_window(
        ts2,
        6,
        60.0,
        &peak
    ));

    assert(peak.failed_attempts == 3);
    assert(peak.window_start == 1000);
    assert(peak.window_end == 1020);

    assert(!find_peak_failure_window(
        NULL,
        6,
        60.0,
        &peak
    ));
    assert(!find_peak_failure_window(
        ts1,
        0,
        60.0,
        &peak
    ));
    assert(!find_peak_failure_window(
        ts1,
        6,
        0.0,
        &peak
    ));
    assert(!find_peak_failure_window(
        ts1,
        6,
        NAN,
        &peak
    ));
    assert(!find_peak_failure_window(
        ts1,
        6,
        60.0,
        NULL
    ));
}

static void test_burst_multiple_episodes_same_ip(void){

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(8);
    assert(table != NULL);

    assert(log_store_add(
        store,
        table,
        (time_t)1000,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)1010,
        "192.168.1.20",
        "backup",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)1020,
        "192.168.1.20",
        "test",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)2000,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)2010,
        "192.168.1.20",
        "server",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)2020,
        "192.168.1.20",
        "backup",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)2030,
        "192.168.1.20",
        "admin",
        "server1",
        AUTH_FAILURE
    ));

    RecordedBurstAlertsContext ctx = {0};
    size_t alerts_found = 0;

    assert(detector_find_burst_alerts_in_store(
        store,
        3,
        60.0,
        record_burst_alert,
        &ctx,
        &alerts_found
    ));

    assert(alerts_found == 2);
    assert(ctx.alerts[0].failed_attempts == 3);
    assert(ctx.alerts[0].window_start == 1000);
    assert(ctx.alerts[0].window_end == 1020);

    assert(ctx.alerts[1].failed_attempts == 4);
    assert(ctx.alerts[1].window_start == 2000);
    assert(ctx.alerts[1].window_end == 2030);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_account_targeting_many_usernames_resizing(void){

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(8);
    assert(table != NULL);

    for (size_t i = 0; i < 200; i++){

        char username[16];
 
        snprintf(username, sizeof(username), "user_%zu", i);
        assert(log_store_add(
            store,
            table,
            (time_t)(1000 + i),
            "192.168.1.20",
            username,
            "server1",
            AUTH_FAILURE
        ));
    }

    AccountTargetingTestContext context = {
        .expected_distinct = 61,
        .expected_failures = 61,
        .expected_start = 1000,
        .expected_end = 1060
    };

    size_t alerts_found = 0;

    assert(detector_find_account_targeting_in_store(
        store,
        50,
        60.0,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(alerts_found == 1);
    assert(context.alerts_received == 1);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_account_targeting_pruned_username_reappears(void){

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(8);
    assert(table != NULL);

    assert(log_store_add(
        store,
        table,
        (time_t)1000,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)1030,
        "192.168.1.20",
        "admin",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)1070,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));
    assert(log_store_add(
        store,
        table,
        (time_t)1080,
        "192.168.1.20",
        "test",
        "server1",
        AUTH_FAILURE
    ));

    AccountTargetingTestContext context = {
        .expected_distinct = 3,
        .expected_failures = 3,
        .expected_start = 1030,
        .expected_end = 1080
    };

    size_t alerts_found = 0;

    assert(detector_find_account_targeting_in_store(
        store,
        3,
        60.0,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(alerts_found == 1);
    assert(context.alerts_received == 1);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_detector_config(void){

    DetectorConfig config_default = detector_config_default();

    assert(config_default.burst_threshold == 3);
    assert(config_default.burst_window_seconds == 60.0);
    assert(config_default.count_threshold == 3);
    assert(config_default.target_min_usernames == 3);
    assert(config_default.target_window_seconds == 60.0);

    assert(detector_config_is_valid(&config_default));
    assert(!detector_config_is_valid(NULL));

    config_default.count_threshold = 0;
    assert(!detector_config_is_valid(&config_default));

    config_default = detector_config_default();
    config_default.burst_threshold = 0;
    assert(!detector_config_is_valid(&config_default));

    config_default = detector_config_default();
    config_default.target_min_usernames = 0;
    assert(!detector_config_is_valid(&config_default));

    config_default = detector_config_default();
    config_default.burst_window_seconds = NAN;
    assert(!detector_config_is_valid(&config_default));

    config_default = detector_config_default();
    config_default.target_window_seconds = -10.0;
    assert(!detector_config_is_valid(&config_default));

    config_default = detector_config_default();
    config_default.target_window_seconds = INFINITY;
    assert(!detector_config_is_valid(&config_default));
}

static bool ref_find_peak_failure_window(
    const time_t *timestamps, size_t count,
    double window_seconds, FailureWindowPeak *out_peak
){

    if (timestamps == NULL || count == 0 || !isfinite(window_seconds) ||
        window_seconds <= 0.0 || out_peak == NULL
    ){
        return false;
    }

    FailureWindowPeak best = {0};

    for (size_t right = 0; right < count; right ++){

        size_t left = 0;

        while(left < right && difftime(timestamps[right], timestamps[left]) >window_seconds){
            left++;
        }

        size_t attempts = right - left + 1;

        if (attempts > best.failed_attempts){
            best.failed_attempts = attempts;
            best.window_end = timestamps[right];
            best.window_start = timestamps[left];
        }
    }

    *out_peak = best;
    return true;
}

static int compare_time_t(const void *a, const void *b){

    const time_t *t1 = a;
    const time_t *t2 = b;

    if (*t1 < *t2) return -1;
    if (*t1 > *t2) return 1;
    return 0;
}

static void test_differential_burst_oracle(void){

    srand(2026);

    for (int trial = 0; trial < 300; trial++){

        size_t n = (size_t)(rand() % 40) + 1;

        double windows[] = {5.0, 10.0, 30.0, 60.0};
        double window = windows[rand() % 4];

        size_t threshold = (size_t)(rand() % 5) + 1;
        time_t raw[40] = {0};

        for (size_t i = 0; i < 40; i++){
            raw[i] = 1000 + (rand() % 120);
        }

        time_t sorted[40];
        memcpy(sorted, raw, 40 * sizeof(time_t));

        qsort(sorted, n, sizeof(sorted[0]), compare_time_t);

        FailureWindowPeak fast_peak = {0};
        FailureWindowPeak ref_peak = {0};

        assert(find_peak_failure_window(sorted, n, window, &fast_peak));
        assert(ref_find_peak_failure_window(sorted, n, window, &ref_peak));
        assert(fast_peak.failed_attempts == ref_peak.failed_attempts);
        assert(fast_peak.window_start == ref_peak.window_start);
        assert(fast_peak.window_end == ref_peak.window_end);

        LogStore *store = log_store_create();
        assert(store != NULL);

        IpTable *table = ip_table_create(8);
        assert(table != NULL);

        for (size_t i = 0; i < n; i++){
            char username[32];
            snprintf(username, sizeof(username), "user_%zu", i);

            assert(log_store_add(
                store,
                table,
                raw[i],
                "192.168.1.20",
                username,
                "server1",
                AUTH_FAILURE
            ));
        }

        BigBurstRecorder actual = {0};
        size_t actual_found = 0;

        assert(detector_find_burst_alerts_in_store(
            store,
            threshold,
            window,
            record_big_burst_alert,
            &actual,
            &actual_found    
        ));

        FailureWindowPeak expected[64] = {0};
        size_t expected_count = 0;
        size_t ep_start = 0;
        while (ep_start < n){
            size_t ep_end = ep_start + 1;
            while(ep_end < n && difftime(sorted[ep_end], sorted[ep_end - 1]) <= window){
                ep_end++;
            }

            FailureWindowPeak ep_peak = {0};
            assert(ref_find_peak_failure_window(
                &sorted[ep_start],
                ep_end - ep_start,
                window,
                &ep_peak
            ));

            if(ep_peak.failed_attempts >= threshold){
                expected[expected_count++] = ep_peak;
            }
            ep_start = ep_end;
        }

        assert(actual_found == expected_count);
        assert(actual.count == expected_count);

        for (size_t i = 0; i < expected_count; i++){
            assert(actual.alerts[i].failed_attempts == expected[i].failed_attempts);
            assert(actual.alerts[i].window_start == expected[i].window_start);
            assert(actual.alerts[i].window_end == expected[i].window_end);
        }

        log_store_destroy(store);
        ip_table_destroy(table);
    }
}

typedef struct {
    time_t timestamp;
    const char *username;
} RefTargetingEvent;

typedef struct {
    AccountTargetingAlert alerts[64];
    size_t count;
} BigTargetingRecorder;

static void record_big_targeting_alert(const AccountTargetingAlert *alert, void *context){

    BigTargetingRecorder *rec = context;

    assert(alert != NULL);
    assert(rec != NULL);

    if (rec->count < 64){
        rec->alerts[rec->count++] = *alert;
    }
}

static int compare_ref_targeting_event(const void *a, const void *b){
    const RefTargetingEvent *e1 = a;
    const RefTargetingEvent *e2 = b;

    if (e1->timestamp < e2->timestamp) return -1;
    if (e1->timestamp > e2->timestamp) return 1;
    return 0;
}

static bool ref_account_targeting_episode(
    const RefTargetingEvent *events,
    size_t ep_start,
    size_t ep_end,
    size_t min_distinct,
    double window_seconds,
    AccountTargetingAlert *out_best
){

    bool found = false;
    AccountTargetingAlert best = {0};

    for (size_t right = ep_start; right < ep_end; right++){
        size_t left = ep_start;

        while (left < right && difftime(events[right].timestamp, events[left].timestamp) > window_seconds){
            left++;
        }

        size_t distinct = 0;
        for (size_t k = left; k <= right; k++){
            bool seen = false;
            for (size_t prev = left; prev < k; prev++){
                if (strcmp(events[prev].username, events[k].username) == 0){
                    seen = true;
                    break;
                }
            }
            if (!seen){
                distinct++;
            }
        }
        size_t attempts = right - left + 1;
        if (distinct >= min_distinct){
            if (!found || distinct > best.distinct_usernames || (distinct == best.distinct_usernames && attempts > best.failed_attempts)){
                found = true;
            
                best.distinct_usernames = distinct;
                best.failed_attempts = attempts;
                best.window_start = events[left].timestamp;
                best.window_end = events[right].timestamp;
            }
        }
    }

    if (found){
        *out_best = best;
        return true;
    }

    return false;
}

static void test_differential_account_targeting_oracle(void){

    const char *users[12] = {"u0", "u1", "u2", "u3", "u4", "u5", "u6", "u7", "u8", "u9", "u10", "u11"};

    srand(9001);

    for (int trial = 0; trial < 200; trial++){
        size_t n = (size_t)(rand() % 40) + 1;
        double windows[] = {5.0, 10.0, 30.0, 60.0};

        double window = windows[rand() % 4];
        size_t min_distinct = (size_t)(rand() % 5) + 1;

        RefTargetingEvent raw[40] = {0};

        for (size_t i = 0; i < n; i++){
            raw[i].timestamp = 1000 + (rand() % 120);
            raw[i].username = users[rand() % 12];
        }

        RefTargetingEvent sorted[40] = {0};
       
        memcpy(sorted, raw, n * sizeof(raw[0]));

        qsort(sorted, n, sizeof(sorted[0]), compare_ref_targeting_event);
        
        LogStore *store = log_store_create();
        assert(store != NULL);

        IpTable *table = ip_table_create(8);
        assert(table != NULL);

        for (size_t i = 0; i  < n; i++){
            assert(log_store_add(
                store,
                table,
                raw[i].timestamp,
                "192.168.1.20",
                raw[i].username,
                "server1",
                AUTH_FAILURE
            ));
        }   

        BigTargetingRecorder actual = {0};
        size_t actual_found = 0;

        assert(detector_find_account_targeting_in_store(
            store,
            min_distinct,
            window,
            record_big_targeting_alert,
            &actual,
            &actual_found
        ));

        size_t ep_start = 0;
        AccountTargetingAlert expected[64] = {0};
        size_t expected_count = 0;

        while(ep_start < n){

            size_t ep_end = ep_start + 1;

            while (ep_end < n && difftime(sorted[ep_end].timestamp, sorted[ep_end - 1].timestamp) <= window){
                ep_end++;
            }

            AccountTargetingAlert ep_peak = {0};
            if (ref_account_targeting_episode(
                sorted,
                ep_start,
                ep_end,
                min_distinct,
                window,
                &ep_peak
            )){
                expected[expected_count++] = ep_peak;
            }
            ep_start = ep_end;
        }

        assert(actual_found == expected_count);
        assert(actual.count == expected_count);

        for (size_t i = 0; i < expected_count; i++){
            assert(actual.alerts[i].distinct_usernames == expected[i].distinct_usernames);
            assert(actual.alerts[i].failed_attempts == expected[i].failed_attempts);
            assert(actual.alerts[i].window_start == expected[i].window_start);
            assert(actual.alerts[i].window_end == expected[i].window_end);
        }

        log_store_destroy(store);
        ip_table_destroy(table);
    }
}

int main(void) {

    test_is_suspicious();
    test_detection_report();
    test_failure_burst();
    test_failures_in_window();
    test_detect_account_targeting();
    test_account_targeting_same_username();
    test_account_targeting_outside_window();
    test_account_targeting_different_IP();
    test_account_targeting_window_expiration();
    test_account_targeting_out_of_order();
    test_account_targeting_multiple_alerts();
    test_account_targeting_ignores_success();
    test_account_targeting_window_boundary();
    test_account_targeting_invalid_parameters();
    test_detector_find_account_targeting_in_store();
    test_detector_analyze_windows_in_store();
    test_account_targeting_peak_not_first_match();
    test_account_targeting_tie_breaks_by_attempts();
    test_account_targeting_multiple_episodes_same_ip();
    test_burst_multiple_episodes_same_ip();
    test_find_peak_failure_window();
    test_account_targeting_many_usernames_resizing();
    test_account_targeting_pruned_username_reappears();
    test_detector_config();
    test_differential_burst_oracle();
    test_differential_account_targeting_oracle();

    printf("All test passed!\n\n");

    return 0;
}
