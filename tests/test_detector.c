#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

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

    assert(detector_print_alerts(table, 3) == 1);

    assert(detector_print_alerts(table, 5) == 0);

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

static void verify_account_targeting_alert(
    const AccountTargetingAlert *alert,
    void *context
) {
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

static void test_detect_account_targeting(void){

    log_management_init();

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(add_log(
        table, 
        (time_t)1000,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table, 
        (time_t)1010,
        "192.168.1.20",
        "admin",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table, 
        (time_t)1020,
        "192.168.1.20",
        "test",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table, 
        (time_t)1030,
        "192.168.1.20",
        "backup",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table, 
        (time_t)1040,
        "192.168.1.20",
        "support",
        "server1",
        AUTH_FAILURE
    ));

    AccountTargetingTestContext context = {0};
    size_t alerts_found = 0;

    context.expected_distinct = 5;
    context.expected_failures = 5;
    context.expected_start = 1000;
    context.expected_end = 1040;

    assert(detector_find_account_targeting(
        5,
        60.0,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(alerts_found == 1);
    assert(context.alerts_received == 1);

    log_management_destroy();
    ip_table_destroy(table);
}

static void test_account_targeting_same_username(void){

    log_management_init();
    
    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(add_log(
        table,
        (time_t)1000,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1010,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1020,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1030,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1040,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));

    size_t alerts_found = 0;
    AccountTargetingTestContext context = {0};

    context.expected_distinct = 0;
    context.expected_failures = 5;
    context.expected_start = 1000;
    context.expected_end = 1040;

    assert(detector_find_account_targeting(
        5,
        60.0,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(alerts_found == 0);
    assert(context.alerts_received == 0);

    log_management_destroy();
    ip_table_destroy(table);
}

static void test_account_targeting_outside_window(void){

    log_management_init();

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(add_log(
        table,
        (time_t)1000,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1100,
        "192.168.1.20",
        "admin",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1200,
        "192.168.1.20",
        "test",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1300,
        "192.168.1.20",
        "backup",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1400,
        "192.168.1.20",
        "support",
        "server1",
        AUTH_FAILURE
    ));

    size_t alerts_found = 0;
    AccountTargetingTestContext context = {0};

    context.expected_distinct = 5;
    context.expected_failures = 5;
    context.expected_start = 1000;
    context.expected_end = 1400;

    assert(detector_find_account_targeting(
        5,
        60.0,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(alerts_found == 0);
    assert(context.alerts_received == 0);

    log_management_destroy();
    ip_table_destroy(table);
}

static void test_account_targeting_different_IP(void){

    log_management_init();
    
    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(add_log(
        table,
        (time_t)1000,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1010,
        "192.168.1.20",
        "admin",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1020,
        "192.168.1.30",
        "test",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1030,
        "192.168.1.30",
        "backup",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1040,
        "192.168.1.30",
        "support",
        "server1",
        AUTH_FAILURE
    ));


    size_t alerts_found = 0;
    AccountTargetingTestContext context = {0};

    context.expected_distinct = 5;
    context.expected_failures = 5;
    context.expected_start = 1000;
    context.expected_end = 1040;

    assert(detector_find_account_targeting(
        5,
        60.0,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(alerts_found == 0);
    assert(context.alerts_received == 0);

    log_management_destroy();
    ip_table_destroy(table);
}


static void test_account_targeting_window_expiration(void){

    log_management_init();
    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(add_log(
        table,
        (time_t)1000,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1010,
        "192.168.1.20",
        "admin",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1020,
        "192.168.1.20",
        "test",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1100,
        "192.168.1.20",
        "backup",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1110,
        "192.168.1.20",
        "support",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1120,
        "192.168.1.20",
        "deploy",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1130,
        "192.168.1.20",
        "postgres",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1140,
        "192.168.1.20",
        "guest",
        "server1",
        AUTH_FAILURE
    ));

    AccountTargetingTestContext context = {0};
    size_t alerts_found = 0;

    context.expected_distinct = 5;
    context.expected_failures = 5;
    context.expected_start = 1100;
    context.expected_end = 1140;

    assert(detector_find_account_targeting(
        5,
        60.0,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(alerts_found == 1);
    assert(context.alerts_received == 1);

    log_management_destroy();
    ip_table_destroy(table);
}

static void test_account_targeting_out_of_order(void){

    log_management_init();
    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(add_log(
        table,
        (time_t)1040,
        "192.168.1.20",
        "support",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1000,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1030,
        "192.168.1.20",
        "backup",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1010,
        "192.168.1.20",
        "admin",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1020,
        "192.168.1.20",
        "test",
        "server1",
        AUTH_FAILURE
    ));

    AccountTargetingTestContext context = {0};
    size_t alerts_found = 0;

    context.expected_distinct = 5;
    context.expected_failures = 5;
    context.expected_start = 1000;
    context.expected_end = 1040;

    assert(detector_find_account_targeting(
        5,
        60.0,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(alerts_found == 1);
    assert(context.alerts_received == 1);

    log_management_destroy();
    ip_table_destroy(table);
}

static void verify_multiple_targeting_alerts(
    const AccountTargetingAlert *alert,
    void *context
){

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

static void test_account_targeting_multiple_alerts(void){

    log_management_init();

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(add_log(
        table,
        (time_t)1000,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1010,
        "192.168.1.30",
        "admin",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1020,
        "192.168.1.20",
        "test",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1030,
        "192.168.1.30",
        "backup",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1040,
        "192.168.1.20",
        "support",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1050,
        "192.168.1.30",
        "guest",
        "server1",
        AUTH_FAILURE
    ));

    MultipleAlertsTestContext context = {0};
    size_t alerts_found = 0;


    assert(detector_find_account_targeting(
        3,
        60.0,
        verify_multiple_targeting_alerts,
        &context,
        &alerts_found
    ));

    assert(context.received_ip20);
    assert(context.received_ip30);
    assert(alerts_found == 2);
    assert(context.alerts_received == 2);

    log_management_destroy();
    ip_table_destroy(table);
}

static void test_account_targeting_ignores_success(void){

    log_management_init();

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(add_log(
        table,
        (time_t)1000,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1010,
        "192.168.1.20",
        "admin",
        "server1",
        AUTH_SUCCESS
    ));

    assert(add_log(
        table,
        (time_t)1020,
        "192.168.1.20",
        "test",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1030,
        "192.168.1.20",
        "backup",
        "server1",
        AUTH_SUCCESS
    ));

    assert(add_log(
        table,
        (time_t)1040,
        "192.168.1.20",
        "support",
        "server1",
        AUTH_FAILURE
    ));

    AccountTargetingTestContext context = {0};
    size_t alerts_found = 0;

    context.expected_distinct = 3;
    context.expected_failures = 3;
    context.expected_start = 1000;
    context.expected_end = 1040;

    assert(detector_find_account_targeting(
        3,
        60.0,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(alerts_found == 1);
    assert(context.alerts_received == 1);

    log_management_destroy();
    ip_table_destroy(table);
}

static void test_account_targeting_window_boundary(void){

    log_management_init();

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(add_log(
        table,
        (time_t)1000,
        "192.168.1.20",
        "root",
        "server1",
        AUTH_FAILURE
    ));

    assert(add_log(
        table,
        (time_t)1060,
        "192.168.1.20",
        "admin",
        "server1",
        AUTH_FAILURE
    ));

    AccountTargetingTestContext context = {0};
    size_t alerts_found = 0;

    context.expected_distinct = 2;
    context.expected_failures = 2;
    context.expected_start = 1000;
    context.expected_end = 1060;

    assert(detector_find_account_targeting(
        2,
        60.0,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(alerts_found == 1);
    assert(context.alerts_received == 1);

    log_management_destroy();
    ip_table_destroy(table);
}

static void test_account_targeting_invalid_parameters(void){

    AccountTargetingTestContext context = {0};
    size_t alerts_found = 0;

    assert(!detector_find_account_targeting(
        0,
        60.0,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(!detector_find_account_targeting(
        3,
        0.0,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(!detector_find_account_targeting(
        3,
        -60.0,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(!detector_find_account_targeting(
        3,
        NAN,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(!detector_find_account_targeting(
        3,
        INFINITY,
        verify_account_targeting_alert,
        &context,
        &alerts_found
    ));

    assert(!detector_find_account_targeting(
        3,
        60.0,
        NULL,
        &context,
        &alerts_found
    ));

    assert(!detector_find_account_targeting(
        3,
        60.0,
        verify_account_targeting_alert,
        &context,
        NULL
    ));
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

    printf("\nAll test passed!\n");

    return 0;
}
