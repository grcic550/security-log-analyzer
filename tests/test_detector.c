#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#include "detector.h"

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
int main(void) {

    test_is_suspicious();
    test_detection_report();
    test_failure_burst();
    test_failures_in_window();

    printf("\nAll test passed!\n");

    return 0;
}
