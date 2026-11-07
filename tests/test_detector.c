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

int main(void) {

    test_is_suspicious();
    test_detection_report();

    printf("\nAll test passed!\n");

    return 0;
}




