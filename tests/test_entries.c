#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "entries.h"

typedef struct {
    size_t visited;
    size_t failed;
} TestLogContext;

static void count_log_callback(time_t timestamp, const char *ip_address, const char *event_type,
                               void *context) {

    TestLogContext *config = context;

    config->visited++;

    if (strcmp(event_type, "LOGIN_FAILED") == 0) {
        config->failed++;
    }

    (void)timestamp;
    (void)ip_address;
}

static void test_log_foreach(void) {

    log_management_init();

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(add_log(table, (time_t)1000, "192.168.1.20", "LOGIN_SUCCESS"));
    assert(add_log(table, (time_t)1020, "192.168.1.40", "LOGIN_FAILED"));
    assert(add_log(table, (time_t)1050, "192.168.1.60", "LOGIN_FAILED"));

    TestLogContext context = {0};

    log_management_foreach(count_log_callback, &context);

    assert(context.visited == 3);
    assert(context.failed == 2);

    log_management_destroy();
    ip_table_destroy(table);
}

int main(void) {

    test_log_foreach();

    printf("\nAll entries test pass!!\n");

    return 0;
}