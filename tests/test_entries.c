#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "entries.h"

typedef struct {
    size_t visited;
    size_t failed;
} TestLogContext;

static void count_log_callback(time_t timestamp, const char *ip_address, AuthResult result,
                               void *context) {

    TestLogContext *config = context;

    config->visited++;

    if (result == AUTH_FAILURE) {
        config->failed++;
    }

    (void)timestamp;
    (void)ip_address;
}

static void test_log_foreach(void) {

    log_management_init();

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(add_log(table, (time_t)1000, "192.168.1.20", AUTH_SUCCESS));
    assert(add_log(table, (time_t)1020, "192.168.1.40", AUTH_FAILURE));
    assert(add_log(table, (time_t)1050, "192.168.1.60", AUTH_FAILURE));

    TestLogContext context = {0};

    log_management_foreach(count_log_callback, &context);

    assert(context.visited == 3);
    assert(context.failed == 2);

    log_management_destroy();
    ip_table_destroy(table);
}

static void test_parse_auth_result(void) {

    AuthResult result = AUTH_SUCCESS;

    assert(parse_auth_result("LOGIN_FAILED", &result));
    assert(result == AUTH_FAILURE);

    assert(!parse_auth_result("INVALID", &result));
    assert(result == AUTH_FAILURE);

    assert(!parse_auth_result(NULL, &result));
    assert(result == AUTH_FAILURE);

    assert(!parse_auth_result("LOGIN_SUCCESS", NULL));
    assert(result == AUTH_FAILURE);

    assert(!parse_auth_result("", &result));
    assert(result == AUTH_FAILURE);

    assert(parse_auth_result("LOGIN_SUCCESS", &result));
    assert(result == AUTH_SUCCESS);
}

static void test_parse_log_line(void){

    log_management_init();

    IpTable *table = ip_table_create(3);
    assert(table != NULL);

    const char *valid_failed = "2026-11-10T14:30:00 192.168.1.20 LOGIN_FAILED";
    const char *valid_success = "2026-11-10T14:31:00 192.168.1.30 LOGIN_SUCCESS";
    const char *another_failed = "2026-11-10T14:32:00 192.168.1.20 LOGIN_FAILED";

    assert(parse_log_line(table, valid_failed));
    assert(parse_log_line(table, valid_success));
    assert(parse_log_line(table, another_failed));

    assert(get_log_count() == 3);
    assert(count_logs_by_event(AUTH_FAILURE) == 2);
    assert(count_logs_by_event(AUTH_SUCCESS) == 1);
    assert(ip_table_get_count(table, "192.168.1.20") == 2);
    assert(ip_table_get_count(table, "192.168.1.30") == 0);


    const char *invalid_event = "2026-11-10T14:33:00 192.168.1.40 LOGIN_UNKNOWN";
    const char *invalid_timestamp = "INVALID_DATE 192.168.1.40 LOGIN_FAILED";
    const char *missing_status = "2026-11-10T14:34:00 192.168.1.40";

    assert(!parse_log_line(table, invalid_event));
    assert(!parse_log_line(table, invalid_timestamp));
    assert(!parse_log_line(table, missing_status));

    assert(get_log_count() == 3);
    assert(count_logs_by_event(AUTH_FAILURE) == 2);
    assert(count_logs_by_event(AUTH_SUCCESS) == 1);
    assert(ip_table_get_count(table, "192.168.1.40") == 0);
    assert(ip_table_get_count(table, "192.168.1.20") == 2);

    log_management_destroy();
    ip_table_destroy(table);
}
int main(void) {

    test_log_foreach();
    test_parse_auth_result();
    test_parse_log_line();

    printf("\nAll entries test pass!!\n");

    return 0;
}