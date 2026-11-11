#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "entries.h"

typedef struct {
    size_t visited;
    size_t failed;
} TestLogContext;

typedef struct{
    size_t checked;
} MetadataTestContext;

static void count_log_callback(const LogEventView *event, void *context) {

    TestLogContext *config = context;

    config->visited++;

    if (event->result == AUTH_FAILURE) {
        config->failed++;
    }

    (void)event->timestamp;
    (void)event->ip_address;
}

static void test_log_foreach(void) {

    log_management_init();

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(add_log(table, (time_t)1000, "192.168.1.20",NULL, NULL, AUTH_SUCCESS));
    assert(add_log(table, (time_t)1020, "192.168.1.40", NULL, NULL, AUTH_FAILURE));
    assert(add_log(table, (time_t)1050, "192.168.1.60", NULL, NULL, AUTH_FAILURE));

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

static void verify_log_metadata(
    const LogEventView *event,
    void *context
) { 

    MetadataTestContext *config = context;

    if (strcmp(event->ip_address, "192.168.1.20") == 0 
        && event->username != NULL 
        && event->hostname != NULL){

        assert(strcmp(event->username, "ante") == 0);
        assert(strcmp(event->hostname, "server1") == 0);

    } else if (strcmp(event->ip_address, "192.168.1.30") == 0){
        assert(event->username == NULL);
        assert(event->hostname == NULL);
    } else {
        assert(0 && "Unexpected event");
    }

    config->checked++;
}

static void test_log_metadata(void){

    log_management_init();

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    char username[] = "ante";
    char hostname[] = "server1";

    assert(add_log(table, (time_t)1000, "192.168.1.20", username, hostname, AUTH_FAILURE));
    
    username[0] = 'X';
    hostname[0] = 'X';

    assert(add_log(table, (time_t)1020, "192.168.1.30", NULL, NULL, AUTH_SUCCESS));

    MetadataTestContext context = {0};

    log_management_foreach(verify_log_metadata, &context);

    assert(context.checked == 2);

    log_management_destroy();
    ip_table_destroy(table);
}

static void verify_ssh_log_metadata(
    const LogEventView *event,
    void *context
){

    MetadataTestContext *config = context;

    if (event->username != NULL && event->hostname != NULL){
        assert(strcmp(event->username, "root") == 0);
        assert(strcmp(event->hostname, "server1") == 0);
    } else {
        assert(0 && "Unexpected event");
    }

    assert(event->ip_address != NULL);
    assert(strcmp(event->ip_address, "192.168.1.20") == 0);
    assert(event->result == AUTH_FAILURE);

    config->checked++;
}

static void verify_ssh_invalid_user(
    const LogEventView *event,
    void *context
){
    MetadataTestContext *config = context;

    if (event->username != NULL && event->hostname != NULL){
        assert(strcmp(event->username, "admin") == 0);
        assert(strcmp(event->hostname, "server1") == 0);
    } else {
        assert(0 && "Unexpected event");
    }

    assert(event->ip_address != NULL);
    assert(strcmp(event->ip_address, "192.168.1.20") == 0);
    assert(event->result == AUTH_FAILURE);

    config->checked++;
}

static void verify_ssh_log_success(
    const LogEventView *event,
    void *context
){
    MetadataTestContext *config = context;

    if (event->username != NULL && event->hostname != NULL){
        assert(strcmp(event->username, "ante") == 0);
        assert(strcmp(event->hostname, "server1") == 0);
    } else {
        assert(0 && "Unexpected event");
    }

    assert(event->ip_address != NULL);
    assert(strcmp(event->ip_address, "192.168.1.30") == 0);
    assert(event->result == AUTH_SUCCESS);

    config->checked++;
}

static void test_parse_ssh_log_line(void){

    log_management_init();

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    const char *line =
        "Nov 10 14:30:15 server1 sshd[1234]: "
        "Failed password for root from "
        "192.168.1.20 port 52341 ssh2";

    assert(parse_ssh_log_line(table, line, 2026));
    assert(get_log_count() == 1);
    assert(ip_table_get_count(table, "192.168.1.20") == 1);

    MetadataTestContext context = {0};
    
    log_management_foreach(verify_ssh_log_metadata, &context);

    assert(context.checked == 1);

    const char *valid_newline =
        "Nov 10 14:30:15 server1 sshd[1234]: "
        "Failed password for root from "
        "192.168.1.20 port 52341 ssh2\n";
    
    assert(parse_ssh_log_line(table, valid_newline, 2026));
    assert(get_log_count() == 2);
    assert(ip_table_get_count(table, "192.168.1.20") == 2);

    const char *missing_ssh2 =
        "Nov 10 14:30:15 server1 sshd[1234]: "
        "Failed password for root from "
        "192.168.1.20 port 52341";

    assert(!parse_ssh_log_line(table, missing_ssh2, 2026));
    assert(get_log_count() == 2);
    assert(ip_table_get_count(table, "192.168.1.20") == 2);

    const char *unsupported =
        "Nov 10 14:30:15 server1 sshd[1234]: "
        "Connection closed by 192.168.1.20 port 52341";

    assert(!parse_ssh_log_line(table, unsupported, 2026));
    assert(get_log_count() == 2);
    assert(ip_table_get_count(table, "192.168.1.20") == 2);

    log_management_destroy();
    ip_table_destroy(table);
}

static void test_parse_ssh_invalid_user(void){

    log_management_init();

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    const char *line = 
        "Nov 10 14:31:00 server1 sshd[1235]: "
        "Failed password for invalid user admin from "
        "192.168.1.20 port 52342 ssh2\n"; 

    assert(parse_ssh_log_line(table, line, 2026));
    assert(get_log_count() == 1);
    assert(ip_table_get_count(table, "192.168.1.20") == 1);

    MetadataTestContext context = {0};

    log_management_foreach(verify_ssh_invalid_user, &context);

    assert(context.checked == 1);

    log_management_destroy();
    ip_table_destroy(table);
}

static void test_parse_ssh_success(void){

    log_management_init();

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    const char *line = 
        "Nov 10 14:32:00 server1 sshd[1236]: "
        "Accepted password for ante from "
        "192.168.1.30 port 52343 ssh2\n";

    assert(parse_ssh_log_line(table, line, 2026));
    assert(get_log_count() == 1);
    assert(ip_table_get_count(table, "192.168.1.30") == 0);

    MetadataTestContext context = {0};

    log_management_foreach(verify_ssh_log_success, &context);

    assert(count_logs_by_event(AUTH_SUCCESS) == 1);
    assert(count_logs_by_event(AUTH_FAILURE) == 0);
    assert(context.checked == 1);

    const char *invalid_suffix =
        "Nov 10 14:32:00 server1 sshd[1236]: "
        "Accepted password for ante from "
        "192.168.1.30 port 52343 ssh2JUNK";


    assert(!parse_ssh_log_line(table, invalid_suffix, 2026));
    assert(get_log_count() == 1);
    assert(ip_table_get_count(table, "192.168.1.30") == 0);
    assert(count_logs_by_event(AUTH_SUCCESS) == 1);
    assert(count_logs_by_event(AUTH_FAILURE) == 0);

    const char *invalid_extra_line =
        "Nov 10 14:32:00 server1 sshd[1236]: "
        "Accepted password for ante from "
        "192.168.1.30 port 52343 ssh2\n"
        "UNEXPECTED DATA";

    assert(!parse_ssh_log_line(table, invalid_extra_line, 2026));
    assert(get_log_count() == 1);
    assert(ip_table_get_count(table, "192.168.1.30") == 0);
    assert(count_logs_by_event(AUTH_SUCCESS) == 1);
    assert(count_logs_by_event(AUTH_FAILURE) == 0);

    const char *invalid_missing_port =
        "Nov 10 14:32:00 server1 sshd[1236]: "
        "Accepted password for ante from "
        "192.168.1.30 ssh2";

    assert(!parse_ssh_log_line(table, invalid_missing_port, 2026));
    assert(get_log_count() == 1);
    assert(ip_table_get_count(table, "192.168.1.30") == 0);
    assert(count_logs_by_event(AUTH_SUCCESS) == 1);
    assert(count_logs_by_event(AUTH_FAILURE) == 0);
    
    log_management_destroy();
    ip_table_destroy(table);
}

int main(void) {

    test_log_foreach();
    test_parse_auth_result();
    test_parse_log_line();
    test_log_metadata();
    test_parse_ssh_log_line();
    test_parse_ssh_invalid_user();
    test_parse_ssh_success();

    printf("\nAll entries test pass!!\n");

    return 0;
}