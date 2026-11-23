#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "entries.h"

typedef struct {
    size_t visited;
    size_t failed;
} TestLogContext;

typedef struct {
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

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    assert(log_store_add(store, table, (time_t)1000, "192.168.1.20", NULL, NULL, AUTH_SUCCESS));
    assert(log_store_add(store, table, (time_t)1020, "192.168.1.40", NULL, NULL, AUTH_FAILURE));
    assert(log_store_add(store, table, (time_t)1050, "192.168.1.60", NULL, NULL, AUTH_FAILURE));

    TestLogContext context = {0};

    log_store_foreach(store, count_log_callback, &context);

    assert(context.visited == 3);
    assert(context.failed == 2);

    log_store_destroy(store);
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

static void test_parse_log_line(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(3);
    assert(table != NULL);

    const char *valid_failed = "2026-11-10T14:30:00 192.168.1.20 LOGIN_FAILED";
    const char *valid_success = "2026-11-10T14:31:00 192.168.1.30 LOGIN_SUCCESS";
    const char *another_failed = "2026-11-10T14:32:00 192.168.1.20 LOGIN_FAILED";

    assert(log_store_parse_simple_line(store, table, valid_failed, TIMESTAMP_LOCAL, NULL));
    assert(log_store_parse_simple_line(store, table, valid_success, TIMESTAMP_LOCAL, NULL));
    assert(log_store_parse_simple_line(store, table, another_failed, TIMESTAMP_LOCAL, NULL));

    assert(log_store_get_count(store) == 3);
    assert(log_store_count_by_event(store, AUTH_FAILURE) == 2);
    assert(log_store_count_by_event(store, AUTH_SUCCESS) == 1);
    assert(ip_table_get_count(table, "192.168.1.20") == 2);
    assert(ip_table_get_count(table, "192.168.1.30") == 0);

    const char *invalid_event = "2026-11-10T14:33:00 192.168.1.40 LOGIN_UNKNOWN";
    const char *invalid_timestamp = "INVALID_DATE 192.168.1.40 LOGIN_FAILED";
    const char *missing_status = "2026-11-10T14:34:00 192.168.1.40";

    assert(!log_store_parse_simple_line(store, table, invalid_event, TIMESTAMP_LOCAL, NULL));
    assert(!log_store_parse_simple_line(store, table, invalid_timestamp, TIMESTAMP_LOCAL, NULL));
    assert(!log_store_parse_simple_line(store, table, missing_status, TIMESTAMP_LOCAL, NULL));

    assert(log_store_get_count(store) == 3);
    assert(log_store_count_by_event(store, AUTH_FAILURE) == 2);
    assert(log_store_count_by_event(store, AUTH_SUCCESS) == 1);
    assert(ip_table_get_count(table, "192.168.1.40") == 0);
    assert(ip_table_get_count(table, "192.168.1.20") == 2);

    const char *extra_field = "2026-11-10T14:30:00 192.168.1.20 LOGIN_FAILED EXTRA";
    const char *long_status =
        "2026-11-10T14:30:00 192.168.1.20 LOGIN_FAILEDXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

    assert(!log_store_parse_simple_line(store, table, extra_field, TIMESTAMP_LOCAL, NULL));
    assert(!log_store_parse_simple_line(store, table, long_status, TIMESTAMP_LOCAL, NULL));

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void verify_log_metadata(const LogEventView *event, void *context) {

    MetadataTestContext *config = context;

    if (strcmp(event->ip_address, "192.168.1.20") == 0 && event->username != NULL &&
        event->hostname != NULL) {

        assert(strcmp(event->username, "ante") == 0);
        assert(strcmp(event->hostname, "server1") == 0);

    } else if (strcmp(event->ip_address, "192.168.1.30") == 0) {
        assert(event->username == NULL);
        assert(event->hostname == NULL);
    } else {
        assert(0 && "Unexpected event");
    }

    config->checked++;
}

static void test_log_metadata(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    char username[] = "ante";
    char hostname[] = "server1";

    assert(log_store_add(store, table, (time_t)1000, "192.168.1.20", username, hostname,
                         AUTH_FAILURE));

    username[0] = 'X';
    hostname[0] = 'X';

    assert(log_store_add(store, table, (time_t)1020, "192.168.1.30", NULL, NULL, AUTH_SUCCESS));

    MetadataTestContext context = {0};

    log_store_foreach(store, verify_log_metadata, &context);

    assert(context.checked == 2);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void verify_ssh_log_metadata(const LogEventView *event, void *context) {

    MetadataTestContext *config = context;

    if (event->username != NULL && event->hostname != NULL) {
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

static void verify_ssh_invalid_user(const LogEventView *event, void *context) {
    MetadataTestContext *config = context;

    if (event->username != NULL && event->hostname != NULL) {
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

static void verify_ssh_log_success(const LogEventView *event, void *context) {
    MetadataTestContext *config = context;

    if (event->username != NULL && event->hostname != NULL) {
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

static void test_parse_ssh_log_line(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    const char *line = "Nov 10 14:30:15 server1 sshd[1234]: "
                       "Failed password for root from "
                       "192.168.1.20 port 52341 ssh2";

    assert(log_store_parse_ssh_line(store, table, line, 2026, TIMESTAMP_LOCAL, NULL) == PARSE_OK);
    assert(log_store_get_count(store) == 1);
    assert(ip_table_get_count(table, "192.168.1.20") == 1);

    MetadataTestContext context = {0};

    log_store_foreach(store, verify_ssh_log_metadata, &context);

    assert(context.checked == 1);

    const char *valid_newline = "Nov 10 14:30:15 server1 sshd[1234]: "
                                "Failed password for root from "
                                "192.168.1.20 port 52341 ssh2\n";

    assert(log_store_parse_ssh_line(store, table, valid_newline, 2026, TIMESTAMP_LOCAL, NULL) ==
           PARSE_OK);
    assert(log_store_get_count(store) == 2);
    assert(ip_table_get_count(table, "192.168.1.20") == 2);

    const char *missing_ssh2 = "Nov 10 14:30:15 server1 sshd[1234]: "
                               "Failed password for root from "
                               "192.168.1.20 port 52341";

    assert(log_store_parse_ssh_line(store, table, missing_ssh2, 2026, TIMESTAMP_LOCAL, NULL) ==
           PARSE_ERROR);
    assert(log_store_get_count(store) == 2);
    assert(ip_table_get_count(table, "192.168.1.20") == 2);

    const char *unsupported = "Nov 10 14:30:15 server1 sshd[1234]: "
                              "Connection closed by 192.168.1.20 port 52341";

    assert(log_store_parse_ssh_line(store, table, unsupported, 2026, TIMESTAMP_LOCAL, NULL) ==
           PARSE_IGNORED);
    assert(log_store_get_count(store) == 2);
    assert(ip_table_get_count(table, "192.168.1.20") == 2);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_parse_ssh_invalid_user(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    const char *line = "Nov 10 14:31:00 server1 sshd[1235]: "
                       "Failed password for invalid user admin from "
                       "192.168.1.20 port 52342 ssh2\n";

    assert(log_store_parse_ssh_line(store, table, line, 2026, TIMESTAMP_LOCAL, NULL) == PARSE_OK);
    assert(log_store_get_count(store) == 1);
    assert(ip_table_get_count(table, "192.168.1.20") == 1);

    MetadataTestContext context = {0};

    log_store_foreach(store, verify_ssh_invalid_user, &context);

    assert(context.checked == 1);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_parse_ssh_success(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    const char *line = "Nov 10 14:32:00 server1 sshd[1236]: "
                       "Accepted password for ante from "
                       "192.168.1.30 port 52343 ssh2\n";

    assert(log_store_parse_ssh_line(store, table, line, 2026, TIMESTAMP_LOCAL, NULL) == PARSE_OK);
    assert(log_store_get_count(store) == 1);
    assert(ip_table_get_count(table, "192.168.1.30") == 0);

    MetadataTestContext context = {0};

    log_store_foreach(store, verify_ssh_log_success, &context);

    assert(log_store_count_by_event(store, AUTH_SUCCESS) == 1);
    assert(log_store_count_by_event(store, AUTH_FAILURE) == 0);
    assert(context.checked == 1);

    const char *invalid_suffix = "Nov 10 14:32:00 server1 sshd[1236]: "
                                 "Accepted password for ante from "
                                 "192.168.1.30 port 52343 ssh2JUNK";

    assert(log_store_parse_ssh_line(store, table, invalid_suffix, 2026, TIMESTAMP_LOCAL, NULL) ==
           PARSE_ERROR);
    assert(log_store_get_count(store) == 1);
    assert(ip_table_get_count(table, "192.168.1.30") == 0);
    assert(log_store_count_by_event(store, AUTH_SUCCESS) == 1);
    assert(log_store_count_by_event(store, AUTH_FAILURE) == 0);

    const char *invalid_extra_line = "Nov 10 14:32:00 server1 sshd[1236]: "
                                     "Accepted password for ante from "
                                     "192.168.1.30 port 52343 ssh2\n"
                                     "UNEXPECTED DATA";

    assert(log_store_parse_ssh_line(store, table, invalid_extra_line, 2026, TIMESTAMP_LOCAL, NULL) ==
           PARSE_ERROR);
    assert(log_store_get_count(store) == 1);
    assert(ip_table_get_count(table, "192.168.1.30") == 0);
    assert(log_store_count_by_event(store, AUTH_SUCCESS) == 1);
    assert(log_store_count_by_event(store, AUTH_FAILURE) == 0);

    const char *invalid_missing_port = "Nov 10 14:32:00 server1 sshd[1236]: "
                                       "Accepted password for ante from "
                                       "192.168.1.30 ssh2";

    assert(log_store_parse_ssh_line(store, table, invalid_missing_port, 2026, TIMESTAMP_LOCAL, NULL) ==
           PARSE_ERROR);
    assert(log_store_get_count(store) == 1);
    assert(ip_table_get_count(table, "192.168.1.30") == 0);
    assert(log_store_count_by_event(store, AUTH_SUCCESS) == 1);
    assert(log_store_count_by_event(store, AUTH_FAILURE) == 0);

    const char *invalid_sshd_part = "Nov 10 14:32:00 server1 sshd[abc]: "
                                    "Accepted password for ante from "
                                    "192.168.1.30 port 52343 ssh2\n";

    assert(log_store_parse_ssh_line(store, table, invalid_sshd_part, 2026, TIMESTAMP_LOCAL, NULL) ==
           PARSE_ERROR);
    assert(log_store_get_count(store) == 1);

    const char *invalid_ip = "2026-11-10T14:30:00 999.999.999.999 LOGIN_FAILED";

    assert(!log_store_parse_simple_line(store, table, invalid_ip, TIMESTAMP_LOCAL, NULL));
    assert(log_store_get_count(store) == 1);

    const char *cron_event = "Nov 10 14:30:15 server1 cron[1234]: (root) CMD (date)";

    assert(log_store_parse_ssh_line(store, table, cron_event, 2026, TIMESTAMP_LOCAL, NULL) ==
           PARSE_IGNORED);
    assert(log_store_get_count(store) == 1);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_ssh_parse_status(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    const char *line = "Nov 14 10:15:00 server1 sshd[1234]: Failed password for root from "
                       "192.168.1.20 port 54321 ssh2";

    assert(log_store_parse_ssh_line(store, table, line, 2026, TIMESTAMP_LOCAL, NULL) == PARSE_OK);
    assert(log_store_get_count(store) == 1);
    assert(ip_table_get_count(table, "192.168.1.20") == 1);

    const char *connection_closed_event =
        "Nov 14 10:15:05 server1 sshd[1235]: Connection closed by 192.168.1.30 port 54322";

    assert(log_store_parse_ssh_line(store, table, connection_closed_event, 2026, TIMESTAMP_LOCAL, NULL) ==
           PARSE_IGNORED);
    assert(log_store_get_count(store) == 1);

    const char *failed_password_event =
        "Nov 14 10:15:05 server1 sshd[1235]: Failed password for root from";

    assert(log_store_parse_ssh_line(store, table, failed_password_event, 2026, TIMESTAMP_LOCAL, NULL) ==
           PARSE_ERROR);
    assert(log_store_get_count(store) == 1);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_ssh_parse_with_year_and_time_normalization(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    const char *normal_line = "Nov 14 10:15:00 server1 sshd[1234]: Failed password for root from "
                              "192.168.1.20 port 54321 ssh2";

    assert(log_store_parse_ssh_line(store, table, normal_line, 2025, TIMESTAMP_LOCAL, NULL) == PARSE_OK);
    assert(log_store_get_count(store) == 1);

    const char *leap_year = "Feb 29 10:15:00 server1 sshd[1234]: Failed password for root from "
                            "192.168.1.20 port 54321 ssh2";

    assert(log_store_parse_ssh_line(store, table, leap_year, 2024, TIMESTAMP_LOCAL, NULL) == PARSE_OK);
    assert(log_store_get_count(store) == 2);

    assert(log_store_parse_ssh_line(store, table, leap_year, 2025, TIMESTAMP_LOCAL, NULL) == PARSE_ERROR);
    assert(log_store_get_count(store) == 2);

    const char *invalid_date = "Feb 30 10:15:00 server1 sshd[1234]: Failed password for root from "
                               "192.168.1.20 port 54321 ssh2";

    assert(log_store_parse_ssh_line(store, table, invalid_date, 2026, TIMESTAMP_LOCAL, NULL) ==
           PARSE_ERROR);
    assert(log_store_get_count(store) == 2);

    char hostname[129];
    memset(hostname, 'a', 128);
    hostname[128] = '\0';

    char line[512];

    snprintf(line, sizeof(line),
             "Nov 10 14:30:15 %s sshd[1234]: "
             "Failed password for root from "
             "192.168.1.20 port 52341 ssh2",
             hostname);

    assert(log_store_parse_ssh_line(store, table, line, 2026, TIMESTAMP_LOCAL, NULL) == PARSE_ERROR);
    assert(log_store_get_count(store) == 2);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_log_store_lifecycle(void) {

    LogStore *store1 = log_store_create();
    LogStore *store2 = log_store_create();

    assert(store1 != NULL);
    assert(store2 != NULL);

    log_store_destroy(store1);
    log_store_destroy(store2);
}

static void test_independant_log_stores(void) {

    IpTable *table1 = ip_table_create(2);
    assert(table1 != NULL);

    IpTable *table2 = ip_table_create(2);
    assert(table2 != NULL);

    LogStore *store1 = log_store_create();
    LogStore *store2 = log_store_create();

    assert(store1 != NULL);
    assert(store2 != NULL);

    assert(log_store_add(store1, table1, (time_t)1000, "192.168.1.20", "root", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store1, table1, (time_t)1010, "192.168.1.20", "test", "server1",
                         AUTH_FAILURE));

    assert(log_store_add(store1, table1, (time_t)1020, "192.168.1.20", "support", "server1",
                         AUTH_SUCCESS));

    assert(log_store_add(store2, table2, (time_t)1375, "192.168.1.20", "root", "server5",
                         AUTH_FAILURE));

    assert(log_store_get_count(store1) == 3);
    assert(log_store_get_count(store2) == 1);

    assert(log_store_count_by_event(store1, AUTH_FAILURE) == 2);
    assert(log_store_count_by_event(store2, AUTH_FAILURE) == 1);

    assert(log_store_count_by_event(store1, AUTH_SUCCESS) == 1);
    assert(log_store_count_by_event(store2, AUTH_SUCCESS) == 0);

    assert(ip_table_get_count(table1, "192.168.1.20") == 2);
    assert(ip_table_get_count(table2, "192.168.1.20") == 1);

    log_store_destroy(store1);
    log_store_destroy(store2);
    ip_table_destroy(table1);
    ip_table_destroy(table2);
}
static void verify_simple_log_metadata(const LogEventView *event, void *context) {
    MetadataTestContext *test = context;

    assert(event != NULL);

    assert(strcmp(event->ip_address, "192.168.1.20") == 0);
    assert(event->username == 0);
    assert(event->hostname == 0);

    assert(event->result == AUTH_FAILURE);

    test->checked++;
}

static void test_log_store_parse_simple_line(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    const char *line = "2026-11-16T10:30:00 192.168.1.20 LOGIN_FAILED";

    assert(log_store_parse_simple_line(store, table, line, TIMESTAMP_LOCAL, NULL));
    assert(log_store_count_by_event(store, AUTH_FAILURE) == 1);
    assert(log_store_get_count(store) == 1);

    MetadataTestContext context = {0};

    log_store_foreach(store, verify_simple_log_metadata, &context);

    assert(context.checked == 1);

    ip_table_destroy(table);
    log_store_destroy(store);
}

static void test_log_store_parse_ssh_line(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    const char *failed_line = "Nov 14 10:15:00 server1 sshd[1234]: Failed password for root from "
                              "192.168.1.20 port 54321 ssh2";

    assert(log_store_parse_ssh_line(store, table, failed_line, 2026, TIMESTAMP_LOCAL, NULL) ==
           PARSE_OK);

    assert(log_store_get_count(store) == 1);
    assert(log_store_count_by_event(store, AUTH_FAILURE) == 1);
    assert(log_store_count_by_event(store, AUTH_SUCCESS) == 0);

    const char *line_ignored =
        "Nov 14 10:15:05 server1 sshd[1235]: Connection closed by 192.168.1.30 port 54322";

    assert(log_store_parse_ssh_line(store, table, line_ignored, 2025, TIMESTAMP_LOCAL, NULL) ==
           PARSE_IGNORED);

    assert(log_store_get_count(store) == 1);
    assert(log_store_count_by_event(store, AUTH_FAILURE) == 1);
    assert(log_store_count_by_event(store, AUTH_SUCCESS) == 0);

    const char *malformed_line =
        "Nov 14 10:15:15 server1 sshd[1237]: Failed password for root from";

    assert(log_store_parse_ssh_line(store, table, malformed_line, 2025, TIMESTAMP_LOCAL, NULL) ==
           PARSE_ERROR);
    assert(log_store_get_count(store) == 1);
    assert(log_store_count_by_event(store, AUTH_FAILURE) == 1);
    assert(log_store_count_by_event(store, AUTH_SUCCESS) == 0);

    ip_table_destroy(table);
    log_store_destroy(store);
}

static void verify_timezone(const LogEventView *event, void *context) {
    (void)context;

    assert(event != NULL);

    assert(event->timestamp == (time_t)0);
}

static void test_utc_timezone_parsing(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    const char *utc_timezone_line = "1970-01-01T00:00:00 192.168.1.20 LOGIN_FAILED";

    assert(log_store_parse_simple_line(store, table, utc_timezone_line, TIMESTAMP_UTC, NULL));

    log_store_foreach(store, verify_timezone, NULL);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_error_response_description(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    ParseIssue issue = PARSE_ISSUE_NONE;

    const char *invalid_ip = "2026-11-14T10:15:00 banana LOGIN_FAILED";

    assert(!log_store_parse_simple_line(store, table, invalid_ip, TIMESTAMP_UTC, &issue));

    assert(issue == PARSE_ISSUE_INVALID_IP);
    assert(log_store_get_count(store) == 0);

    issue = PARSE_ISSUE_NONE;

    const char *invalid_port = "Nov 14 10:15:00 server1 sshd[1234]: "
                               "Failed password for root from "
                               "192.168.1.20 port abc ssh2";

    ParseStatus status =
        log_store_parse_ssh_line(store, table, invalid_port, 2026, TIMESTAMP_UTC, &issue);

    assert(status == PARSE_ERROR);
    assert(issue == PARSE_ISSUE_INVALID_PORT);

    assert(log_store_get_count(store) == 0);

    issue = PARSE_ISSUE_INVALID_PORT;

    const char *publickey_login = 
        "Nov 14 10:15:00 server1 sshd[1234]: "
        "Accepted publickey for ante from "
        "192.168.1.30 port 52342 ssh2";

    status = log_store_parse_ssh_line(store, table, publickey_login, 2026, TIMESTAMP_UTC, &issue);

    assert(status == PARSE_IGNORED);
    assert(issue == PARSE_ISSUE_NONE);

    assert(log_store_get_count(store) == 0);

    issue = PARSE_ISSUE_NONE;

    const char *invalid_date = 
        "INVALID server1 sshd[1234]: "
        "Failed password for root from 192.168.1.20 port 52341 ssh2";

    assert(log_store_parse_ssh_line(
        store,
        table,
        invalid_date,
        2026,
        TIMESTAMP_UTC,
        &issue
    ) == PARSE_ERROR);

    assert(issue == PARSE_ISSUE_INVALID_TIMESTAMP);

    issue = PARSE_ISSUE_NONE;

    const char *missing_hostname = "Nov 14 10:15:00";

    assert(log_store_parse_ssh_line(
        store,
        table,
        missing_hostname,
        2026,
        TIMESTAMP_UTC,
        &issue
    ) == PARSE_ERROR);

    assert(issue == PARSE_ISSUE_MALFORMED_SSH);

    log_store_destroy(store);
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
    test_ssh_parse_status();
    test_ssh_parse_with_year_and_time_normalization();
    test_log_store_lifecycle();
    test_independant_log_stores();
    test_log_store_parse_simple_line();
    test_log_store_parse_ssh_line();
    test_utc_timezone_parsing();
    test_error_response_description();

    printf("\nAll entries test pass!!\n");

    return 0;
}