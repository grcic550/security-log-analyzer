#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "entries.h"
#include "ip_table.h"

static size_t allocations_until_failure = 0;
static bool fail_next_realloc = false;

static void fail_on_nth_malloc(size_t n) {
    assert(n > 0);
    allocations_until_failure = n;
}

void *__real_malloc(size_t size);
void *__real_realloc(void *ptr, size_t size);

void *__wrap_malloc(size_t size) {
    if (allocations_until_failure > 0) {
        allocations_until_failure--;

        if (allocations_until_failure == 0) {
            return NULL;
        }
    }

    return __real_malloc(size);
}

void *__wrap_realloc(void *ptr, size_t size) {

    if (fail_next_realloc) {
        fail_next_realloc = false;
        return NULL;
    }

    return __real_realloc(ptr, size);
}

static void test_malloc_failure(size_t failure_number) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    const char *line = "2026-11-14T10:15:00 192.168.1.20 LOGIN_FAILED";

    ParseIssue issue = PARSE_ISSUE_NONE;

    fail_on_nth_malloc(failure_number);

    assert(!log_store_parse_simple_line(store, table, line, TIMESTAMP_UTC, &issue));

    assert(issue == PARSE_ISSUE_STORAGE_FAILURE);
    assert(log_store_get_count(store) == 0);
    assert(ip_table_get_count(table, "192.168.1.20") == 0);
    assert(allocations_until_failure == 0);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_store_realloc_failure(void) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    const char *initial_lines[8] = {"2026-11-14T10:00:00 192.168.1.10 LOGIN_SUCCESS",
                                    "2026-11-14T10:01:00 192.168.1.11 LOGIN_SUCCESS",
                                    "2026-11-14T10:02:00 192.168.1.12 LOGIN_SUCCESS",
                                    "2026-11-14T10:03:00 192.168.1.13 LOGIN_SUCCESS",
                                    "2026-11-14T10:04:00 192.168.1.14 LOGIN_SUCCESS",
                                    "2026-11-14T10:05:00 192.168.1.15 LOGIN_SUCCESS",
                                    "2026-11-14T10:06:00 192.168.1.16 LOGIN_SUCCESS",
                                    "2026-11-14T10:07:00 192.168.1.17 LOGIN_SUCCESS"};

    ParseIssue issue = PARSE_ISSUE_NONE;

    for (size_t i = 0; i < 8; i++) {
        assert(log_store_parse_simple_line(store, table, initial_lines[i], TIMESTAMP_UTC, &issue));
    }

    const char *ninth_line = "2026-11-14T10:15:00 192.168.1.20 LOGIN_FAILED";

    fail_next_realloc = true;

    assert(!log_store_parse_simple_line(store, table, ninth_line, TIMESTAMP_UTC, &issue));

    assert(issue == PARSE_ISSUE_STORAGE_FAILURE);
    assert(log_store_get_count(store) == 8);
    assert(ip_table_get_count(table, "192.168.1.20") == 0);

    fail_next_realloc = false;

    assert(log_store_parse_simple_line(store, table, ninth_line, TIMESTAMP_UTC, &issue));

    assert(issue == PARSE_ISSUE_NONE);
    assert(log_store_get_count(store) == 9);
    assert(ip_table_get_count(table, "192.168.1.20") == 1);

    log_store_destroy(store);
    ip_table_destroy(table);
}

static void test_ssh_malloc_failure(size_t failure_number) {

    LogStore *store = log_store_create();
    assert(store != NULL);

    IpTable *table = ip_table_create(2);
    assert(table != NULL);

    const char *line = "Nov 14 10:15:00 server1 sshd[1234]: "
                       "Failed password for root from "
                       "192.168.1.20 port 52341 ssh2";

    ParseIssue issue = PARSE_ISSUE_NONE;

    fail_on_nth_malloc(failure_number);

    assert(log_store_parse_ssh_line(store, table, line, 2026, TIMESTAMP_UTC, &issue) ==
           PARSE_ERROR);

    assert(issue == PARSE_ISSUE_STORAGE_FAILURE);
    assert(log_store_get_count(store) == 0);
    assert(ip_table_get_count(table, "192.168.1.20") == 0);
    assert(allocations_until_failure == 0);

    log_store_destroy(store);
    ip_table_destroy(table);
}

int main(void) {

    for (size_t i = 1; i <= 4; i++) {
        test_malloc_failure(i);
    }

    for (size_t i = 1; i <= 6; i++) {
        test_ssh_malloc_failure(i);
    }

    test_store_realloc_failure();

    puts("Allocation failure tests passed!\n\n");
    return 0;
}