#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "entries.h"
#include "ip_table.h"

struct LogEntry {
    time_t timestamp;
    char *ip_address;
    AuthResult result;
};

typedef struct {
    time_t timestamp;
    char ip_address[64];
    AuthResult result;
} ParsedLog;

static LogEntry **log_entry = NULL;
static size_t log_count = 0;
static size_t capacity = 0;
static size_t successful_logins = 0;
static size_t failed_logins = 0;

static bool resize_logs();
static void clear_logs(void);

size_t get_log_count(void) { return log_count; }

static bool parse_simple_log_line(const char *line, ParsedLog *result) {
    if (line == NULL || result == NULL) {
        return false;
    }

    char date[64];
    char ip_address[64];
    char status[32];

    if (sscanf(line, "%63s %63s %31s", date, ip_address, status) != 3) {
        fprintf(stderr, "Error while parsing line!\n");
        return false;
    }

    struct tm date_time = {0};
    time_t final_time;

    char *end = strptime(date, "%Y-%m-%dT%H:%M:%S", &date_time);

    if (end == NULL || *end != '\0') {
        fprintf(stderr, "Invalid timestamp format!\n");
        return false;
    }

    date_time.tm_isdst = -1;
    final_time = mktime(&date_time);

    ParsedLog temp = {0};

    temp.timestamp = final_time;

    if (!parse_auth_result(status, &temp.result)) {
        fprintf(stderr, "Error with event_type!\n");
        return false;
    }

    strcpy(temp.ip_address, ip_address);
    *result = temp;

    return true;
}

bool parse_auth_result(const char *text, AuthResult *result) {

    if (text == NULL || result == NULL) {
        return false;
    }

    if (strcmp(text, "LOGIN_FAILED") == 0) {
        *result = AUTH_FAILURE;
        return true;
    }
    if (strcmp(text, "LOGIN_SUCCESS") == 0) {
        *result = AUTH_SUCCESS;
        return true;
    }

    return false;
}

size_t count_logs_by_event(AuthResult result) {

    if (result == AUTH_FAILURE) {
        return failed_logins;
    } else if (result == AUTH_SUCCESS) {
        return successful_logins;
    }

    return 0;
}

void log_management_init(void) {
    if (log_entry != NULL) {
        return;
    }

    capacity = 10;
    log_count = 0;

    log_entry = malloc(capacity * sizeof(*log_entry));

    if (log_entry == NULL) {
        perror("Failed to allocate memory for entry");
        exit(1);
    }
}

bool add_log(IpTable *table, time_t timestamp, const char ip_address[], AuthResult result) {

    if (table == NULL || ip_address == NULL || ip_address[0] == '\0') {
        return false;
    }

    if (result != AUTH_FAILURE && result != AUTH_SUCCESS) {
        return false;
    }

    LogEntry *new_log = malloc(sizeof(*new_log));

    if (new_log == NULL) {
        return false;
    }

    new_log->ip_address = malloc(strlen(ip_address) + 1);

    if (new_log->ip_address == NULL) {
        perror("Failed allocating memory for ip_address");
        free(new_log);
        return false;
    }

    strcpy(new_log->ip_address, ip_address);

    new_log->result = result;
    new_log->timestamp = timestamp;

    if (log_count >= capacity) {
        if (!resize_logs()) {
            free(new_log->ip_address);
            free(new_log);

            return false;
        }
    }

    if (result == AUTH_SUCCESS) {
        successful_logins++;
    } else if (result == AUTH_FAILURE) {
        if (!ip_table_insert(table, ip_address)) {
            fprintf(stderr, "Failed to add IP address to hash table");
            free(new_log->ip_address);
            free(new_log);
            return false;
        }

        failed_logins++;
    }

    log_entry[log_count++] = new_log;

    return true;
}

static bool resize_logs() {

    size_t new_capacity;

    if (capacity == 0) {
        new_capacity = 10;
    } else {
        new_capacity = capacity * 2;
    }

    LogEntry **temp = realloc(log_entry, new_capacity * sizeof(*log_entry));

    if (temp == NULL) {
        perror("Failed to allocate memory for temp of resizing");
        return false;
    }

    log_entry = temp;
    capacity = new_capacity;

    return true;
}

bool parse_log_line(IpTable *table, const char *line) {

    if (line == NULL) {
        return false;
    }

    ParsedLog log;

    if (!parse_simple_log_line(line, &log)) {
        return false;
    }

    if (!add_log(table, log.timestamp, log.ip_address, log.result)) {
        fprintf(stderr, "Error: Failed to add log!!\n");
        return false;
    }

    return true;
}

void log_management_foreach(LogCallback callback, void *context) {

    if (callback == NULL) {
        return;
    }

    for (size_t i = 0; i < log_count; i++) {
        callback(log_entry[i]->timestamp, log_entry[i]->ip_address, log_entry[i]->result, context);
    }
}

void log_management_destroy(void) {

    clear_logs();

    log_entry = NULL;
    capacity = 0;
}

static void clear_logs(void) {

    for (size_t i = 0; i < log_count; i++) {
        free(log_entry[i]->ip_address);
        free(log_entry[i]);
    }

    log_count = 0;
    successful_logins = 0;
    failed_logins = 0;
    free(log_entry);
}