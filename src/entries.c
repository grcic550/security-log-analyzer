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
    char *event_type;
};

static LogEntry **log_entry = NULL;
static size_t log_count = 0;
static size_t capacity = 0;
static size_t successful_logins = 0;
static size_t failed_logins = 0;

static bool resize_logs();
static void clear_logs(void);

size_t get_log_count(void) { return log_count; }

size_t count_logs_by_event(const char *event_type) {

    if (strcmp(event_type, "LOGIN_FAILED") == 0) {
        return failed_logins;
    } else if (strcmp(event_type, "LOGIN_SUCCESS") == 0) {
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

bool add_log(IpTable *table, time_t timestamp, char ip_address[], char event_type[]) {

    if (ip_address == NULL || event_type == NULL || ip_address[0] == '\0' ||
        event_type[0] == '\0') {
        return false;
    }

    if (strcmp(event_type, "LOGIN_FAILED") != 0 && strcmp(event_type, "LOGIN_SUCCESS") != 0) {
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

    new_log->event_type = malloc(strlen(event_type) + 1);

    if (new_log->event_type == NULL) {
        perror("Failed to allocate memory for event_type");
        free(new_log->ip_address);
        free(new_log);
        return false;
    }

    strcpy(new_log->event_type, event_type);
    strcpy(new_log->ip_address, ip_address);

    new_log->timestamp = timestamp;

    if (log_count >= capacity) {
        if (!resize_logs()) {
            free(new_log->event_type);
            free(new_log->ip_address);
            free(new_log);

            return false;
        }
    }

    if (strcmp(event_type, "LOGIN_SUCCESS") == 0) {
        successful_logins++;
    } else if (strcmp(event_type, "LOGIN_FAILED") == 0) {
        if (!ip_table_insert(table, ip_address)) {
            fprintf(stderr, "Failed to add IP address to hash table");
            free(new_log->event_type);
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

    char date[30];
    char ip_address[20];
    char status[30];

    if (sscanf(line, "%29s %19s %29s", date, ip_address, status) != 3) {
        printf("Error while parsing line!\n");
        return false;
    }

    printf("---Extracted text---\n");
    printf("Temporary date string: %s\n", date);
    printf("IP Address:            %s\n", ip_address);
    printf("Status:                %s\n", status);

    struct tm date_time = {0};
    time_t final_time;

    if (strptime(date, "%Y-%m-%dT%H:%M:%S", &date_time) == NULL) {
        printf("Error: Format is not right!\n");
        return false;
    }

    final_time = mktime(&date_time);

    if (!add_log(table, final_time, ip_address, status)) {
        return false;
    }

    return true;
}

void log_management_destroy(void) {

    clear_logs();

    log_entry = NULL;
    capacity = 0;
}

static void clear_logs(void) {

    for (size_t i = 0; i < log_count; i++) {
        free(log_entry[i]->ip_address);
        free(log_entry[i]->event_type);
        free(log_entry[i]);
    }

    log_count = 0;
    successful_logins = 0;
    failed_logins = 0;
    free(log_entry);
}