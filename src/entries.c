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
    char *username;
    char *hostname;
    AuthResult result;
};

typedef struct {
    time_t timestamp;
    char ip_address[64];
    char username[64];
    char hostname[128];

    bool has_username;
    bool has_hostname;

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

ParseStatus parse_ssh_log_line(
    IpTable *table,
    const char *line,
    int year
) {

    if (table == NULL || line == NULL || year < 1900){
        return PARSE_ERROR;
    }

    char hostname[128];
    char username[64];
    char ip_address[64];
    struct tm date_time = {0};
    time_t final_timestamp;
    int consumed = 0;
    int matched = 0;
    AuthResult auth_result;

    date_time.tm_year = year - 1900;
    date_time.tm_isdst = -1;
    
    char *end = strptime(line, "%b %e %H:%M:%S", &date_time);

    if (end == NULL){
        return PARSE_ERROR;
    }
    struct tm original = date_time;
    final_timestamp = mktime(&date_time);

    if (final_timestamp == (time_t)-1 || date_time.tm_year != original.tm_year || date_time.tm_mon != original.tm_mon ||
        date_time.tm_mday != original.tm_mday || date_time.tm_hour != original.tm_hour ||
        date_time.tm_min != original.tm_min || date_time.tm_sec != original.tm_sec){
            return PARSE_ERROR;
    }

    if (sscanf(end, " %127s%n", hostname, &consumed) != 1){
        return PARSE_ERROR;
    }

    const char *remaining = end + consumed;
    int consumed2 = 0;

    matched = sscanf(
        remaining,
        " sshd[%*u]: Failed password for %63s from %63s port %*u ssh2 %n",
        username,
        ip_address,
        &consumed2
    );

    if (matched == 2 && consumed2 > 0){
        auth_result = AUTH_FAILURE;
    } else {
        
        consumed2 = 0;
        matched = sscanf(
            remaining,
            " sshd[%*u]: Failed password for invalid user %63s from %63s port %*u ssh2 %n",
            username,
            ip_address,
            &consumed2
        );

        if (matched == 2 && consumed2 > 0){
            auth_result = AUTH_FAILURE;
        } else {

            consumed2 = 0;
            matched = sscanf(
                remaining,
                " sshd[%*u]: Accepted password for %63s from %63s port %*u ssh2 %n",
                username,
                ip_address,
                &consumed2
            );

            if (matched == 2 && consumed2 > 0){
                auth_result = AUTH_SUCCESS;
            } else {
                if (strstr(remaining, "Failed password for ") != NULL ||
                    strstr(remaining, "Accepted password for ") != NULL){
                        return PARSE_ERROR;
                    }
                return PARSE_IGNORED;
            }
        }
    }

    if (consumed2 == 0){
        return PARSE_ERROR;
    }

    const char *ending = remaining + consumed2;

    if (*ending != '\0'){
        return PARSE_ERROR;
    }

    ParsedLog temp = {0};

    temp.timestamp = final_timestamp;
    strcpy(temp.hostname, hostname);
    temp.has_hostname = true;

    strcpy(temp.username, username);
    temp.has_username = true;

    strcpy(temp.ip_address, ip_address);
    temp.result = auth_result;

    if (!add_log(
        table, 
        temp.timestamp,
        temp.ip_address,
        temp.has_username ? temp.username : NULL,
        temp.has_hostname ? temp.hostname : NULL,
        temp.result    
    )){
        return PARSE_ERROR;
    }

    return PARSE_OK;
}

static void free_log_entry(LogEntry *entry){

    if (entry == NULL){
        return;
    }

    free(entry->ip_address);
    free(entry->username);
    free(entry->hostname);
    free(entry);
}

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
    struct tm original = date_time;
    final_time = mktime(&date_time);

    if (final_time == (time_t)-1 || date_time.tm_year != original.tm_year || date_time.tm_mon != original.tm_mon ||
        date_time.tm_mday != original.tm_mday || date_time.tm_hour != original.tm_hour ||
        date_time.tm_min != original.tm_min || date_time.tm_sec != original.tm_sec){
            return false;
        }

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

bool add_log(
    IpTable *table, time_t timestamp, 
    const char *ip_address, 
    const char *username, 
    const char *hostname, 
    AuthResult result
) {

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

    new_log->ip_address = NULL;
    new_log->username = NULL;
    new_log->hostname = NULL;

    new_log->ip_address = malloc(strlen(ip_address) + 1);

    if (new_log->ip_address == NULL) {
        fprintf(stderr, "Failed to allocate memory for IP address!\n");
        free_log_entry(new_log);
        return false;
    }

    if (username != NULL){
        new_log->username = malloc(strlen(username) + 1);

        if (new_log->username == NULL){
            fprintf(stderr, "Failed to allocate memory for username!\n");
            free_log_entry(new_log);
            return false;
        }
        strcpy(new_log->username, username);

    }

    if (hostname != NULL){
        new_log->hostname = malloc(strlen(hostname) +1);

        if (new_log->hostname == NULL){
            fprintf(stderr, "Failed to allocate memory for hostname!\n");
            free_log_entry(new_log);
            return false;
        }
        strcpy(new_log->hostname, hostname);

    }

    strcpy(new_log->ip_address, ip_address);

    new_log->result = result;
    new_log->timestamp = timestamp;


    if (log_count >= capacity) {
        if (!resize_logs()) {
            free_log_entry(new_log);
            return false;
        }
    }

    if (result == AUTH_SUCCESS) {
        successful_logins++;
    } else if (result == AUTH_FAILURE) {
        if (!ip_table_insert(table, ip_address)) {
            fprintf(stderr, "Failed to add IP address to hash table");
            free_log_entry(new_log);
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

    if (!add_log(
        table, 
        log.timestamp, 
        log.ip_address,
        log.has_username ? log.username : NULL, 
        log.has_hostname ? log.hostname : NULL, 
        log.result)
    ) {
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
        LogEventView view = {
            .timestamp = log_entry[i]->timestamp,
            .ip_address = log_entry[i]->ip_address,
            .username = log_entry[i]->username,
            .hostname = log_entry[i]->hostname,
            .result = log_entry[i]->result
        };

        callback(&view, context);
    }
}

void log_management_destroy(void) {

    clear_logs();

    log_entry = NULL;
    capacity = 0;
}

static void clear_logs(void) {

    for (size_t i = 0; i < log_count; i++) {
        free_log_entry(log_entry[i]);
    }

    log_count = 0;
    successful_logins = 0;
    failed_logins = 0;
    free(log_entry);
}