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

struct LogStore {
    LogEntry **entries;
    size_t count;
    size_t capacity;
    size_t successful_logins;
    size_t failed_logins;
};

static void free_log_entry(LogEntry *entry) {

    if (entry == NULL) {
        return;
    }

    free(entry->ip_address);
    free(entry->username);
    free(entry->hostname);
    free(entry);
}

static LogEntry *create_log_entry(const char *ip_address, const char *username,
                                  const char *hostname, time_t timestamp, AuthResult result) {
    LogEntry *new_log = malloc(sizeof(*new_log));

    if (new_log == NULL) {
        return NULL;
    }

    new_log->ip_address = NULL;
    new_log->username = NULL;
    new_log->hostname = NULL;

    new_log->ip_address = malloc(strlen(ip_address) + 1);

    if (new_log->ip_address == NULL) {
        fprintf(stderr, "Failed to allocate memory for IP address!\n");
        free_log_entry(new_log);
        return NULL;
    }

    if (username != NULL) {
        new_log->username = malloc(strlen(username) + 1);

        if (new_log->username == NULL) {
            fprintf(stderr, "Failed to allocate memory for username!\n");
            free_log_entry(new_log);
            return NULL;
        }
        strcpy(new_log->username, username);
    }

    if (hostname != NULL) {
        new_log->hostname = malloc(strlen(hostname) + 1);

        if (new_log->hostname == NULL) {
            fprintf(stderr, "Failed to allocate memory for hostname!\n");
            free_log_entry(new_log);
            return NULL;
        }
        strcpy(new_log->hostname, hostname);
    }

    strcpy(new_log->ip_address, ip_address);

    new_log->result = result;
    new_log->timestamp = timestamp;

    return new_log;
}

static bool resize_log_store(LogStore *store) {

    size_t new_capacity = store->capacity == 0 ? 8 : store->capacity * 2;

    LogEntry **temp = realloc(store->entries, new_capacity * sizeof(*store->entries));

    if (temp == NULL) {
        fprintf(stderr, "Failed to reallocate memory for store!\n");
        return false;
    }

    store->entries = temp;
    store->capacity = new_capacity;

    return true;
}

LogStore *log_store_create(void) {

    LogStore *new_store = calloc(1, sizeof(*new_store));

    if (new_store == NULL) {
        fprintf(stderr, "Failed to allocate memory for new store!\n");
        return NULL;
    }

    new_store->capacity = 8;
    new_store->entries = calloc(new_store->capacity, sizeof(*new_store->entries));

    if (new_store->entries == NULL) {
        fprintf(stderr, "Failed to allocate memory for entries in store!\n");
        free(new_store);
        return NULL;
    }

    return new_store;
}

bool log_store_add(LogStore *store, IpTable *table, time_t timestamp, const char *ip_address,
                   const char *username, const char *hostname, AuthResult result) {

    if (store == NULL || table == NULL || ip_address == NULL || ip_address[0] == '\0') {
        return false;
    }

    if (result != AUTH_FAILURE && result != AUTH_SUCCESS) {
        return false;
    }

    LogEntry *new_log = create_log_entry(ip_address, username, hostname, timestamp, result);

    if (new_log == NULL) {
        return false;
    }

    if (store->count >= store->capacity) {
        if (!resize_log_store(store)) {
            fprintf(stderr, "Failed to resize store!\n");
            free_log_entry(new_log);
            return false;
        }
    }

    if (result == AUTH_SUCCESS) {
        store->successful_logins++;
    } else if (result == AUTH_FAILURE) {
        if (!ip_table_insert(table, ip_address)) {
            free_log_entry(new_log);
            return false;
        }
        store->failed_logins++;
    }

    store->entries[store->count++] = new_log;

    return true;
}

size_t log_store_get_count(const LogStore *store) {

    if (store == NULL) {
        return 0;
    }

    return store->count;
}

size_t log_store_count_by_event(const LogStore *store, AuthResult result) {

    if (store == NULL) {
        return 0;
    }

    if (result != AUTH_FAILURE && result != AUTH_SUCCESS) {
        return 0;
    }

    if (result == AUTH_FAILURE) {
        return store->failed_logins;
    }

    return store->successful_logins;
}

void log_store_foreach(const LogStore *store, LogCallback callback, void *context) {

    if (store == NULL || callback == NULL) {
        return;
    }

    for (size_t i = 0; i < store->count; i++) {
        LogEventView view = {.timestamp = store->entries[i]->timestamp,
                             .ip_address = store->entries[i]->ip_address,
                             .username = store->entries[i]->username,
                             .hostname = store->entries[i]->hostname,
                             .result = store->entries[i]->result};

        callback(&view, context);
    }
}

static ParseStatus parse_ssh_fields(const char *line, int year, ParsedLog *out) {
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

    if (end == NULL) {
        return PARSE_ERROR;
    }
    struct tm original = date_time;
    final_timestamp = mktime(&date_time);

    if (final_timestamp == (time_t)-1 || date_time.tm_year != original.tm_year ||
        date_time.tm_mon != original.tm_mon || date_time.tm_mday != original.tm_mday ||
        date_time.tm_hour != original.tm_hour || date_time.tm_min != original.tm_min ||
        date_time.tm_sec != original.tm_sec) {
        return PARSE_ERROR;
    }

    if (sscanf(end, " %127s%n", hostname, &consumed) != 1) {
        return PARSE_ERROR;
    }

    const char *remaining = end + consumed;
    int consumed2 = 0;

    matched = sscanf(remaining, " sshd[%*u]: Failed password for %63s from %63s port %*u ssh2 %n",
                     username, ip_address, &consumed2);

    if (matched == 2 && consumed2 > 0) {
        auth_result = AUTH_FAILURE;
    } else {

        consumed2 = 0;
        matched =
            sscanf(remaining,
                   " sshd[%*u]: Failed password for invalid user %63s from %63s port %*u ssh2 %n",
                   username, ip_address, &consumed2);

        if (matched == 2 && consumed2 > 0) {
            auth_result = AUTH_FAILURE;
        } else {

            consumed2 = 0;
            matched = sscanf(remaining,
                             " sshd[%*u]: Accepted password for %63s from %63s port %*u ssh2 %n",
                             username, ip_address, &consumed2);

            if (matched == 2 && consumed2 > 0) {
                auth_result = AUTH_SUCCESS;
            } else {
                if (strstr(remaining, "Failed password for ") != NULL ||
                    strstr(remaining, "Accepted password for ") != NULL) {
                    return PARSE_ERROR;
                }
                return PARSE_IGNORED;
            }
        }
    }

    if (consumed2 == 0) {
        return PARSE_ERROR;
    }

    const char *ending = remaining + consumed2;

    if (*ending != '\0') {
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

    *out = temp;

    return PARSE_OK;
}

ParseStatus log_store_parse_ssh_line(LogStore *store, IpTable *table, const char *line, int year) {
    if (store == NULL || table == NULL || line == NULL) {
        return PARSE_ERROR;
    }

    ParsedLog parsed = {0};

    ParseStatus status = parse_ssh_fields(line, year, &parsed);

    if (status != PARSE_OK) {
        return status;
    }

    if (!log_store_add(store, table, parsed.timestamp, parsed.ip_address,
                       parsed.has_username ? parsed.username : NULL,
                       parsed.has_hostname ? parsed.hostname : NULL, parsed.result)) {
        return PARSE_ERROR;
    }

    return PARSE_OK;
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

    if (final_time == (time_t)-1 || date_time.tm_year != original.tm_year ||
        date_time.tm_mon != original.tm_mon || date_time.tm_mday != original.tm_mday ||
        date_time.tm_hour != original.tm_hour || date_time.tm_min != original.tm_min ||
        date_time.tm_sec != original.tm_sec) {
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

bool log_store_parse_simple_line(LogStore *store, IpTable *table, const char *line) {

    if (store == NULL || table == NULL || line == NULL) {
        return false;
    }

    ParsedLog parsed = {0};

    if (!parse_simple_log_line(line, &parsed)) {
        return false;
    }

    if (!log_store_add(store, table, parsed.timestamp, parsed.ip_address,
                       parsed.has_username ? parsed.username : NULL,
                       parsed.has_hostname ? parsed.hostname : NULL, parsed.result)) {
        return false;
    }

    return true;
}

void log_store_destroy(LogStore *store) {

    if (store == NULL) {
        return;
    }

    for (size_t i = 0; i < store->count; i++) {
        free_log_entry(store->entries[i]);
    }

    free(store->entries);
    free(store);
}