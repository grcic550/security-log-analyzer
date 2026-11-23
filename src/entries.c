#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
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

typedef struct {
    const char *start;
    size_t length;
} TokenSpan;

static void set_parse_issue(ParseIssue *issue, ParseIssue value) {
    if (issue != NULL) {
        *issue = value;
    }
}

static bool same_calendar_fields(const struct tm *a, const struct tm *b) {

    if (a == NULL || b == NULL) {
        return false;
    }

    return a->tm_year == b->tm_year && a->tm_mon == b->tm_mon && a->tm_mday == b->tm_mday &&
           a->tm_hour == b->tm_hour && a->tm_min == b->tm_min && a->tm_sec == b->tm_sec;
}

static bool is_ambiguous_local_time(const struct tm *calendar) {

    if (calendar == NULL) {
        return false;
    }

    struct tm standard = *calendar;
    struct tm daylight = *calendar;

    standard.tm_isdst = 0;
    daylight.tm_isdst = 1;

    time_t standard_time = mktime(&standard);
    time_t daylight_time = mktime(&daylight);

    if (standard_time == (time_t)-1 || daylight_time == (time_t)-1) {
        return false;
    }

    if (standard.tm_isdst != 0 || !same_calendar_fields(calendar, &standard)) {
        return false;
    }

    if (daylight.tm_isdst <= 0 || !same_calendar_fields(calendar, &daylight)) {
        return false;
    }

    return standard_time != daylight_time;
}

static bool convert_calendar_time(struct tm *calendar, TimestampMode mode, time_t *result) {

    if (calendar == NULL || result == NULL) {
        return false;
    }

    struct tm original = *calendar;

    calendar->tm_isdst = -1;

    time_t converted;

    if (mode == TIMESTAMP_LOCAL) {
        if (is_ambiguous_local_time(&original)) {
            return false;
        }

        converted = mktime(calendar);
    } else if (mode == TIMESTAMP_UTC) {
        converted = timegm(calendar);
    } else {
        return false;
    }

    if (converted == (time_t)-1) {
        return false;
    }

    if (!same_calendar_fields(calendar, &original)) {
        return false;
    }

    *result = converted;

    return true;
}

static bool next_token(const char **cursor, TokenSpan *token) {

    if (cursor == NULL || *cursor == NULL || token == NULL) {
        return false;
    }

    const char *p = *cursor;

    while (isspace((unsigned char)*p)) {
        p++;
    }

    if (*p == '\0') {
        *cursor = p;
        return false;
    }

    const char *start = p;

    while (*p != '\0' && !isspace((unsigned char)*p)) {
        p++;
    }

    token->start = start;
    token->length = (size_t)(p - start);

    *cursor = p;

    return true;
}

static bool copy_token(TokenSpan token, char *destination, size_t capacity) {

    if (destination == NULL || token.length == 0 || token.length >= capacity) {
        return false;
    }

    memcpy(destination, token.start, token.length);

    destination[token.length] = '\0';

    return true;
}

static bool token_equals(TokenSpan token, const char *literal) {

    if (token.start == NULL || literal == NULL) {
        return false;
    }

    size_t literal_length = strlen(literal);

    return token.length == literal_length && memcmp(token.start, literal, literal_length) == 0;
}

static bool parse_auth_span(TokenSpan token, AuthResult *result) {

    if (result == NULL) {
        return false;
    }

    if (token_equals(token, "LOGIN_FAILED")) {
        *result = AUTH_FAILURE;
        return true;
    }

    if (token_equals(token, "LOGIN_SUCCESS")) {
        *result = AUTH_SUCCESS;
        return true;
    }

    return false;
}

static bool is_sshd_process_token(TokenSpan token) {

    if (token.length < 8) {
        return false;
    }

    if (memcmp(token.start, "sshd[", 5) != 0) {
        return false;
    }

    if (token.start[token.length - 2] != ']' || token.start[token.length - 1] != ':') {
        return false;
    }

    for (size_t i = 5; i < token.length - 2; i++) {
        if (!isdigit((unsigned char)token.start[i])) {
            return false;
        }
    }

    return true;
}

static bool valid_ssh_port(TokenSpan token) {

    if (token.start == NULL || token.length == 0) {
        return false;
    }

    unsigned int value = 0;

    for (size_t i = 0; i < token.length; i++) {

        unsigned char c = (unsigned char)token.start[i];

        if (!isdigit(c)) {
            return false;
        }

        unsigned int digit = c - '0';

        if (value > (65535U - digit) / 10U) {
            return false;
        }

        value = value * 10U + digit;
    }

    return value != 0;
}

static bool valid_ip_address(const char *ip_address) {

    if (ip_address == NULL || ip_address[0] == '\0') {
        return false;
    }

    struct in_addr ipv4;
    struct in6_addr ipv6;

    return inet_pton(AF_INET, ip_address, &ipv4) == 1 ||
           inet_pton(AF_INET6, ip_address, &ipv6) == 1;
}

static bool token_starts_with(TokenSpan token, const char *prefix) {

    if (token.start == NULL || prefix == NULL) {
        return false;
    }

    size_t prefix_length = strlen(prefix);

    return token.length >= prefix_length && memcmp(token.start, prefix, prefix_length) == 0;
}

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

static ParseStatus parse_ssh_fields(const char *line, int year, TimestampMode mode, ParsedLog *out,
                                    ParseIssue *issue) {
    char hostname[128];
    char username[64];
    char ip_address[64];
    struct tm date_time = {0};
    time_t final_timestamp;
    AuthResult auth_result;

    set_parse_issue(issue, PARSE_ISSUE_NONE);

    date_time.tm_year = year - 1900;

    char *end = strptime(line, "%b %e %H:%M:%S", &date_time);

    if (end == NULL) {
        set_parse_issue(issue, PARSE_ISSUE_INVALID_TIMESTAMP);
        return PARSE_ERROR;
    }

    if (!convert_calendar_time(&date_time, mode, &final_timestamp)) {
        set_parse_issue(issue, PARSE_ISSUE_INVALID_TIMESTAMP);
        return PARSE_ERROR;
    }

    if (!isspace((unsigned char)*end)){
        set_parse_issue(issue, PARSE_ISSUE_MALFORMED_SSH);
        return PARSE_ERROR;
    }

    const char *cursor = end;

    TokenSpan hostname_token;

    if (!next_token(&cursor, &hostname_token)) {
        set_parse_issue(issue, PARSE_ISSUE_MALFORMED_SSH);
        return PARSE_ERROR;
    }

    if (!copy_token(hostname_token, hostname, sizeof(hostname))) {
        set_parse_issue(issue, PARSE_ISSUE_MALFORMED_SSH);
        return PARSE_ERROR;
    }

    TokenSpan process_token;

    if (!next_token(&cursor, &process_token)) {
        set_parse_issue(issue, PARSE_ISSUE_MALFORMED_SSH);
        return PARSE_ERROR;
    }

    if (!token_starts_with(process_token, "sshd")) {
        return PARSE_IGNORED;
    }

    if (!is_sshd_process_token(process_token)) {
        set_parse_issue(issue, PARSE_ISSUE_INVALID_PROCESS);
        return PARSE_ERROR;
    }

    TokenSpan action_token;

    if (!next_token(&cursor, &action_token)) {
        set_parse_issue(issue, PARSE_ISSUE_MALFORMED_SSH);
        return PARSE_ERROR;
    }

    if (token_equals(action_token, "Failed")) {
        auth_result = AUTH_FAILURE;
    } else if (token_equals(action_token, "Accepted")) {
        auth_result = AUTH_SUCCESS;
    } else {
        return PARSE_IGNORED;
    }

    TokenSpan method_token;
    TokenSpan for_token;

    if (!next_token(&cursor, &method_token)) {
        set_parse_issue(issue, PARSE_ISSUE_MALFORMED_SSH);
        return PARSE_ERROR;
    }

    if (!token_equals(method_token, "password")) {
        return PARSE_IGNORED;
    }

    if (!next_token(&cursor, &for_token) || !token_equals(for_token, "for")) {
        set_parse_issue(issue, PARSE_ISSUE_MALFORMED_SSH);
        return PARSE_ERROR;
    }

    TokenSpan username_token;

    if (!next_token(&cursor, &username_token)) {
        set_parse_issue(issue, PARSE_ISSUE_MALFORMED_SSH);
        return PARSE_ERROR;
    }

    if (auth_result == AUTH_FAILURE && token_equals(username_token, "invalid")) {

        const char *lookahead = cursor;
        TokenSpan next;

        if (next_token(&lookahead, &next) && token_equals(next, "user")) {
            if (!next_token(&lookahead, &username_token)) {
                set_parse_issue(issue, PARSE_ISSUE_MALFORMED_SSH);
                return PARSE_ERROR;
            }

            cursor = lookahead;
        }
    }

    if (!copy_token(username_token, username, sizeof(username))) {
        set_parse_issue(issue, PARSE_ISSUE_MALFORMED_SSH);
        return PARSE_ERROR;
    }

    TokenSpan from_token;

    if (!next_token(&cursor, &from_token) || !token_equals(from_token, "from")) {
        set_parse_issue(issue, PARSE_ISSUE_MALFORMED_SSH);
        return PARSE_ERROR;
    }

    TokenSpan ip_token;

    if (!next_token(&cursor, &ip_token)) {
        set_parse_issue(issue, PARSE_ISSUE_MALFORMED_SSH);
        return PARSE_ERROR;
    }

    if (!copy_token(ip_token, ip_address, sizeof(ip_address)) || !valid_ip_address(ip_address)) {
        set_parse_issue(issue, PARSE_ISSUE_INVALID_IP);
        return PARSE_ERROR;
    }

    TokenSpan port_keyword;

    if (!next_token(&cursor, &port_keyword) || !token_equals(port_keyword, "port")) {
        set_parse_issue(issue, PARSE_ISSUE_MALFORMED_SSH);
        return PARSE_ERROR;
    }

    TokenSpan port_token;

    if (!next_token(&cursor, &port_token) || !valid_ssh_port(port_token)) {
        set_parse_issue(issue, PARSE_ISSUE_INVALID_PORT);
        return PARSE_ERROR;
    }

    TokenSpan protocol_token;

    if (!next_token(&cursor, &protocol_token) || !token_equals(protocol_token, "ssh2")) {
        set_parse_issue(issue, PARSE_ISSUE_MALFORMED_SSH);
        return PARSE_ERROR;
    }

    TokenSpan extra_token;

    if (next_token(&cursor, &extra_token)) {
        set_parse_issue(issue, PARSE_ISSUE_MALFORMED_SSH);
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

ParseStatus log_store_parse_ssh_line(LogStore *store, IpTable *table, const char *line, int year,
                                     TimestampMode mode, ParseIssue *issue) {
    if (store == NULL || table == NULL || line == NULL) {
        return PARSE_ERROR;
    }

    if (year < 1900){
        set_parse_issue(issue, PARSE_ISSUE_INVALID_TIMESTAMP);
        return PARSE_ERROR;
    }

    ParsedLog parsed = {0};

    ParseStatus status = parse_ssh_fields(line, year, mode, &parsed, issue);

    if (status != PARSE_OK) {
        return status;
    }

    if (!log_store_add(store, table, parsed.timestamp, parsed.ip_address,
                       parsed.has_username ? parsed.username : NULL,
                       parsed.has_hostname ? parsed.hostname : NULL, parsed.result)) {

        set_parse_issue(issue, PARSE_ISSUE_STORAGE_FAILURE);
        return PARSE_ERROR;
    }

    return PARSE_OK;
}

static bool parse_simple_log_line(const char *line, TimestampMode mode, ParsedLog *result,
                                  ParseIssue *issue) {

    if (issue != NULL) {
        *issue = PARSE_ISSUE_NONE;
    }

    if (line == NULL || result == NULL) {
        return false;
    }

    char date[64];
    char ip_address[64];

    const char *cursor = line;

    TokenSpan date_token;
    TokenSpan ip_token;
    TokenSpan status_token;
    TokenSpan extra_token;

    if (!next_token(&cursor, &date_token) || !next_token(&cursor, &ip_token) ||
        !next_token(&cursor, &status_token) || next_token(&cursor, &extra_token)) {

        if (issue != NULL) {
            *issue = PARSE_ISSUE_FIELD_COUNT;
        }

        return false;
    }

    if (!copy_token(date_token, date, sizeof(date)) ||
        !copy_token(ip_token, ip_address, sizeof(ip_address))) {
        if (issue != NULL) {
            *issue = PARSE_ISSUE_FIELD_TOO_LONG;
        }

        return false;
    }

    if (!valid_ip_address(ip_address)) {
        if (issue != NULL) {
            *issue = PARSE_ISSUE_INVALID_IP;
        }
        return false;
    }

    struct tm date_time = {0};
    time_t final_time;

    char *end = strptime(date, "%Y-%m-%dT%H:%M:%S", &date_time);

    if (end == NULL || *end != '\0') {

        if (issue != NULL) {
            *issue = PARSE_ISSUE_INVALID_TIMESTAMP;
        }
        return false;
    }

    if (!convert_calendar_time(&date_time, mode, &final_time)) {

        if (issue != NULL) {
            *issue = PARSE_ISSUE_INVALID_TIMESTAMP;
        }
        return false;
    }

    ParsedLog temp = {0};

    temp.timestamp = final_time;

    if (!parse_auth_span(status_token, &temp.result)) {
        if (issue != NULL) {
            *issue = PARSE_ISSUE_INVALID_STATUS;
        }

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

    TokenSpan token = {.start = text, .length = strlen(text)};

    return parse_auth_span(token, result);
}

bool log_store_parse_simple_line(LogStore *store, IpTable *table, const char *line,
                                 TimestampMode mode, ParseIssue *issue) {

    if (store == NULL || table == NULL || line == NULL) {
        return false;
    }

    ParsedLog parsed = {0};

    if (!parse_simple_log_line(line, mode, &parsed, issue)) {
        return false;
    }

    if (!log_store_add(store, table, parsed.timestamp, parsed.ip_address,
                       parsed.has_username ? parsed.username : NULL,
                       parsed.has_hostname ? parsed.hostname : NULL, parsed.result)) {

        set_parse_issue(issue, PARSE_ISSUE_STORAGE_FAILURE);

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