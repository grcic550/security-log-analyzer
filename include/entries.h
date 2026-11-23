#ifndef ENTRIES_H
#define ENTRIES_H

#include "ip_table.h"
#include <stdbool.h>
#include <time.h>

typedef struct LogEntry LogEntry;
typedef enum { AUTH_SUCCESS, AUTH_FAILURE } AuthResult;
typedef enum { TIMESTAMP_LOCAL, TIMESTAMP_UTC } TimestampMode;
typedef enum {
    PARSE_ISSUE_NONE,
    PARSE_ISSUE_FIELD_COUNT,
    PARSE_ISSUE_FIELD_TOO_LONG,
    PARSE_ISSUE_INVALID_IP,
    PARSE_ISSUE_INVALID_TIMESTAMP,
    PARSE_ISSUE_INVALID_STATUS,
    PARSE_ISSUE_STORAGE_FAILURE,
    PARSE_ISSUE_INVALID_PROCESS,
    PARSE_ISSUE_INVALID_PORT,
    PARSE_ISSUE_MALFORMED_SSH
} ParseIssue;

typedef struct {
    time_t timestamp;
    const char *ip_address;
    const char *username;
    const char *hostname;
    AuthResult result;
} LogEventView;

typedef struct LogStore LogStore;
typedef void (*LogCallback)(const LogEventView *event, void *context);
typedef enum { PARSE_OK, PARSE_IGNORED, PARSE_ERROR } ParseStatus;

LogStore *log_store_create(void);
bool log_store_add(LogStore *store, IpTable *table, time_t timestamp, const char *ip_address,
                   const char *username, const char *hostname, AuthResult result);

bool log_store_parse_simple_line(LogStore *store, IpTable *table, const char *line,
                                 TimestampMode mode, ParseIssue *issue);

ParseStatus log_store_parse_ssh_line(LogStore *store, IpTable *table, const char *line, int year,
                                     TimestampMode mode, ParseIssue *issue);

size_t log_store_get_count(const LogStore *store);
size_t log_store_count_by_event(const LogStore *store, AuthResult result);
void log_store_foreach(const LogStore *store, LogCallback callback, void *context);

bool parse_auth_result(const char *text, AuthResult *result);

void log_store_destroy(LogStore *store);

#endif