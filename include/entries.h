#ifndef ENTRIES_H
#define ENTRIES_H

#include "ip_table.h"
#include <stdbool.h>
#include <time.h>

typedef struct LogEntry LogEntry;
typedef enum { AUTH_SUCCESS, AUTH_FAILURE } AuthResult;
typedef void (*LogCallback)(time_t timestamp, const char *ip_address, AuthResult result,
                            void *context);

bool parse_log_line(IpTable *table, const char *line);
bool add_log(IpTable *table, time_t timestamp, const char *ip_address, AuthResult result);
bool parse_auth_result(const char *text, AuthResult *result);
size_t get_log_count(void);
size_t count_logs_by_event(AuthResult result);

void log_management_foreach(LogCallback callback, void *context);
void log_management_init(void);
void log_management_destroy(void);

#endif