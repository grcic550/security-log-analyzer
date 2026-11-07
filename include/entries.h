#ifndef ENTRIES_H
#define ENTRIES_H

#include <stdbool.h>
#include <time.h>
#include "ip_table.h"

typedef struct LogEntry LogEntry;

bool parse_log_line(IpTable *table, const char *line);
bool add_log(IpTable *table, time_t timestamp, char *ip_address, char *event_type);
size_t get_log_count(void);
size_t count_logs_by_event(const char *event_type);
void log_management_init(void);
void log_management_destroy(void);

#endif