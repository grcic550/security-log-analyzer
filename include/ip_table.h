#ifndef IP_TABLE_H
#define IP_TABLE_H

#include <stdbool.h>
#include <stddef.h>

typedef struct IpEntry IpEntry;
typedef struct IpTable IpTable;
typedef void (*IpCallback)(const char *ip_address, size_t failed_attempts, void *context);

IpEntry *create_ip_entry(const char *ip_address);
bool ip_table_insert(IpTable *table, const char *ip_address);
IpTable *ip_table_create(size_t initial_bucket_count);
void free_entries(IpEntry *head);
void ip_table_destroy(IpTable *table);
size_t ip_table_get_count(IpTable *table, const char *ip_address);
void ip_table_print_report(IpTable *table);

void ip_table_foreach(const IpTable *table, IpCallback callback, void *context);

#endif