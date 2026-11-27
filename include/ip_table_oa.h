#ifndef IP_TABLE_OA_H
#define IP_TABLE_OA_H

#include <stdbool.h>
#include <stddef.h>

typedef struct IpTableOA IpTableOA;
typedef void (*IpOACallback)(const char *ip_address, size_t failed_attempts, void *context);

IpTableOA *ip_table_oa_create(size_t initial_capacity);
bool ip_table_oa_insert(IpTableOA *table, const char *ip_address);
size_t ip_table_oa_get_count(const IpTableOA *table, const char *ip_address);
size_t ip_table_oa_size(const IpTableOA *table);
size_t ip_table_oa_capacity(const IpTableOA *table);
bool ip_table_oa_remove(IpTableOA *table, const char *ip_address);
void ip_table_oa_foreach(const IpTableOA *table, IpOACallback callback, void *context);
void ip_table_oa_destroy(IpTableOA *table);
size_t ip_table_oa_max_psl(IpTableOA *table);

#endif