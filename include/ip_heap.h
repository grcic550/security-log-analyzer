#ifndef IP_HEAP_H
#define IP_HEAP_H

#include <stdbool.h>
#include <stddef.h>

#include "ip_table.h"

typedef struct {
    const char *ip_address;
    size_t failed_attempts;
} IpRankEntry;

typedef struct IpMinHeap IpMinHeap;

IpMinHeap *ip_heap_create(size_t capacity);
void ip_heap_destroy(IpMinHeap *heap);
size_t ip_heap_size(const IpMinHeap *heap);
size_t ip_heap_capacity(const IpMinHeap *heap);
bool ip_heap_push(IpMinHeap *heap, IpRankEntry entry);
bool ip_heap_peek_min(const IpMinHeap *heap, IpRankEntry *out);
bool ip_heap_pop_min(IpMinHeap *heap, IpRankEntry *out);
bool ip_heap_replace_min(IpMinHeap *heap, IpRankEntry entry);

bool ip_heap_top_k_from_table(const IpTable *table, size_t k, IpRankEntry *out_entries, size_t *out_count);


#endif