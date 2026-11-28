#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "ip_heap.h"

struct IpMinHeap {
    IpRankEntry *nodes;
    size_t size;
    size_t capacity;
};

static bool is_worse_rank(const IpRankEntry *a, const IpRankEntry *b) {

    if (a == NULL || b == NULL) {
        return false;
    }

    if (a->failed_attempts != b->failed_attempts) {
        return a->failed_attempts < b->failed_attempts;
    }

    return strcmp(a->ip_address, b->ip_address) > 0;
}

static void collect_top_k_callback(
    const char *ip_address,
    size_t failed_attempts,
    void *context
){

    IpMinHeap *heap = context;

    IpRankEntry candidate = {
        .ip_address = ip_address,
        .failed_attempts = failed_attempts
    };

    if (heap->size < heap->capacity){
        ip_heap_push(heap, candidate);
    } else {
        if (is_worse_rank(&heap->nodes[0], &candidate)){
            ip_heap_replace_min(heap, candidate);
        }
    }

}

static bool swap_entries(IpRankEntry *a, IpRankEntry *b) {

    if (a == NULL || b == NULL) {
        return false;
    }

    IpRankEntry temp = *a;
    *a = *b;
    *b = temp;

    return true;
}

static void shift_up(IpMinHeap *heap, size_t idx) {
    size_t parent = 0;

    if (heap == NULL) {
        return;
    }

    while (idx > 0) {
        parent = (idx - 1) / 2;

        if (is_worse_rank(&heap->nodes[idx], &heap->nodes[parent])) {
            if (!swap_entries(&heap->nodes[idx], &heap->nodes[parent])) {
                return;
            }
            idx = parent;
        } else {
            break;
        }
    }
}

static void sift_down(IpMinHeap *heap, size_t idx) {

    if (heap == NULL) {
        return;
    }

    while (true) {

        size_t left = 2 * idx + 1;
        size_t right = 2 * idx + 2;

        size_t worst = idx;

        if (left < heap->size && is_worse_rank(&heap->nodes[left], &heap->nodes[worst])) {
            worst = left;
        }
        if (right < heap->size && is_worse_rank(&heap->nodes[right], &heap->nodes[worst])) {
            worst = right;
        }

        if (worst == idx) {
            break;
        }

        swap_entries(&heap->nodes[idx], &heap->nodes[worst]);
        idx = worst;
    }
}

IpMinHeap *ip_heap_create(size_t capacity) {

    if (capacity == 0 || capacity > SIZE_MAX / sizeof(IpRankEntry)) {
        return NULL;
    }

    IpMinHeap *heap = malloc(sizeof(*heap));

    if (heap == NULL) {
        fprintf(stderr, "Failed to allocate memory for heap!\n");
        return NULL;
    }

    heap->nodes = calloc(capacity, sizeof(IpRankEntry));

    if (heap->nodes == NULL) {
        fprintf(stderr, "Failed to allocate memory for nodes!\n");
        free(heap);
        return NULL;
    }

    heap->capacity = capacity;
    heap->size = 0;

    return heap;
}

size_t ip_heap_size(const IpMinHeap *heap) {

    if (heap == NULL) {
        return 0;
    }

    return heap->size;
}

size_t ip_heap_capacity(const IpMinHeap *heap) {

    if (heap == NULL) {
        return 0;
    }

    return heap->capacity;
}

bool ip_heap_push(IpMinHeap *heap, IpRankEntry entry) {

    if (heap == NULL || entry.ip_address == NULL || heap->size >= heap->capacity) {
        return false;
    }

    heap->nodes[heap->size++] = entry;
    shift_up(heap, heap->size - 1);

    return true;
}

bool ip_heap_peek_min(const IpMinHeap *heap, IpRankEntry *out) {

    if (heap == NULL || out == NULL || heap->size == 0) {
        return false;
    }

    *out = heap->nodes[0];

    return true;
}

bool ip_heap_pop_min(IpMinHeap *heap, IpRankEntry *out) {

    if (heap == NULL || out == NULL || heap->size == 0) {
        return false;
    }

    *out = heap->nodes[0];

    heap->nodes[0] = heap->nodes[heap->size - 1];
    heap->size--;

    if (heap->size > 0) {
        sift_down(heap, 0);
    }

    return true;
}

bool ip_heap_replace_min(IpMinHeap *heap, IpRankEntry entry) {

    if (heap == NULL || entry.ip_address == NULL || heap->size == 0) {
        return false;
    }

    heap->nodes[0] = entry;
    sift_down(heap, 0);

    return true;
}

bool ip_heap_top_k_from_table(
    const IpTable *table,
    size_t k,
    IpRankEntry *out_entries,
    size_t *out_count
){

    if (table == NULL || out_count == NULL){
        return false;
    }

    size_t table_size = ip_table_size(table);

    if (k == 0 || table_size == 0){
        *out_count = 0;
        return true;
    }

    if (out_entries == NULL){
        return false;
    }

    size_t effective_k = (k < table_size) ? k : table_size;

    IpMinHeap *heap = ip_heap_create(effective_k);

    if (heap == NULL){
        fprintf(stderr, "Failed to allocate memory for heap!\n");
        return false;
    }

    ip_table_foreach(
        table,
        collect_top_k_callback,
        heap
    );

    size_t count = ip_heap_size(heap);

    for (size_t i = count; i > 0; i--){
        ip_heap_pop_min(heap, &out_entries[i - 1]);
    }

    *out_count = count;
    ip_heap_destroy(heap);

    return true;
}

void ip_heap_destroy(IpMinHeap *heap) {

    if (heap == NULL) {
        return;
    }

    free(heap->nodes);
    heap->capacity = 0;
    heap->size = 0;
    free(heap);
}