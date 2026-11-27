#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "ip_heap.h"
#include "ip_table.h"

#define ROUNDS 20
#define NUM_IPS 100000

typedef struct {
    IpRankEntry *entries;
    size_t count;
    size_t capacity;
} RankCollector;

static double now_ms(void){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void collect_rank_callback(
    const char *ip_address, size_t failed_attempts, void *context
){

    RankCollector *collector = context;

    if (collector->count < collector->capacity){
        collector->entries[collector->count].ip_address = ip_address;
        collector->entries[collector->count].failed_attempts = failed_attempts;
        collector->count++;
    }
}

static int compare_rank_desc(const void *a, const void *b){

    const IpRankEntry *first = a;
    const IpRankEntry *second = b;

    if (first->failed_attempts > second->failed_attempts){
        return -1;
    }
    if(first->failed_attempts < second->failed_attempts){
        return 1;
    }

    return strcmp(first->ip_address, second->ip_address);
}

static bool top_k_via_qsort(
    const IpTable *table, size_t n_expected, size_t k,
    IpRankEntry *out, size_t *out_count
){

    if (table == NULL || out_count == NULL){
        return false;
    }

    if (k == 0 || n_expected == 0){
        *out_count = 0;
        return true;
    }

    if (out == NULL){
        return false;
    }

    IpRankEntry *all = malloc(n_expected * sizeof(*all));

    if (all == NULL){
        fprintf(stderr, "Failed to allocate memory for collected data!\n");
        return false;
    }

    RankCollector collector = {
        .entries = all,
        .count = 0,
        .capacity = n_expected
    };

    ip_table_foreach(
        table,
        collect_rank_callback,
        &collector
    );

    qsort(collector.entries, collector.count, sizeof(*collector.entries), compare_rank_desc);

    size_t to_copy = (k < collector.count) ? k : collector.count;
    if (to_copy){
        memcpy(out, collector.entries, to_copy * sizeof(*out));
    }
    *out_count = to_copy;

    free(all);
    return true;
}

int main(void){

    IpTable *table = ip_table_create(8);
    if (table == NULL){
        fprintf(stderr, "Failed to create table!\n");
        return EXIT_FAILURE;
    }

    srand(42);
    for (size_t i = 0; i < NUM_IPS; i++){
        unsigned int b = (i >> 16) & 0xFF;
        unsigned int c = (i >> 8) & 0xFF;
        unsigned int d = i & 0xFF;

        char ip[16];
        snprintf(ip, sizeof(ip), "10.%u.%u.%u", b, c, d);

        int repeats = (rand() % 20) + 1;

        for (int r = 0; r < repeats; r++){
            if (!ip_table_insert(
                table,
                ip
            )){
                fprintf(stderr, "Failed to insert ip in table!\n");
                ip_table_destroy(table);
                return EXIT_FAILURE;
            }
        }
    }

    const size_t ks[] = {10, 100, 10000};
    const size_t num_ks = sizeof(ks) / sizeof(ks[0]);

    printf("%-10s %16s %16s\n", "Top (K)", "Heap (ms)", "Qsort (ms)");

    for (size_t idx = 0; idx < num_ks; idx++){

        size_t k = ks[idx];

        IpRankEntry *heap_out = malloc(k * sizeof(*heap_out));
        IpRankEntry *qsort_out = malloc(k * sizeof(*qsort_out));

        if (!heap_out || !qsort_out){
            fprintf(stderr, "Failed to allocate memory for output buffers!\n");
            free(heap_out);
            free(qsort_out);
            ip_table_destroy(table);
            return EXIT_FAILURE;
        }

        size_t heap_count = 0;
        double t0 = now_ms();
        for (int r = 0; r < ROUNDS; r++){
            if(!ip_heap_top_k_from_table(
                table,
                k,
                heap_out,
                &heap_count
            )){
                fprintf(stderr, "Failed to extract top k from heap!\n");
                free(heap_out);
                free(qsort_out);
                ip_table_destroy(table);
                return EXIT_FAILURE;
            }
        }
        double heap_ms = now_ms() - t0;

        size_t qsort_count = 0;
        t0 = now_ms();
        for (int r = 0; r < ROUNDS; r++){
            if (!top_k_via_qsort(
                table,
                NUM_IPS,
                k,
                qsort_out,
                &qsort_count
            )){
                fprintf(stderr, "ERROR! Failed to get top k via qsort!\n");
                free(heap_out);
                free(qsort_out);
                ip_table_destroy(table);
                return EXIT_FAILURE;
            }
        }
        double qsort_ms = now_ms() - t0;

        if (heap_count != qsort_count){
            fprintf(stderr, "ERROR! Heap count and qsort count different!\n");
            free(heap_out);
            free(qsort_out);
            ip_table_destroy(table);
            return EXIT_FAILURE;
        }
        for (size_t i = 0; i < heap_count; i++){
            if (strcmp(heap_out[i].ip_address, qsort_out[i].ip_address) != 0){
                fprintf(stderr, "ERROR! Missmatch between IPs!!\n");
                free(heap_out);
                free(qsort_out);
                ip_table_destroy(table);
                return EXIT_FAILURE;
            }
            if (heap_out[i].failed_attempts != qsort_out[i].failed_attempts){
                fprintf(stderr, "ERROR! Heap and Qsort show different count of failed attempts!\n");
                free(heap_out);
                free(qsort_out);
                ip_table_destroy(table);
                return EXIT_FAILURE;
            }
        }

        printf("%-10zu %16.3f %16.3f\n", k, heap_ms, qsort_ms);

        free(heap_out);
        free(qsort_out);
    }

    ip_table_destroy(table);
    return EXIT_SUCCESS;
}