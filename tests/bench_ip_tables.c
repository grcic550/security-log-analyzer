#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ip_table.h"
#include "ip_table_oa.h"

#define NUM_IPS 50000
#define IP_LEN 16
#define START_CAP 16
#define INSERT_PASS 2
#define LOOKUP_ROUND 10

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void shuffle_ips(char (*ips)[IP_LEN], size_t n) {

    if (n < 2) {
        return;
    }

    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)rand() % (i + 1);
        char tmp[IP_LEN];
        memcpy(tmp, ips[i], IP_LEN);
        memcpy(ips[i], ips[j], IP_LEN);
        memcpy(ips[j], tmp, IP_LEN);
    }
}

int main(void) {

    char(*existing_ips)[IP_LEN] = malloc(NUM_IPS * sizeof(*existing_ips));
    char(*missing_ips)[IP_LEN] = malloc(NUM_IPS * sizeof(*missing_ips));

    if (!existing_ips || !missing_ips) {
        fprintf(stderr, "Memory allocation failed\n");
        free(existing_ips);
        free(missing_ips);
        return 1;
    }

    size_t idx = 0;

    for (size_t i = 1; i <= 200; i++) {
        for (size_t j = 1; j <= 250; j++) {
            snprintf(existing_ips[idx], IP_LEN, "10.%zu.%zu.1", i, j);
            snprintf(missing_ips[idx], IP_LEN, "172.%zu.%zu.1", i, j);
            idx++;
        }
    }

    srand(42);
    shuffle_ips(existing_ips, NUM_IPS);
    shuffle_ips(missing_ips, NUM_IPS);

    IpTable *table_chained = ip_table_create(START_CAP);
    IpTableOA *table_oa = ip_table_oa_create(START_CAP);

    if (!table_chained || !table_oa) {
        fprintf(stderr, "Failed to create tables!\n");
        ip_table_destroy(table_chained);
        ip_table_oa_destroy(table_oa);
        free(existing_ips);
        free(missing_ips);
        return 1;
    }

    double t0 = now_ms();

    for (int pass = 0; pass < INSERT_PASS; pass++) {
        for (size_t k = 0; k < NUM_IPS; k++) {
            ip_table_insert(table_chained, existing_ips[k]);
        }
    }

    double chained_insert_ms = now_ms() - t0;

    t0 = now_ms();

    for (int pass = 0; pass < INSERT_PASS; pass++) {
        for (size_t k = 0; k < NUM_IPS; k++) {
            ip_table_oa_insert(table_oa, existing_ips[k]);
        }
    }

    double oa_insert_ms = now_ms() - t0;

    size_t chained_hit_sum = 0;
    t0 = now_ms();
    for (int r = 0; r < LOOKUP_ROUND; r++) {
        for (size_t k = 0; k < NUM_IPS; k++) {
            chained_hit_sum += ip_table_get_count(table_chained, existing_ips[k]);
        }
    }
    double chained_hit_ms = now_ms() - t0;

    size_t oa_hit_sum = 0;
    t0 = now_ms();
    for (int r = 0; r < LOOKUP_ROUND; r++) {
        for (size_t k = 0; k < NUM_IPS; k++) {
            oa_hit_sum += ip_table_oa_get_count(table_oa, existing_ips[k]);
        }
    }
    double oa_hit_ms = now_ms() - t0;

    size_t chained_miss_sum = 0;
    t0 = now_ms();
    for (int r = 0; r < LOOKUP_ROUND; r++) {
        for (size_t k = 0; k < NUM_IPS; k++) {
            chained_miss_sum += ip_table_get_count(table_chained, missing_ips[k]);
        }
    }
    double chained_miss_ms = now_ms() - t0;

    size_t oa_miss_sum = 0;
    t0 = now_ms();
    for (int r = 0; r < LOOKUP_ROUND; r++) {
        for (size_t k = 0; k < NUM_IPS; k++) {
            oa_miss_sum += ip_table_oa_get_count(table_oa, missing_ips[k]);
        }
    }
    double oa_miss_ms = now_ms() - t0;

    const size_t expected_hits = (size_t)LOOKUP_ROUND * NUM_IPS * INSERT_PASS;

    if (chained_hit_sum != oa_hit_sum || chained_hit_sum != expected_hits) {
        fprintf(stderr, "ERROR: Hit checksum mismatch (chained=%zu, oa=%zu, expected=%zu)\n",
                chained_hit_sum, oa_hit_sum, expected_hits);
    }

    if (chained_miss_sum != 0 || oa_miss_sum != 0) {
        fprintf(stderr, "ERROR: Miss checksum non-zero (chained=%llu, oa=%llu)\n",
                (unsigned long long)chained_miss_sum, (unsigned long long)oa_miss_sum);
    }

    printf("%-22s %12s %12s\n", "Workload", "IpTable (ms)", "IpTableOA (ms)");
    printf("------------------------------------------------\n");
    printf("%-22s %12.3f %12.3f\n", "Insert (100k)", chained_insert_ms, oa_insert_ms);
    printf("%-22s %12.3f %12.3f\n", "Hit Lookup (500k)", chained_hit_ms, oa_hit_ms);
    printf("%-22s %12.3f %12.3f\n", "Miss Lookup (500k)", chained_miss_ms, oa_miss_ms);
    printf("------------------------------------------------\n");
    printf("Hit checksum match:   %s (%llu)\n", (chained_hit_sum == oa_hit_sum) ? "YES" : "NO",
           (unsigned long long)chained_hit_sum);
    printf("Miss checksums == 0:  %s\n",
           (chained_miss_sum == 0 && oa_miss_sum == 0) ? "YES" : "NO");
    printf("IpTableOA max PSL:    %zu\n\n", ip_table_oa_max_psl(table_oa));

    ip_table_destroy(table_chained);
    ip_table_oa_destroy(table_oa);
    free(existing_ips);
    free(missing_ips);

    return 0;
}