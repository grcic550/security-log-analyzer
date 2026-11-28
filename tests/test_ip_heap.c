#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "ip_heap.h"

static void test_ip_heap(void) {

    IpMinHeap *heap = ip_heap_create(8);
    assert(heap != NULL);

    assert(ip_heap_create(0) == NULL);

    IpRankEntry entry = {0};

    assert(!ip_heap_peek_min(heap, &entry));
    assert(!ip_heap_pop_min(heap, &entry));
    assert(!ip_heap_replace_min(heap, entry));

    IpRankEntry entry1 = {.ip_address = "10.0.0.1", .failed_attempts = 5};
    assert(ip_heap_push(heap, entry1));

    IpRankEntry entry2 = {.ip_address = "10.0.0.9", .failed_attempts = 5};
    assert(ip_heap_push(heap, entry2));

    IpRankEntry entry3 = {.ip_address = "10.0.0.2", .failed_attempts = 12};
    assert(ip_heap_push(heap, entry3));

    IpRankEntry entry4 = {.ip_address = "10.0.0.3", .failed_attempts = 1};
    assert(ip_heap_push(heap, entry4));

    IpRankEntry out1 = {0};
    assert(ip_heap_pop_min(heap, &out1));
    assert(strcmp(out1.ip_address, "10.0.0.3") == 0);
    assert(out1.failed_attempts == 1);

    IpRankEntry out2 = {0};
    assert(ip_heap_pop_min(heap, &out2));
    assert(strcmp(out2.ip_address, "10.0.0.9") == 0);
    assert(out2.failed_attempts == 5);

    IpRankEntry out3 = {0};
    assert(ip_heap_pop_min(heap, &out3));
    assert(strcmp(out3.ip_address, "10.0.0.1") == 0);
    assert(out3.failed_attempts == 5);

    IpRankEntry out4 = {0};
    assert(ip_heap_pop_min(heap, &out4));
    assert(strcmp(out4.ip_address, "10.0.0.2") == 0);
    assert(out4.failed_attempts == 12);

    IpMinHeap *heap2 = ip_heap_create(1);
    assert(heap2 != NULL);

    IpRankEntry heap2_entry = {.ip_address = "192.168.1.20", .failed_attempts = 20};

    assert(ip_heap_push(heap2, heap2_entry));

    IpRankEntry heap2_entry_2 = {.ip_address = "192.168.1.30", .failed_attempts = 50};

    assert(!ip_heap_push(heap2, heap2_entry_2));

    IpRankEntry bad_ip = {.ip_address = NULL, .failed_attempts = 10};

    assert(ip_heap_capacity(NULL) == 0);
    assert(ip_heap_size(NULL) == 0);
    assert(!ip_heap_peek_min(NULL, &out1));
    assert(!ip_heap_peek_min(heap, NULL));
    assert(!ip_heap_pop_min(NULL, &out1));
    assert(!ip_heap_pop_min(heap, NULL));
    assert(!ip_heap_push(NULL, out1));
    assert(!ip_heap_push(heap, bad_ip));
    assert(!ip_heap_replace_min(NULL, out1));
    assert(!ip_heap_replace_min(heap, bad_ip));

    IpMinHeap *heap3 = ip_heap_create(3);
    assert(heap3 != NULL);

    IpRankEntry heap3_entry1 = {
        .ip_address = "10.0.0.1",
        .failed_attempts = 5
    };

    IpRankEntry heap3_entry2 = {
        .ip_address = "10.0.0.2",
        .failed_attempts = 12
    };

    IpRankEntry heap3_entry3 = {
        .ip_address = "10.0.0.3",
        .failed_attempts = 8
    };

    assert(ip_heap_push(heap3, heap3_entry1));
    assert(ip_heap_push(heap3, heap3_entry2));
    assert(ip_heap_push(heap3, heap3_entry3));

    IpRankEntry heap3_entry4 = {
        .ip_address = "10.0.0.4",
        .failed_attempts = 20
    };

    assert(ip_heap_replace_min(heap3, heap3_entry4));

    IpRankEntry heap3_out1 = {0};
    IpRankEntry heap3_out2 = {0};
    IpRankEntry heap3_out3 = {0};

    assert(ip_heap_pop_min(heap3, &heap3_out1));
    assert(heap3_out1.failed_attempts == 8);

    assert(ip_heap_pop_min(heap3, &heap3_out2));
    assert(heap3_out2.failed_attempts == 12);

    assert(ip_heap_pop_min(heap3, &heap3_out3));
    assert(heap3_out3.failed_attempts == 20);

    ip_heap_destroy(heap);
    ip_heap_destroy(heap2);
    ip_heap_destroy(heap3);
}

static void insert_n(IpTable *table, const char *ip, size_t n){
    for (size_t i = 0; i < n; i++){
        assert(ip_table_insert(table, ip));
    }
}

static void test_top_k_from_table(void){

    IpTable *table = ip_table_create(8);
    assert(table != NULL);

    insert_n(table, "10.0.0.6", 1);
    insert_n(table, "10.0.0.5", 5);
    insert_n(table, "10.0.0.1", 8);
    insert_n(table, "10.0.0.4", 2);
    insert_n(table, "10.0.0.2", 5);
    insert_n(table, "10.0.0.3", 3);

    IpRankEntry out[3];
    size_t out_count = 999;

    assert(ip_heap_top_k_from_table(
        table,
        3,
        out,
        &out_count
    ));

    assert(out_count == 3);

    assert(strcmp(out[0].ip_address, "10.0.0.1") == 0 && out[0].failed_attempts == 8);
    assert(strcmp(out[1].ip_address, "10.0.0.2") == 0 && out[1].failed_attempts == 5);
    assert(strcmp(out[2].ip_address, "10.0.0.5") == 0 && out[2].failed_attempts == 5);

    ip_table_destroy(table);
}

static void test_top_k_larger_than_table(void){

    IpTable *table = ip_table_create(8);
    assert(table != NULL);

    insert_n(table, "10.0.0.1", 4);
    insert_n(table, "10.0.0.2", 1);
    insert_n(table, "10.0.0.3", 7);

    IpRankEntry out[10];
    size_t out_count = 999;

    assert(ip_heap_top_k_from_table(
        table,
        10,
        out,
        &out_count
    ));

    assert(out_count == 3);

    assert(strcmp(out[0].ip_address, "10.0.0.3") == 0 && out[0].failed_attempts == 7);
    assert(strcmp(out[1].ip_address, "10.0.0.1") == 0 && out[1].failed_attempts == 4);
    assert(strcmp(out[2].ip_address, "10.0.0.2") == 0 && out[2].failed_attempts == 1);

    ip_table_destroy(table);
}

static void test_top_k_empty_and_zero(void){

    IpTable *table = ip_table_create(8);
    assert(table != NULL);

    IpRankEntry out[5];
    size_t out_count = 999;

    assert(ip_heap_top_k_from_table(
        table,
        5,
        out,
        &out_count
    ));

    assert(out_count == 0);

    insert_n(table, "10.0.0.1", 3);
    out_count = 999;

    assert(ip_heap_top_k_from_table(
        table,
        0,
        out,
        &out_count
    ));

    assert(out_count == 0);

    ip_table_destroy(table);
}

static void test_edge_cases(void){

    assert(ip_heap_create(SIZE_MAX) == NULL);
    assert(ip_heap_create((SIZE_MAX / sizeof(IpRankEntry)) + 1) == NULL);

    IpTable *table = ip_table_create(3);
    assert(table != NULL);

    insert_n(table, "192.168.1.20", 3);
    insert_n(table, "192.168.1.30", 2);
    insert_n(table, "192.168.1.40", 7);

    IpRankEntry out[3];
    size_t count = 0;

    assert(ip_heap_top_k_from_table(
        table,
        SIZE_MAX,
        out,
        &count
    ));

    assert(count == 3);

    ip_table_destroy(table);
}

int main(void) {

    test_ip_heap();
    test_top_k_empty_and_zero();
    test_top_k_from_table();
    test_top_k_larger_than_table();
    test_edge_cases();

    printf("All tests pass!\n\n");

    return 0;
}