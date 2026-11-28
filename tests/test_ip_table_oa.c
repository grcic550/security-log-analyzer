#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ip_table_oa.h"

typedef struct {
    size_t visited;
    size_t sum_failed_attempts;
} OATestContext;

static void test_open_addressing_table(void) {

    assert(ip_table_oa_create(0) == NULL);

    IpTableOA *table = ip_table_oa_create(10);
    assert(table != NULL);

    assert(ip_table_oa_capacity(table) == 16);

    IpTableOA *table_2 = ip_table_oa_create(8);
    assert(table_2 != NULL);

    assert(ip_table_oa_capacity(table_2) == 8);

    assert(ip_table_oa_insert(table, "192.168.1.20"));

    assert(ip_table_oa_get_count(table, "192.168.1.20") == 1);
    assert(ip_table_oa_size(table) == 1);

    assert(ip_table_oa_insert(table, "192.168.1.30"));
    assert(ip_table_oa_get_count(table, "192.168.1.30") == 1);
    assert(ip_table_oa_size(table) == 2);

    assert(ip_table_oa_insert(table, "192.168.1.20"));
    assert(ip_table_oa_get_count(table, "192.168.1.20") == 2);
    assert(ip_table_oa_size(table) == 2);

    assert(ip_table_oa_get_count(table, "192.168.2.20") == 0);

    for (size_t i = 1; i <= 6; i++) {
        char ip[16];

        snprintf(ip, sizeof(ip), "192.168.1.%zu", i);
        assert(ip_table_oa_insert(table_2, ip));
    }

    assert(ip_table_oa_size(table_2) == 6);

    assert(!ip_table_oa_insert(NULL, "192.168.1.20"));
    assert(!ip_table_oa_insert(table, NULL));
    assert(ip_table_oa_get_count(NULL, "192.168.1.20") == 0);

    ip_table_oa_destroy(table);
    ip_table_oa_destroy(table_2);
}

static void test_oa_resizing(void) {

    IpTableOA *table = ip_table_oa_create(2);
    assert(table != NULL);

    for (size_t i = 1; i <= 100; i++) {
        char ip[16];

        snprintf(ip, sizeof(ip), "192.168.1.%zu", i);
        assert(ip_table_oa_insert(table, ip));
    }

    for (size_t i = 1; i <= 10; i++) {
        char ip[16];

        snprintf(ip, sizeof(ip), "192.168.1.%zu", i);
        assert(ip_table_oa_insert(table, ip));
    }

    size_t cap = ip_table_oa_capacity(table);
    assert(ip_table_oa_capacity(table) >= 128);
    assert((cap & (cap - 1)) == 0);
    assert(ip_table_oa_size(table) == 100);

    for (size_t i = 1; i <= 10; i++) {
        char ip[16];

        snprintf(ip, sizeof(ip), "192.168.1.%zu", i);
        assert(ip_table_oa_get_count(table, ip) == 2);
    }

    for (size_t i = 11; i <= 100; i++) {
        char ip[16];

        snprintf(ip, sizeof(ip), "192.168.1.%zu", i);
        assert(ip_table_oa_get_count(table, ip) == 1);
    }

    ip_table_oa_destroy(table);
}

static void test_oa_deletion(void) {

    IpTableOA *table = ip_table_oa_create(8);
    assert(table != NULL);

    for (size_t i = 1; i <= 6; i++) {
        char ip[16];

        snprintf(ip, sizeof(ip), "192.168.1.%zu", i);
        assert(ip_table_oa_insert(table, ip));
    }

    assert(ip_table_oa_size(table) == 6);

    assert(ip_table_oa_remove(table, "192.168.1.5"));
    assert(ip_table_oa_remove(table, "192.168.1.6"));

    assert(ip_table_oa_size(table) == 4);

    for (size_t i = 1; i <= 4; i++) {
        char ip[16];

        snprintf(ip, sizeof(ip), "192.168.1.%zu", i);
        assert(ip_table_oa_get_count(table, ip) == 1);
    }

    assert(ip_table_oa_insert(table, "192.168.1.4"));

    assert(ip_table_oa_get_count(table, "192.168.1.4") == 2);
    assert(ip_table_oa_size(table) == 4);

    assert(!ip_table_oa_remove(table, "192.168.1.30"));

    ip_table_oa_destroy(table);
}

static void test_oa_robin_hood(void) {

    IpTableOA *table = ip_table_oa_create(8);
    assert(table != NULL);

    for (size_t i = 1; i <= 4; i++) {
        for (size_t j = 1; j <= 255; j++) {
            char ip[16];

            snprintf(ip, sizeof(ip), "192.168.%zu.%zu", i, j);
            assert(ip_table_oa_insert(table, ip));
        }
    }

    for (size_t i = 1; i <= 4; i++) {
        for (size_t j = 1; j <= 255; j++) {
            char ip[16];

            snprintf(ip, sizeof(ip), "192.168.%zu.%zu", i, j);
            assert(ip_table_oa_get_count(table, ip) == 1);
        }
    }

    assert(ip_table_oa_max_psl(table) < 20);
    assert(ip_table_oa_size(table) == 1020);

    printf("Max psl: %zu\n", ip_table_oa_max_psl(table));

    ip_table_oa_destroy(table);
}

static void test_oa_no_bloat_on_churn(void){

    IpTableOA *table = ip_table_oa_create(8);
    assert(table != NULL);

    for (size_t i = 0; i < 200; i++){
        assert(ip_table_oa_insert(
            table,
            "10.0.0.1" 
        ));
        assert(ip_table_oa_remove(
            table,
            "10.0.0.1"
        ));
    }

    assert(ip_table_oa_size(table) == 0);
    assert(ip_table_oa_capacity(table) == 8);

    ip_table_oa_destroy(table);
}

static void test_oa_update_does_not_resize(void){

    IpTableOA *table = ip_table_oa_create(8);
    assert(table != NULL);

    assert(ip_table_oa_insert(
        table,
        "10.0.0.1"
    ));
    assert(ip_table_oa_insert(
        table,
        "10.0.0.2"
    ));
    assert(ip_table_oa_insert(
        table,
        "10.0.0.3"
    ));
    assert(ip_table_oa_insert(
        table,
        "10.0.0.4"
    ));
    assert(ip_table_oa_insert(
        table,
        "10.0.0.5"
    ));

    assert(ip_table_oa_capacity(table) == 8);

    for (size_t i = 0; i < 20; i++){
        assert(ip_table_oa_insert(
        table,
        "10.0.0.1"
        ));
        assert(ip_table_oa_insert(
            table,
            "10.0.0.2"
        ));
        assert(ip_table_oa_insert(
            table,
            "10.0.0.3"
        ));
        assert(ip_table_oa_insert(
            table,
            "10.0.0.4"
        ));
        assert(ip_table_oa_insert(
            table,
            "10.0.0.5"
        ));
    }

    assert(ip_table_oa_capacity(table) == 8);
    assert(ip_table_oa_get_count(
        table, "10.0.0.1"
    ) == 21);

    ip_table_oa_destroy(table);
}

static void verify_visited(
    const char *ip_address,
    size_t failed_attempts,
    void *context
){

    OATestContext *test = context;

    (void)ip_address;

    test->visited++;
    test->sum_failed_attempts += failed_attempts;
}

static void test_table_oa_randomized_differential(void){

    char ip_strings[64][16] = {{0}};

    for (size_t i = 0; i < 64; i++){

        snprintf(ip_strings[i], sizeof(ip_strings[i]), "10.0.0.%zu", i);
    }

    size_t expected[64] = {0};
    size_t expected_live_count = 0;
    size_t sum_expected = 0;
    
    IpTableOA *table = ip_table_oa_create(4);
    assert(table != NULL);

    srand(12345);

    for (size_t i = 0; i < 5000; i++){
        size_t id = (size_t)(rand() % 64);

        if (rand() % 2 == 0){
            assert(ip_table_oa_insert(
                table,
                ip_strings[id]
            ));

            expected[id]++;
        } else {
            bool removed = ip_table_oa_remove(
                table,
                ip_strings[id]
            );

            assert(removed == (expected[id] > 0));
            expected[id] = 0;
        }

        if (i % 50 == 49){
            expected_live_count = 0;
            sum_expected = 0;

            for (size_t j = 0; j < 64; j++){
            
                assert(ip_table_oa_get_count(
                    table,
                    ip_strings[j]
                ) == expected[j]);
                
                if (expected[j] != 0){
                    expected_live_count++;
                }

                sum_expected += expected[j];
            }

            assert(ip_table_oa_size(table) == expected_live_count);
        }
    }

    OATestContext context = {0};

    ip_table_oa_foreach(
        table,
        verify_visited,
        &context
    );

    assert(context.visited == expected_live_count);
    assert(context.sum_failed_attempts == sum_expected);

    ip_table_oa_destroy(table);
}

int main(void) {

    test_open_addressing_table();
    test_oa_resizing();
    test_oa_deletion();
    test_oa_robin_hood();
    test_oa_no_bloat_on_churn();
    test_oa_update_does_not_resize();
    test_table_oa_randomized_differential();

    printf("All tests pass!!\n\n");

    return 0;
}