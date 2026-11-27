#include <assert.h>
#include <stdio.h>
#include <stdio.h>
#include <stddef.h>

#include "ip_table_oa.h"

static void test_open_addressing_table(void){

    assert(ip_table_oa_create(0) == NULL);

    IpTableOA *table = ip_table_oa_create(10);
    assert(table != NULL);

    assert(ip_table_oa_capacity(table) == 16);

    IpTableOA *table_2 = ip_table_oa_create(8);
    assert(table_2 != NULL);

    assert(ip_table_oa_capacity(table_2) == 8);

    assert(ip_table_oa_insert(
        table,
        "192.168.1.20"
    ));

    assert(ip_table_oa_get_count(table, "192.168.1.20") == 1);
    assert(ip_table_oa_size(table) == 1);

    assert(ip_table_oa_insert(table, "192.168.1.30"));
    assert(ip_table_oa_get_count(table, "192.168.1.30") == 1);
    assert(ip_table_oa_size(table) == 2);

    assert(ip_table_oa_insert(table, "192.168.1.20"));
    assert(ip_table_oa_get_count(table, "192.168.1.20") == 2);
    assert(ip_table_oa_size(table) == 2);

    assert(ip_table_oa_get_count(table, "192.168.2.20") == 0);

    for (size_t i = 1; i <= 6; i++){
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

static void test_oa_resizing(void){

    IpTableOA *table = ip_table_oa_create(2);
    assert(table != NULL);

    for (size_t i = 1; i <= 100; i++){
        char ip[16];

        snprintf(ip, sizeof(ip), "192.168.1.%zu", i);
        assert(ip_table_oa_insert(table, ip));
    }

    for (size_t i = 1; i <= 10; i++){
        char ip[16];

        snprintf(ip, sizeof(ip), "192.168.1.%zu", i);
        assert(ip_table_oa_insert(table, ip));
    }

    size_t cap = ip_table_oa_capacity(table);
    assert(ip_table_oa_capacity(table) >= 128);
    assert((cap & (cap - 1)) == 0);
    assert(ip_table_oa_size(table) == 100);

    for (size_t i = 1; i <= 10; i++){
        char ip[16];

        snprintf(ip, sizeof(ip), "192.168.1.%zu", i);
        assert(ip_table_oa_get_count(table, ip) == 2);
    }

    for (size_t i = 11; i <= 100; i++){
        char ip[16];

        snprintf(ip, sizeof(ip), "192.168.1.%zu", i);
        assert(ip_table_oa_get_count(table, ip) == 1);
    }

    ip_table_oa_destroy(table);

}

static void test_oa_deletion(void){

    IpTableOA *table = ip_table_oa_create(8);
    assert(table != NULL);

    for (size_t i = 1; i <= 6; i++){
        char ip[16];

        snprintf(ip, sizeof(ip), "192.168.1.%zu", i);
        assert(ip_table_oa_insert(table, ip));
    }

    assert(ip_table_oa_size(table) == 6);

    assert(ip_table_oa_remove(table, "192.168.1.5"));
    assert(ip_table_oa_remove(table, "192.168.1.6"));

    assert(ip_table_oa_size(table) == 4);

    for (size_t i = 1; i <= 4; i++){
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

static void test_oa_robin_hood(void){

    IpTableOA *table = ip_table_oa_create(8);
    assert(table != NULL);

    for (size_t i = 1; i <= 4; i++){
        for (size_t j = 1; j <= 255; j++){
            char ip[16];

            snprintf(ip, sizeof(ip), "192.168.%zu.%zu", i, j);
            assert(ip_table_oa_insert(table, ip));
        }
    }

    for (size_t i = 1; i <= 4; i++){
        for (size_t j = 1; j <= 255; j++){
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

int main(void){

    test_open_addressing_table();
    test_oa_resizing();
    test_oa_deletion();
    test_oa_robin_hood();
    
    printf("All tests pass!!\n\n");

    return 0;
}