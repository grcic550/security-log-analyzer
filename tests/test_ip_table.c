#include <assert.h>
#include <stdio.h>

#include "ip_table.h"

static void test_creation(void){

    IpTable *table = ip_table_create(2);

    assert(table != NULL);

    assert(ip_table_create(0) == NULL);

    ip_table_destroy(table);
}

static void test_insertion(void){

    IpTable *table = ip_table_create(2);

    assert(table != NULL);

    assert(ip_table_get_count(table, "192.168.1.20") == 0);

    assert(ip_table_insert(table, "192.168.1.20"));

    assert(ip_table_get_count(table, "192.168.1.20") == 1);

    assert(ip_table_get_count(table, "192.168.1.40") == 0);

    ip_table_destroy(table);
}

static void test_duplicate_insertion(void){

    IpTable *table = ip_table_create(2);

    assert(table != NULL);

    assert(ip_table_insert(table, "192.168.1.20"));
    assert(ip_table_insert(table, "192.168.1.20"));
    assert(ip_table_insert(table, "192.168.1.20"));

    assert(ip_table_get_count(table, "192.168.1.20") == 3);

    ip_table_destroy(table);
}

static void test_collisions(void){

    IpTable *table = ip_table_create(2);

    assert(table != NULL);

    assert(ip_table_insert(table, "192.168.1.20"));
    assert(ip_table_insert(table, "192.168.1.40"));

    assert(ip_table_get_count(table, "192.168.1.20") == 1);
    assert(ip_table_get_count(table, "192.168.1.40") == 1);

    assert(ip_table_insert(table, "192.168.1.20"));

    assert(ip_table_get_count(table, "192.168.1.20") == 2);
    assert(ip_table_get_count(table, "192.168.1.40") == 1);

    ip_table_destroy(table);
}

static void test_resizing(void){
    IpTable *table = ip_table_create(2);

    assert(table != NULL);

    assert(ip_table_get_count(table, "192.168.1.20") == 0);

    assert(ip_table_insert(table, "192.168.1.20"));

    assert(ip_table_get_count(table, "192.168.1.20") == 1);

    assert(ip_table_insert(table, "192.168.1.20"));

    assert(ip_table_insert(table, "192.168.1.20"));

    assert(ip_table_get_count(table, "192.168.1.20") == 3);

    assert(ip_table_insert(table, "192.168.1.50"));

    assert(ip_table_get_count(table, "192.168.1.20") == 3);

    assert(ip_table_insert(table, "192.168.1.70"));

    assert(ip_table_get_count(table, "192.168.1.20") == 3);
    assert(ip_table_get_count(table, "192.168.1.50") == 1);
    assert(ip_table_get_count(table, "192.168.1.70") == 1);

    ip_table_destroy(table);
}

int main(void){

    test_collisions();
    test_resizing();
    test_creation();
    test_duplicate_insertion();
    test_insertion();

    printf("All tests passed!\n");

    return 0;
}

