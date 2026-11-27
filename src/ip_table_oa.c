#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ip_table_oa.h"

typedef enum { SLOT_EMPTY = 0, SLOT_OCCUPIED, SLOT_DELETED } SlotState;

typedef struct {
    SlotState state;
    char *ip_address;
    size_t failed_attempts;
    size_t psl;
} IpSlot;

struct IpTableOA {
    IpSlot *slots;
    size_t capacity;
    size_t count;
    size_t tombstone_count;
};

static size_t next_power_of_two(size_t min_capacity) {

    size_t cap = 2;

    while (cap < min_capacity) {

        if (cap > (SIZE_MAX / 2)) {
            fprintf(stderr, "Number too big!!\n");
            return 0;
        }

        cap *= 2;
    }

    return cap;
}

static size_t hash_ip(const char *ip_address) {

    unsigned long hash = 5381;
    unsigned int c;

    while ((c = (unsigned char)*ip_address++) != 0) {
        hash = ((hash << 5) + hash) + (size_t)c;
    }

    uint64_t h = (uint64_t)hash;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;

    return (size_t)h;
}

static bool insert_slot_robin_hood(IpSlot *slots, size_t capacity, IpSlot incoming) {

    size_t idx = hash_ip(incoming.ip_address) & (capacity - 1);

    incoming.psl = 0;

    while (true) {

        if (slots[idx].state == SLOT_EMPTY) {
            slots[idx] = incoming;

            return false;
        }

        if (slots[idx].state == SLOT_DELETED) {
            slots[idx] = incoming;

            return true;
        }

        if (incoming.psl > slots[idx].psl) {
            IpSlot tmp;
            tmp = slots[idx];
            slots[idx] = incoming;
            incoming = tmp;
        }

        idx = (idx + 1) & (capacity - 1);
        incoming.psl++;
    }
}

static bool ip_table_oa_resize(IpTableOA *table) {

    if (table->capacity > (SIZE_MAX / 2)) {
        return false;
    }

    size_t new_capacity = table->capacity * 2;

    IpSlot *new_slots = calloc(new_capacity, sizeof(*new_slots));

    if (new_slots == NULL) {
        fprintf(stderr, "Failed to allocate for slots in resizing!\n");
        return false;
    }

    for (size_t i = 0; i < table->capacity; i++) {
        if (table->slots[i].state == SLOT_OCCUPIED) {
            insert_slot_robin_hood(new_slots, new_capacity, table->slots[i]);
        }
    }

    free(table->slots);
    table->slots = new_slots;
    table->capacity = new_capacity;
    table->tombstone_count = 0;

    return true;
}

IpTableOA *ip_table_oa_create(size_t initial_capacity) {

    if (initial_capacity == 0) {
        return NULL;
    }

    size_t capacity = next_power_of_two(initial_capacity);

    if (capacity == 0) {
        return NULL;
    }

    IpTableOA *table = malloc(sizeof(*table));

    if (table == NULL) {
        fprintf(stderr, "Failed to allocate memory for new table!\n");
        return NULL;
    }

    table->slots = calloc(capacity, sizeof(IpSlot));

    if (table->slots == NULL) {
        free(table);
        fprintf(stderr, "Failed to allocate memory for slots!\n");
        return NULL;
    }

    table->capacity = capacity;
    table->count = 0;
    table->tombstone_count = 0;

    return table;
}

bool ip_table_oa_insert(IpTableOA *table, const char *ip_address) {

    if (table == NULL || ip_address == NULL || ip_address[0] == '\0') {
        return false;
    }

    if ((table->count + table->tombstone_count + 1) * 10 >= table->capacity * 7) {
        if (!ip_table_oa_resize(table)) {
            fprintf(stderr, "Failed to resize table!\n");
            return false;
        }
    }

    size_t idx = hash_ip(ip_address) & (table->capacity - 1);
    size_t psl = 0;

    while (true) {

        if (table->slots[idx].state == SLOT_EMPTY) {
            break;
        }

        if (table->slots[idx].state == SLOT_OCCUPIED) {
            if (strcmp(table->slots[idx].ip_address, ip_address) == 0) {
                table->slots[idx].failed_attempts++;

                return true;
            }

            if (psl > table->slots[idx].psl) {
                break;
            }
        }

        idx = (idx + 1) & (table->capacity - 1);
        psl++;
    }

    char *copy = malloc(strlen(ip_address) + 1);

    if (copy == NULL) {
        fprintf(stderr, "Failed to allocate memory for ip_address!\n");
        return false;
    }

    strcpy(copy, ip_address);

    IpSlot incoming = {.state = SLOT_OCCUPIED, .ip_address = copy, .failed_attempts = 1, .psl = 0};

    if (insert_slot_robin_hood(table->slots, table->capacity, incoming)) {
        table->tombstone_count--;
    }

    table->count++;

    return true;
}

bool ip_table_oa_remove(IpTableOA *table, const char *ip_address) {

    if (table == NULL || ip_address == NULL || ip_address[0] == '\0') {
        return false;
    }

    size_t idx = hash_ip(ip_address) & (table->capacity - 1);
    size_t psl = 0;

    while (true) {

        if (table->slots[idx].state == SLOT_EMPTY) {
            return false;
        } else if (table->slots[idx].state == SLOT_OCCUPIED) {
            if (strcmp(table->slots[idx].ip_address, ip_address) == 0) {

                free(table->slots[idx].ip_address);
                table->slots[idx].ip_address = NULL;
                table->slots[idx].failed_attempts = 0;
                table->slots[idx].state = SLOT_DELETED;
                table->slots[idx].psl = 0;
                table->count--;
                table->tombstone_count++;

                return true;
            }

            if (psl > table->slots[idx].psl) {
                return false;
            }
        }

        idx = (idx + 1) & (table->capacity - 1);
        psl++;
    }
}

size_t ip_table_oa_get_count(const IpTableOA *table, const char *ip_address) {

    if (table == NULL || ip_address == NULL || ip_address[0] == '\0') {
        return 0;
    }

    size_t index = hash_ip(ip_address) & (table->capacity - 1);
    size_t psl = 0;

    while (true) {

        if (table->slots[index].state == SLOT_EMPTY) {
            return 0;
        } else if (table->slots[index].state == SLOT_OCCUPIED) {
            if (strcmp(table->slots[index].ip_address, ip_address) == 0) {
                return table->slots[index].failed_attempts;
            }

            if (psl > table->slots[index].psl) {
                return 0;
            }
        }

        index = (index + 1) & (table->capacity - 1);
        psl++;
    }
}

size_t ip_table_oa_size(const IpTableOA *table) {
    if (table == NULL) {
        return 0;
    }

    return table->count;
}

size_t ip_table_oa_capacity(const IpTableOA *table) {

    if (table == NULL) {
        return 0;
    }

    return table->capacity;
}

void ip_table_oa_foreach(const IpTableOA *table, IpOACallback callback, void *context) {

    if (table == NULL || callback == NULL) {
        return;
    }

    for (size_t i = 0; i < table->capacity; i++) {

        if (table->slots[i].state == SLOT_OCCUPIED) {
            callback(table->slots[i].ip_address, table->slots[i].failed_attempts, context);
        }
    }
}

void ip_table_oa_destroy(IpTableOA *table) {

    if (table == NULL) {
        return;
    }

    for (size_t i = 0; i < table->capacity; i++) {
        free(table->slots[i].ip_address);
    }

    free(table->slots);

    table->slots = NULL;
    table->count = 0;
    table->capacity = 0;
    table->tombstone_count = 0;
    free(table);
}

size_t ip_table_oa_max_psl(IpTableOA *table) {

    if (table == NULL) {
        return 0;
    }

    size_t max_psl = 0;

    for (size_t i = 0; i < table->capacity; i++) {
        if (table->slots[i].state == SLOT_OCCUPIED) {
            if (table->slots[i].psl > max_psl) {
                max_psl = table->slots[i].psl;
            }
        }
    }

    return max_psl;
}
