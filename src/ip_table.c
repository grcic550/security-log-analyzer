#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ip_table.h"

struct IpEntry {
    char *ip_address;
    size_t failed_attempts;
    struct IpEntry *next;
};

struct IpTable {
    IpEntry **buckets;
    size_t bucket_count;
    size_t entry_count;
};

typedef enum { ENTRY_ERROR, ENTRY_UPDATED, ENTRY_INSERTED } EntryResult;

static EntryResult add_entry(IpEntry **head, const char *ip_address);
static size_t hash_ip(const char *ip_address, size_t bucket_count);
static bool ip_table_resize(IpTable *table);

IpEntry *create_ip_entry(const char *ip_address) {

    IpEntry *new_entry = malloc(sizeof(*new_entry));

    if (new_entry == NULL) {
        fprintf(stderr, "Failed to allocate memory for new IpEntry");
        return NULL;
    }

    new_entry->ip_address = malloc(strlen(ip_address) + 1);

    if (new_entry->ip_address == NULL) {
        fprintf(stderr, "Failed to allocate memory for IP address");
        free(new_entry);
        return NULL;
    }

    strcpy(new_entry->ip_address, ip_address);
    new_entry->failed_attempts = 1;
    new_entry->next = NULL;

    return new_entry;
}

EntryResult add_entry(IpEntry **head, const char *ip_address) {

    IpEntry *temp = *head;

    while (temp != NULL) {
        if (strcmp(temp->ip_address, ip_address) == 0) {
            temp->failed_attempts++;
            return ENTRY_UPDATED;
        }
        temp = temp->next;
    }

    IpEntry *new_entry = create_ip_entry(ip_address);

    if (new_entry == NULL) {
        fprintf(stderr, "Failed to add entry because new_entry could not be created.");
        return ENTRY_ERROR;
    }
    new_entry->next = *head;
    *head = new_entry;

    return ENTRY_INSERTED;
}

bool ip_table_insert(IpTable *table, const char *ip_address) {

    size_t index = hash_ip(ip_address, table->bucket_count);

    EntryResult result = add_entry(&table->buckets[index], ip_address);

    if (result == ENTRY_ERROR) {
        fprintf(stderr, "Failed to add IP address to the bucket");
        return false;
    } else if (result == ENTRY_INSERTED) {
        table->entry_count++;

        double load = (double)table->entry_count / table->bucket_count;
        if (load >= 0.75) {
            if (!ip_table_resize(table)) {
                fprintf(stderr, "Warning: hash table resize failed\n");
            }
        }
    }
    return true;
}

static bool ip_table_resize(IpTable *table) {

    size_t new_bucket_count = 2 * table->bucket_count;

    IpEntry **new_buckets = calloc(new_bucket_count, sizeof(*new_buckets));

    if (new_buckets == NULL) {
        fprintf(stderr, "Failed to allocate memory while resizing table for new entries");
        return false;
    }

    for (size_t i = 0; i < table->bucket_count; i++) {

        IpEntry *current = table->buckets[i];

        while (current != NULL) {
            IpEntry *next = current->next;
            size_t new_index = hash_ip(current->ip_address, new_bucket_count);

            current->next = new_buckets[new_index];
            new_buckets[new_index] = current;

            current = next;
        }
    }

    free(table->buckets);
    table->buckets = new_buckets;
    table->bucket_count = new_bucket_count;

    return true;
}

IpTable *ip_table_create(size_t initial_bucket_count) {

    if (initial_bucket_count == 0) {
        return NULL;
    }

    IpTable *new_table = malloc(sizeof(*new_table));

    if (new_table == NULL) {
        fprintf(stderr, "Failed to allocate memory for new IP table");
        return NULL;
    }

    new_table->buckets = calloc(initial_bucket_count, sizeof(*new_table->buckets));

    if (new_table->buckets == NULL) {
        fprintf(stderr, "Failed to allocate memory for buckets in new IP table.");
        free(new_table);
        return NULL;
    }

    new_table->bucket_count = initial_bucket_count;
    new_table->entry_count = 0;

    return new_table;
}

static size_t hash_ip(const char *ip_address, size_t bucket_count) {

    unsigned long hash = 5381;
    int c;

    while ((c = (unsigned char)*ip_address++) != 0) {
        hash = ((hash << 5) + hash) + c;
    }

    return hash % bucket_count;
}

size_t ip_table_get_count(IpTable *table, const char *ip_address) {

    size_t index = hash_ip(ip_address, table->bucket_count);

    IpEntry *temp = table->buckets[index];

    while (temp != NULL) {
        if (strcmp(temp->ip_address, ip_address) == 0) {
            return temp->failed_attempts;
        }
        temp = temp->next;
    }

    return 0;
}

void ip_table_foreach(const IpTable *table, IpCallback callback, void *context) {

    if (table == NULL || callback == NULL) {
        return;
    }

    for (size_t i = 0; i < table->bucket_count; i++) {

        IpEntry *current = table->buckets[i];

        while (current != NULL) {
            callback(current->ip_address, current->failed_attempts, context);
            current = current->next;
        }
    }
}

void ip_table_print_report(IpTable *table) {

    printf("\n========== FAILED LOGINS BY IP ==========\n");

    for (size_t i = 0; i < table->bucket_count; i++) {

        IpEntry *temp = table->buckets[i];

        while (temp != NULL) {
            printf("%-20s %zu\n", temp->ip_address, temp->failed_attempts);

            temp = temp->next;
        }
    }
}

void free_entries(IpEntry *head) {
    IpEntry *temp;
    while (head != NULL) {
        temp = head;
        head = head->next;
        free(temp->ip_address);
        free(temp);
    }
}

void ip_table_destroy(IpTable *table) {

    if (table == NULL) {
        return;
    }

    for (size_t i = 0; i < table->bucket_count; i++) {
        free_entries(table->buckets[i]);
        table->buckets[i] = NULL;
    }
    free(table->buckets);
    table->buckets = NULL;
    table->bucket_count = 0;
    free(table);
}