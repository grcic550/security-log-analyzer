#include <stdio.h>

#include "entries.h"
#include "ip_table.h"
#define MAX_LENGTH_LINE 256

int main() {

    log_management_init();
    IpTable *table = ip_table_create(100);

    if (table == NULL) {
        fprintf(stderr, "Failed to create IP table\n");
        log_management_destroy();
        return 1;
    }

    FILE *file = fopen("examples/sample.log", "r");

    if (file == NULL) {
        perror("Error while opening file!");
        ip_table_destroy(table);
        return 1;
    }

    char line[MAX_LENGTH_LINE];

    while (fgets(line, sizeof(line), file) != NULL) {

        if (!parse_log_line(table, line)) {
            perror("Failed to parse this line!");
            continue;
        }
    }

    fclose(file);

    printf("\n\n");
    printf("========== LOG ANALYSIS ==========\n");
    printf("Total events:      %10zu\n", get_log_count());
    printf("Successful logins: %10zu\n", count_logs_by_event("LOGIN_SUCCESS"));
    printf("Failed logins:     %10zu\n", count_logs_by_event("LOGIN_FAILED"));

    printf("\n\n");
    printf("========== IP STATISTICS ==========\n");
    printf("192.168.1.20: %zu failed attempt(s)\n", ip_table_get_count(table, "192.168.1.20"));

    printf("192.168.1.40: %zu failed attempt(s)\n", ip_table_get_count(table, "192.168.1.40"));

    printf("192.268.1.10: %zu failed attempt(s)\n", ip_table_get_count(table, "192.168.1.10"));

    ip_table_print_report(table);

    log_management_destroy();
    ip_table_destroy(table);
    return 0;
}