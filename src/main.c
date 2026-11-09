#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "detector.h"
#include "entries.h"
#include "ip_table.h"
#define MAX_LENGTH_LINE 256

int main(int argc, char *argv[]) {

    const char *log_path = "examples/sample.log";
    size_t threshold = 3;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "'%s' without value!\n", argv[i]);
                return EXIT_FAILURE;
            } else {
                log_path = argv[++i];
            }
        } else if (strcmp(argv[i], "--threshold") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "'%s' without value!\n", argv[i]);
                return EXIT_FAILURE;
            } else {
                i++;

                if (argv[i][0] == '-') {
                    fprintf(stderr, "Threshold must be positive!\n");
                    return EXIT_FAILURE;
                }

                errno = 0;
                char *end;
                unsigned long number = strtoul(argv[i], &end, 10);

                if (errno == ERANGE) {
                    fprintf(stderr, "Number is out of range!\n");
                    return EXIT_FAILURE;
                }
                if (end == argv[i]) {
                    fprintf(stderr, "Error! No digits were converted.\n");
                    return EXIT_FAILURE;
                }
                if (*end != '\0') {
                    fprintf(stderr, "The input contains unconverted characters: %s\n", end);
                    return EXIT_FAILURE;
                }
                if (number == 0) {
                    fprintf(stderr, "Threshold mush be positive!\n");
                    return EXIT_FAILURE;
                }
                if (number > SIZE_MAX) {
                    fprintf(stderr, "Error: Value is too large for size_t\n");
                    return EXIT_FAILURE;
                }

                threshold = (size_t)number;
            }
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return EXIT_FAILURE;
        }
    }

    log_management_init();
    IpTable *table = ip_table_create(100);

    if (table == NULL) {
        fprintf(stderr, "Failed to create IP table\n");
        log_management_destroy();
        return 1;
    }

    FILE *file = fopen(log_path, "r");

    if (file == NULL) {
        fprintf(stderr, "Error while opening file!\n");
        log_management_destroy();
        ip_table_destroy(table);
        return 1;
    }

    char line[MAX_LENGTH_LINE];

    while (fgets(line, sizeof(line), file) != NULL) {

        if (!parse_log_line(table, line)) {
            fprintf(stderr, "Failed to parse this line!\n");
            continue;
        }
    }

    fclose(file);

    printf("\n");
    printf("========== LOG ANALYSIS ==========\n");
    printf("Total events:      %10zu\n", get_log_count());
    printf("Successful logins: %10zu\n", count_logs_by_event("LOGIN_SUCCESS"));
    printf("Failed logins:     %10zu\n", count_logs_by_event("LOGIN_FAILED"));

    printf("\\n");
    ip_table_print_report(table);

    size_t suspicious_count = detector_print_alerts(table, threshold);

    printf("\nTotal suspicious IP addresses: %zu\n\n", suspicious_count);

    log_management_destroy();
    ip_table_destroy(table);
    return 0;
}