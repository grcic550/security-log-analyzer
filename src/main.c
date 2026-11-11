#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "detector.h"
#include "entries.h"
#include "ip_table.h"
#include <cli_utils.h>
#define MAX_LENGTH_LINE 256

int main(int argc, char *argv[]) {

    const char *log_path = "examples/sample.log";
    size_t threshold = 3;
    double window_seconds = 60.0;

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
                fprintf(stderr, "Missing threshold value!\n");
                return EXIT_FAILURE;
            }

            if (!parse_positive_size(argv[++i], &threshold)) {
                fprintf(stderr, "Invalid threshold!\n");
                return EXIT_FAILURE;
            }
        } else if (strcmp(argv[i], "--window") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing window value!\n");
                return EXIT_FAILURE;
            }

            if (!parse_positive_double(argv[++i], &window_seconds)) {
                fprintf(stderr, "Invalid window!\n");
                return EXIT_FAILURE;
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
    printf("Successful logins: %10zu\n", count_logs_by_event(AUTH_SUCCESS));
    printf("Failed logins:     %10zu\n", count_logs_by_event(AUTH_FAILURE));

    printf("\n");
    ip_table_print_report(table);

    size_t suspicious_count = detector_print_alerts(table, threshold);

    printf("\nTotal suspicious IP addresses: %zu\n", suspicious_count);

    printf("\n========== TIME-WINDOW SECURITY ALERTS ==========\n");

    size_t window_alerts = detector_analyze_windows(threshold, window_seconds);

    printf("\nIP addresses with suspicious bursts: %zu\n", window_alerts);
    log_management_destroy();
    ip_table_destroy(table);
    return 0;
}