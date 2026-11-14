#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <sys/types.h>

#include "detector.h"
#include "entries.h"
#include "ip_table.h"
#include "cli_utils.h"

static bool format_timestamp(
    time_t timestamp,
    char *buffer,
    size_t buffer_size
){
    struct tm *time_info = localtime(&timestamp);

    if (time_info == NULL){
        return false;
    }

    return strftime(
        buffer,
        buffer_size,
        "%Y-%m-%d %H:%M:%S",
        time_info
    ) != 0;
}

static void print_account_targeting_alert(
    const AccountTargetingAlert *alert,
    void *context
){
    (void)context;

    char start[64];
    char end[64];

    if (!format_timestamp(alert->window_start, start, sizeof(start)) ||
        !format_timestamp(alert->window_end, end, sizeof(end))){

            fprintf(stderr, "Failed to format alert timestamp!\n");
            return;
        }

    printf("\n[ACCOUNT TARGETING]\n");
    printf("IP Address: %-21s\n", alert->ip_address);
    printf("Failed attempts: %-21zu\n", alert->failed_attempts);
    printf("Distinct usernames: %-21zu\n", alert->distinct_usernames);
    printf("Window start: %-21s\n", start);
    printf("Window end: %-21s\n", end);
}

int main(int argc, char *argv[]) {

    const char *log_path = "examples/sample.log";
    size_t threshold = 3;
    double window_seconds = 60.0;
    int year = 2026;

    DetectorMode mode = DETECTOR_ALL;
    LogFormat format = LOG_FORMAT_SIMPLE;

    bool file_provided = false;
    bool format_provided = false;
    bool year_provided = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "'%s' without value!\n", argv[i]);
                return EXIT_FAILURE;
            } else {
                log_path = argv[++i];
                file_provided = true;
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
        } else if (strcmp(argv[i], "--detector") == 0){

            const char *selected = argv[++i];

            if (selected == NULL){
                fprintf(stderr, "Error!! Argument --detector empty!!!\n");
                return EXIT_FAILURE;
            }

            if (strcmp(selected, "all") == 0){
                mode = DETECTOR_ALL;
            } else if(strcmp(selected, "burst") == 0){
                mode = DETECTOR_BURST;
            } else if (strcmp(selected, "count") == 0){
                mode = DETECTOR_COUNT;
            } else if (strcmp(selected, "account-targeting") == 0) {
                mode = DETECTOR_ACCOUNT_TARGETING;
            } else {
                fprintf(stderr, "Unknown detector: %s\n", selected);
                return EXIT_FAILURE;
            }
        } else if (strcmp(argv[i], "--format") == 0){
            const char *selected = argv[++i];

            if (selected == NULL){
                fprintf(stderr, "Error!! Argument --format empty!\n");
                return EXIT_FAILURE;
            }

            if (strcmp(selected, "simple") == 0){
                format = LOG_FORMAT_SIMPLE;
            } else if (strcmp(selected, "ssh") == 0){
                format = LOG_FORMAT_SSH;
            } else {
                fprintf(stderr, "Unknown format: %s\n", selected);
                return EXIT_FAILURE;
            }

            format_provided = true;
        } else if (strcmp(argv[i], "--year") == 0){

            const char *selected = argv[++i];
            size_t parsed_year;

            if (selected == NULL){
                fprintf(stderr, "Error!! Argument --year empty!!\n");
                return EXIT_FAILURE;
            }

            if (!parse_positive_size(selected, &parsed_year)){
                fprintf(stderr, "Failed to parse the year!\n");
                return EXIT_FAILURE;
            }

            if (parsed_year < 1900 || parsed_year > 2100){
                fprintf(stderr, "Parsed year is out of reasonable range!!\n");
                return EXIT_FAILURE;
            }

            year = (int)parsed_year;
            year_provided= true;
        }
        else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return EXIT_FAILURE;
        }
    }

    if (file_provided && !format_provided){
        fprintf(stderr, "Error: --format is required when --file is provided.\n");
        return EXIT_FAILURE;
    }

    if (format_provided && format == LOG_FORMAT_SSH && !year_provided){
        fprintf(stderr, "Error: --year is required for SSH logs.\n");
        return EXIT_FAILURE;
    }

    if (format == LOG_FORMAT_SIMPLE && year_provided){
        fprintf(stderr, "Error: --year is not required for simple logs.\n");
        return EXIT_FAILURE;
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

    size_t line_number = 0;
    char *line = NULL;
    size_t capacity = 0;
    ssize_t bytes_read;

    while ((bytes_read = getline(&line, &capacity, file)) != -1) {
        line_number++;

        if (format == LOG_FORMAT_SIMPLE){
            if (!parse_log_line(table, line)){
                fprintf(stderr, "Warning: Invalid simple log at line %zu\n", line_number);
            }
        } else {
            ParseStatus status = parse_ssh_log_line(table, line, year);

            if (status == PARSE_ERROR){
                fprintf(stderr, "Warning: Invalid SSH log at line %zu\n", line_number);
            }
        }
    }

    if (ferror(file)){
        fprintf(stderr, "Error while reading the file!\n");
        
        free(line);
        fclose(file);
        log_management_destroy();
        ip_table_destroy(table);

        return EXIT_FAILURE;
    }

    free(line);
    fclose(file);

    printf("\n");
    printf("========== LOG ANALYSIS ==========\n");
    printf("Total events:      %10zu\n", get_log_count());
    printf("Successful logins: %10zu\n", count_logs_by_event(AUTH_SUCCESS));
    printf("Failed logins:     %10zu\n", count_logs_by_event(AUTH_FAILURE));

    if (mode == DETECTOR_COUNT || mode == DETECTOR_ALL){

        printf("\n");
        ip_table_print_report(table);

        size_t suspicious_count = detector_print_alerts(table, threshold);

        printf("\nTotal suspicious IP addresses: %zu\n", suspicious_count);

    }

    if ( mode == DETECTOR_BURST || mode == DETECTOR_ALL){
        printf("\n========== TIME-WINDOW SECURITY ALERTS ==========\n");
        size_t window_alerts = detector_analyze_windows(threshold, window_seconds);
        printf("\nIP addresses with suspicious bursts: %zu\n", window_alerts);
    }

    if (mode == DETECTOR_ACCOUNT_TARGETING || mode == DETECTOR_ALL){
        size_t alerts_found = 0;
        printf("\n========== MULTI-ACCOUNT TARGETING ==========\n");

        if (!detector_find_account_targeting(
            threshold,
            window_seconds,
            print_account_targeting_alert,
            NULL,
            &alerts_found

        )){
            fprintf(stderr, "Failed to detect account targeting!\n");
            log_management_destroy();
            ip_table_destroy(table);
            return EXIT_FAILURE;
        }

        printf("\nTotal account-targeting alerts: %zu\n", alerts_found);
    }

    log_management_destroy();
    ip_table_destroy(table);
    return 0;
}