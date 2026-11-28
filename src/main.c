#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <time.h>

#include "cli_utils.h"
#include "detector.h"
#include "entries.h"
#include "ip_table.h"
#include "ip_heap.h"

static const char *parse_issue_message(ParseIssue issue) {

    switch (issue) {
    case PARSE_ISSUE_NONE:
        return "No parsing issue";

    case PARSE_ISSUE_FIELD_COUNT:
        return "Invalid number of fields";

    case PARSE_ISSUE_FIELD_TOO_LONG:
        return "A field exceeds its maximum length";

    case PARSE_ISSUE_INVALID_IP:
        return "Invalid IP address!";

    case PARSE_ISSUE_INVALID_STATUS:
        return "Invalid status!";

    case PARSE_ISSUE_INVALID_TIMESTAMP:
        return "Invalid timestamp!";

    case PARSE_ISSUE_STORAGE_FAILURE:
        return "Storage failure!";

    case PARSE_ISSUE_MALFORMED_SSH:
        return "Malformed SSH line!";

    case PARSE_ISSUE_INVALID_PORT:
        return "Invalid port!";

    case PARSE_ISSUE_INVALID_PROCESS:
        return "Invalid process!";

    default:
        return "Unknown parsing error!";
    }
}

static bool format_timestamp(time_t timestamp, TimestampMode mode, char *buffer,
                             size_t buffer_size) {
    struct tm time_info;

    if (mode == TIMESTAMP_LOCAL) {
        if (!localtime_r(&timestamp, &time_info)) {
            return false;
        }
    } else if (mode == TIMESTAMP_UTC) {
        if (!gmtime_r(&timestamp, &time_info)) {
            return false;
        }
    } else {
        return false;
    }

    return strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", &time_info) != 0;
}

static void print_account_targeting_alert(const AccountTargetingAlert *alert, void *context) {

    if (context == NULL) {
        fprintf(stderr, "Missing timezone context!\n");
        return;
    }

    const TimestampMode *mode = context;
    char start[64];
    char end[64];

    if (!format_timestamp(alert->window_start, *mode, start, sizeof(start)) ||
        !format_timestamp(alert->window_end, *mode, end, sizeof(end))) {

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
    size_t top_k = 0;

    DetectorMode mode = DETECTOR_ALL;
    LogFormat format = LOG_FORMAT_SIMPLE;
    TimestampMode timezone_mode = TIMESTAMP_LOCAL;

    bool file_provided = false;
    bool format_provided = false;
    bool year_provided = false;
    bool top_provided = false;

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
        } else if (strcmp(argv[i], "--detector") == 0) {

            const char *selected = argv[++i];

            if (selected == NULL) {
                fprintf(stderr, "Error!! Argument --detector empty!!!\n");
                return EXIT_FAILURE;
            }

            if (strcmp(selected, "all") == 0) {
                mode = DETECTOR_ALL;
            } else if (strcmp(selected, "burst") == 0) {
                mode = DETECTOR_BURST;
            } else if (strcmp(selected, "count") == 0) {
                mode = DETECTOR_COUNT;
            } else if (strcmp(selected, "account-targeting") == 0) {
                mode = DETECTOR_ACCOUNT_TARGETING;
            } else {
                fprintf(stderr, "Unknown detector: %s\n", selected);
                return EXIT_FAILURE;
            }
        } else if (strcmp(argv[i], "--format") == 0) {
            const char *selected = argv[++i];

            if (selected == NULL) {
                fprintf(stderr, "Error!! Argument --format empty!\n");
                return EXIT_FAILURE;
            }

            if (strcmp(selected, "simple") == 0) {
                format = LOG_FORMAT_SIMPLE;
            } else if (strcmp(selected, "ssh") == 0) {
                format = LOG_FORMAT_SSH;
            } else {
                fprintf(stderr, "Unknown format: %s\n", selected);
                return EXIT_FAILURE;
            }

            format_provided = true;
        } else if (strcmp(argv[i], "--year") == 0) {

            const char *selected = argv[++i];
            size_t parsed_year;

            if (selected == NULL) {
                fprintf(stderr, "Error!! Argument --year empty!!\n");
                return EXIT_FAILURE;
            }

            if (!parse_positive_size(selected, &parsed_year)) {
                fprintf(stderr, "Failed to parse the year!\n");
                return EXIT_FAILURE;
            }

            if (parsed_year < 1900 || parsed_year > 2100) {
                fprintf(stderr, "Parsed year is out of reasonable range!!\n");
                return EXIT_FAILURE;
            }

            year = (int)parsed_year;
            year_provided = true;
        } else if (strcmp(argv[i], "--timezone") == 0) {

            if (i + 1 >= argc) {
                fprintf(stderr, "Missing timezone value!\n");
                return EXIT_FAILURE;
            }
            char *selected = argv[++i];

            if (strcasecmp(selected, "local") == 0) {
                timezone_mode = TIMESTAMP_LOCAL;
            } else if (strcasecmp(selected, "utc") == 0) {
                timezone_mode = TIMESTAMP_UTC;
            } else {
                fprintf(stderr, "Error! Invalid argument!\n");
                return EXIT_FAILURE;
            }
        } else if (strcmp(argv[i], "--top") == 0){

            if (i + 1 >= argc){
                fprintf(stderr, "Missing top value!\n");
                return EXIT_FAILURE;
            }

            size_t parsed_top;

            if (!parse_positive_size(argv[++i], &parsed_top)){
                fprintf(stderr, "Failed to parse --top value!\n");
                return EXIT_FAILURE;
            }

            top_k = parsed_top;
            top_provided = true;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return EXIT_FAILURE;
        }
    }

    if (file_provided && !format_provided) {
        fprintf(stderr, "Error: --format is required when --file is provided.\n");
        return EXIT_FAILURE;
    }

    if (format_provided && format == LOG_FORMAT_SSH && !year_provided) {
        fprintf(stderr, "Error: --year is required for SSH logs.\n");
        return EXIT_FAILURE;
    }

    if (format == LOG_FORMAT_SIMPLE && year_provided) {
        fprintf(stderr, "Error: --year is not required for simple logs.\n");
        return EXIT_FAILURE;
    }

    LogStore *store = NULL;
    IpTable *table = NULL;
    IpRankEntry *top_entries = NULL;
    FILE *file = NULL;
    char *line = NULL;

    ParseIssue issue = PARSE_ISSUE_NONE;

    size_t capacity = 0;
    size_t line_number = 0;

    int result = EXIT_FAILURE;

    store = log_store_create();

    if (store == NULL) {
        fprintf(stderr, "Failed to create log store!\n");
        goto cleanup;
    }

    table = ip_table_create(100);

    if (table == NULL) {
        fprintf(stderr, "Failed to create IP table\n");
        goto cleanup;
    }

    file = fopen(log_path, "r");

    if (file == NULL) {
        fprintf(stderr, "Error while opening file!\n");
        goto cleanup;
    }

    while ((getline(&line, &capacity, file)) != -1) {
        line_number++;

        if (format == LOG_FORMAT_SIMPLE) {

            if (!log_store_parse_simple_line(store, table, line, timezone_mode, &issue)) {
                if (issue == PARSE_ISSUE_STORAGE_FAILURE) {
                    fprintf(stderr, "Fatal: Storage failure at line %zu\n", line_number);
                    goto cleanup;
                }
                fprintf(stderr, "Warning: Line %zu: %s\n", line_number, parse_issue_message(issue));
            }
        } else {
            ParseStatus status =
                log_store_parse_ssh_line(store, table, line, year, timezone_mode, &issue);

            if (status == PARSE_ERROR) {

                if (issue == PARSE_ISSUE_STORAGE_FAILURE) {
                    fprintf(stderr, "Fatal: Storage failure at line %zu\n", line_number);
                    goto cleanup;
                }
                fprintf(stderr, "Warning! Line %zu: %s\n", line_number, parse_issue_message(issue));
            }
        }
    }

    if (ferror(file)) {
        fprintf(stderr, "Error while reading the file!\n");
        goto cleanup;
    }

    printf("\n");
    printf("========== LOG ANALYSIS ==========\n");
    printf("Total events:      %10zu\n", log_store_get_count(store));
    printf("Successful logins: %10zu\n", log_store_count_by_event(store, AUTH_SUCCESS));
    printf("Failed logins:     %10zu\n", log_store_count_by_event(store, AUTH_FAILURE));

    if (mode == DETECTOR_COUNT || mode == DETECTOR_ALL) {

        if (top_provided){

            size_t table_size = ip_table_size(table);
            size_t effective_k = (top_k < table_size) ? top_k : table_size;
            size_t top_count = 0;
            
            if (effective_k > 0){

                if (effective_k > SIZE_MAX / sizeof(*top_entries)){
                    fprintf(stderr, "Too big of a K!\n");
                    goto cleanup;
                }

                top_entries = malloc(effective_k * sizeof(*top_entries));

                if (top_entries == NULL){
                    fprintf(stderr, "Failed to allocate memory for top entries!\n");
                    goto cleanup;
                }

                if (!ip_heap_top_k_from_table(
                    table,
                    effective_k,
                    top_entries,
                    &top_count
                )){
                    fprintf(stderr, "Failed to find top k from table!\n");
                    goto cleanup;
                }
            }
            
            printf("\n");
            printf("========== TOP %zu IP ADDRESSES BY FAILED LOGINS ==========\n", top_k);
            
            if (top_count == 0){
                printf("No logins found!\n");

            } else {
                for (size_t i = 0; i < top_count; i++){
                    printf("%zu. IP ADDRESS: %s -> Failed attempts: %zu\n",
                            i + 1,
                            top_entries[i].ip_address,
                            top_entries[i].failed_attempts
                    );
                }
            }
        } else {
            printf("\n");
            ip_table_print_report(table);
        }

        size_t suspicious_count = detector_print_alerts(table, threshold);

        printf("\nTotal suspicious IP addresses: %zu\n", suspicious_count);
    }

    if (mode == DETECTOR_BURST || mode == DETECTOR_ALL) {
        printf("\n========== TIME-WINDOW SECURITY ALERTS ==========\n");
        size_t window_alerts = detector_analyze_windows_in_store(store, threshold, window_seconds);
        printf("\nIP addresses with suspicious bursts: %zu\n", window_alerts);
    }

    if (mode == DETECTOR_ACCOUNT_TARGETING || mode == DETECTOR_ALL) {
        size_t alerts_found = 0;
        printf("\n========== MULTI-ACCOUNT TARGETING ==========\n");

        if (!detector_find_account_targeting_in_store(store, threshold, window_seconds,
                                                      print_account_targeting_alert, &timezone_mode,
                                                      &alerts_found)) {
            fprintf(stderr, "Failed to detect account targeting!\n");
            goto cleanup;
        }

        printf("\nTotal account-targeting alerts: %zu\n", alerts_found);
    }

    result = EXIT_SUCCESS;

cleanup:
    free(line);
    free(top_entries);

    if (file != NULL) {
        fclose(file);
    }

    log_store_destroy(store);
    ip_table_destroy(table);

    return result;
}