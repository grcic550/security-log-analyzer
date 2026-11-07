#ifndef DETECTOR_H
#define DETECTOR_H

#include <stdbool.h>
#include <stddef.h>

#include "ip_table.h"

bool is_suspicious(size_t failed_attempts, size_t threshold);

size_t detector_print_alerts(const IpTable *table, size_t threshold);
#endif