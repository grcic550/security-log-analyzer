CC = gcc

CFLAGS = -std=c99 -Wall -Wextra -Wconversion -Wshadow -pedantic -g -fsanitize=address,undefined

CPPFLAGS = -Iinclude

SOURCES = src/main.c src/entries.c src/ip_table.c src/detector.c src/cli_utils.c src/ip_heap.c

HEADERS = include/entries.h include/ip_table.h include/detector.h include/cli_utils.h include/ip_heap.h 

TARGET = build/loganalyzer

TEST_TARGET = build/test_ip_table

TEST_SOURCES = tests/test_ip_table.c src/ip_table.c

DETECTOR_TEST_TARGET = build/test_detector

DETECTOR_TEST_SOURCES = tests/test_detector.c src/detector.c src/ip_table.c src/entries.c

ENTRIES_TEST_TARGET = build/test_entries

ENTRIES_TEST_SOURCES = tests/test_entries.c src/entries.c src/ip_table.c

CLI_UTILS_TEST_TARGET = build/test_cli_utils

CLI_UTILS_TEST_SOURCES = tests/test_cli_utils.c src/cli_utils.c

ALLOC_TEST_TARGET = build/test_allocation_failures

ALLOC_TEST_SOURCES = tests/test_allocation_failures.c src/entries.c src/ip_table.c

ALLOC_BUILD_RULE = $(CFLAGS) -Wl,--wrap=malloc -Wl,--wrap=realloc

OA_TEST_TARGET = build/test_ip_table_oa

OA_TEST_SOURCES = tests/test_ip_table_oa.c src/ip_table_oa.c

BENCH_TARGET = build/bench_ip_tables

BENCH_SOURCES = tests/bench_ip_tables.c src/ip_table.c src/ip_table_oa.c

BENCH_CFLAGS = -std=c99 -Wall -Wextra -Wconversion -pedantic -O2

HEAP_TARGET = build/test_ip_heap

HEAP_SOURCES = tests/test_ip_heap.c src/ip_heap.c src/ip_table.c

BENCH_TOP_K_TARGET = build/bench_top_k

BENCH_TOP_K_SOURCES = tests/bench_top_k.c src/ip_table.c src/ip_heap.c

all:$(TARGET)

$(TARGET):$(SOURCES) $(HEADERS)
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) -o $(TARGET)

$(TEST_TARGET):$(TEST_SOURCES) include/ip_table.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(TEST_SOURCES) -o $(TEST_TARGET)

$(DETECTOR_TEST_TARGET): $(DETECTOR_TEST_SOURCES) include/detector.h include/entries.h include/ip_table.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DETECTOR_TEST_SOURCES) -o $(DETECTOR_TEST_TARGET)

$(ENTRIES_TEST_TARGET): $(ENTRIES_TEST_SOURCES) include/entries.h include/ip_table.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(ENTRIES_TEST_SOURCES) -o $(ENTRIES_TEST_TARGET)

$(CLI_UTILS_TEST_TARGET): $(CLI_UTILS_TEST_SOURCES) include/cli_utils.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CLI_UTILS_TEST_SOURCES) -o $(CLI_UTILS_TEST_TARGET)

$(ALLOC_TEST_TARGET): $(ALLOC_TEST_SOURCES) include/entries.h include/ip_table.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(ALLOC_BUILD_RULE) $(ALLOC_TEST_SOURCES) -o $(ALLOC_TEST_TARGET)

$(OA_TEST_TARGET): $(OA_TEST_SOURCES) include/ip_table_oa.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(OA_TEST_SOURCES) -o $(OA_TEST_TARGET)

$(BENCH_TARGET): $(BENCH_SOURCES) include/ip_table.h include/ip_table_oa.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(BENCH_CFLAGS) $(BENCH_SOURCES) -o $(BENCH_TARGET)

$(HEAP_TARGET): $(HEAP_SOURCES) include/ip_heap.h include/ip_table.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(HEAP_SOURCES) -o $(HEAP_TARGET)

$(BENCH_TOP_K_TARGET): $(BENCH_TOP_K_SOURCES) include/ip_heap.h include/ip_table.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(BENCH_CFLAGS) $(BENCH_TOP_K_SOURCES) -o $(BENCH_TOP_K_TARGET)

test: $(TARGET) $(TEST_TARGET) $(DETECTOR_TEST_TARGET) $(ENTRIES_TEST_TARGET) $(CLI_UTILS_TEST_TARGET) $(ALLOC_TEST_TARGET) $(OA_TEST_TARGET) $(HEAP_TARGET)
	./$(TEST_TARGET)
	./$(DETECTOR_TEST_TARGET)
	./$(ENTRIES_TEST_TARGET)
	./$(CLI_UTILS_TEST_TARGET)
	./$(ALLOC_TEST_TARGET)
	./$(OA_TEST_TARGET)
	./$(HEAP_TARGET)
	bash tests/test_cli.sh

bench: $(BENCH_TARGET) $(BENCH_TOP_K_TARGET)
	./$(BENCH_TARGET)
	./$(BENCH_TOP_K_TARGET)

.PHONY: all clean test bench

clean:
	rm -f $(TARGET) $(TEST_TARGET) $(DETECTOR_TEST_TARGET) $(ENTRIES_TEST_TARGET) $(CLI_UTILS_TEST_TARGET) $(ALLOC_TEST_TARGET) $(OA_TEST_TARGET) $(BENCH_TARGET) $(HEAP_TARGET) $(BENCH_TOP_K_TARGET)
