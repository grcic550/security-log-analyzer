CC = gcc

CFLAGS = -std=c99 -Wall -Wextra -Wconversion -pedantic -g -fsanitize=address,undefined

CPPFLAGS = -Iinclude

SOURCES = src/main.c src/entries.c src/ip_table.c src/detector.c src/cli_utils.c

HEADERS = include/entries.h include/ip_table.h include/detector.h include/cli_utils.h

TARGET = build/loganalyzer

TEST_TARGET = build/test_ip_table

TEST_SOURCES = tests/test_ip_table.c src/ip_table.c

DETECTOR_TEST_TARGET = build/test_detector

DETECTOR_TEST_SOURCES = tests/test_detector.c src/detector.c src/ip_table.c src/entries.c

ENTRIES_TEST_TARGET = build/test_entries

ENTRIES_TEST_SOURCES = tests/test_entries.c src/entries.c src/ip_table.c

CLI_UTILS_TEST_TARGET = build/test_cli_utils

CLI_UTILS_TEST_SOURCES = tests/test_cli_utils.c src/cli_utils.c

all:$(TARGET)

$(TARGET):$(SOURCES) $(HEADERS)
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) -o $(TARGET)

$(TEST_TARGET):$(TEST_SOURCES) include/ip_table.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(TEST_SOURCES) -o $(TEST_TARGET)

$(DETECTOR_TEST_TARGET): $(DETECTOR_TEST_SOURCES) include/detector.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DETECTOR_TEST_SOURCES) -o $(DETECTOR_TEST_TARGET)

$(ENTRIES_TEST_TARGET): $(ENTRIES_TEST_SOURCES) include/entries.h include/ip_table.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(ENTRIES_TEST_SOURCES) -o $(ENTRIES_TEST_TARGET)

$(CLI_UTILS_TEST_TARGET): $(CLI_UTILS_TEST_SOURCES) include/cli_utils.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CLI_UTILS_TEST_SOURCES) -o $(CLI_UTILS_TEST_TARGET)

test: $(TARGET) $(TEST_TARGET) $(DETECTOR_TEST_TARGET) $(ENTRIES_TEST_TARGET) $(CLI_UTILS_TEST_TARGET)
	./$(TEST_TARGET)
	./$(DETECTOR_TEST_TARGET)
	./$(ENTRIES_TEST_TARGET)
	./$(CLI_UTILS_TEST_TARGET)
	bash tests/test_cli.sh

.PHONY: all clean test

clean:
	rm -f $(TARGET) $(TEST_TARGET) $(DETECTOR_TEST_TARGET) $(ENTRIES_TEST_TARGET) $(CLI_UTILS_TEST_TARGET)
