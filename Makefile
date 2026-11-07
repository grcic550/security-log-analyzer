CC = gcc

CFLAGS = -std=c99 -Wall -Wextra -pedantic -g -fsanitize=address,undefined

CPPFLAGS = -Iinclude

SOURCES = src/main.c src/entries.c src/ip_table.c

HEADERS = include/entries.h include/ip_table.h

TARGET = build/loganalyzer

TEST_TARGET = build/test_ip_table

TEST_SOURCES = tests/test_ip_table.c src/ip_table.c 

all:$(TARGET)

$(TARGET):$(SOURCES) $(HEADERS)
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) -o $(TARGET)

$(TEST_TARGET):$(TEST_SOURCES) include/ip_table.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(TEST_SOURCES) -o $(TEST_TARGET)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

.PHONY: all clean test

clean:
	rm -f $(TARGET) $(TEST_TARGET) 
