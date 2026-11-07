CC = gcc

CFLAGS = -std=c99 -Wall -Wextra -pedantic -g -fsanitize=address,undefined

CPPFLAGS = -Iinclude

SOURCES = src/main.c src/entries.c src/ip_table.c

HEADERS = include/entries.h include/ip_table.h

TARGET = build/loganalyzer

all:$(TARGET)

$(TARGET):$(SOURCES) $(HEADERS)
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) -o $(TARGET)

.PHONY: all clean

clean:
	rm -f $(TARGET) 
