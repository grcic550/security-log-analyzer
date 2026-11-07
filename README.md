# Security Log Analyzer

A command-line security log analyzer implemented in C.

This project analyzes authentication logs and provides statistics about successful and failed login attempts.

It is being developed as a practical exercise in C programming,
data structures, algorithms, and secure software development.

## Features

- Parse authentication log entries
- Count successful and failed login attempts
- Track failed login attempts per IP address
- Hash table with seperate chaining
- Dynamic hash table resizing
- Dynamic memory management

## Technologies

- C99
- GCC
- GNU Make
- Linux

## Building

Compile the application:

	make

Run the analyzer:

	./build/loganalyzer

Remove the compiled executable:

	make clean

## Log format

Each log entry follows this format:

	YYYY-MM-DDTHH:MM:SS IP_ADDRESS EVENT_TYPE

Example:

	2026-11-06T10:31:00 192.168.1.20 LOGIN_SUCCESS

Supported event types:

- LOGIN_SUCCESS
- LOGIN_FAILED

## Project Status

This project is under active development

Planned improvements include:
- Command-line arguments
- Suspicious activity detection
- Automated tests
- Performanse benchmarking

