# Security Log Analyzer

A command-line authentication log analyzer written in **C99** for Linux. It parses synthetic and OpenSSH (`sshd`) authentication logs, tracks failed attempts per IP using a custom resizing hash table, and detects brute-force bursts and multi-account targeting attacks.

## Highlights

- **Dual log format parsing** — supports both ISO-timestamp simple logs and OpenSSH `sshd` logs (failed passwords, invalid users, accepted passwords, ignored non-auth lines, and structured `ParseIssue` diagnostics).
- **Multiple detection engines** — per-IP failure counts, sliding time-window brute-force burst detection, and multi-account targeting detection (distinct usernames targeted from one IP within a window).
- **Custom data structures & memory safety** — opaque `LogStore` API, hash table with separate chaining and dynamic resizing, dynamic line reading via `getline()`, and unified `goto cleanup` teardown.
- **Strict compiler & runtime verification** — built with `-std=c99 -Wall -Wextra -Wconversion -pedantic -fsanitize=address,undefined` and tested with unit tests, CLI integration tests, and **`malloc`/`realloc` fault-injection tests** (`-Wl,--wrap=malloc -Wl,--wrap=realloc`).
- **Timezone-aware timestamps** — supports `--timezone local` and `--timezone utc` with calendar and leap-year validation.

## Building & Testing

Build the binary:

```bash
make
```

Run the test suite (unit tests, OOM fault-injection tests under ASan/UBSan, and CLI integration tests):

```bash
make test
```

Clean build artifacts:

```bash
make clean
```

## CLI Usage

Run with default settings (`examples/sample.log`, `simple` format, threshold `3`, window `60s`, all detectors):

```bash
./build/loganalyzer
```

Analyze an OpenSSH log with multi-account targeting detection in UTC:

```bash
./build/loganalyzer \
  --file /path/to/auth.log \
  --format ssh \
  --year 2026 \
  --timezone utc \
  --threshold 3 \
  --window 60 \
  --detector all
```

### Options

| Flag | Values / Type | Default | Description |
| --- | --- | --- | --- |
| `--file <path>` | File path | `examples/sample.log` | Input log file (requires `--format`). |
| `--format <fmt>` | `simple`, `ssh` | `simple` | Input log format. |
| `--year <YYYY>` | `1900`–`2100` | — | Required for `ssh` logs (syslog timestamps omit the year); rejected for `simple` logs. |
| `--threshold <N>` | Positive integer | `3` | Minimum failures (or distinct usernames for `account-targeting`) to trigger an alert. |
| `--window <sec>` | Positive float | `60.0` | Sliding time window in seconds for burst and account-targeting detection. |
| `--detector <mode>` | `all`, `count`, `burst`, `account-targeting` | `all` | Select which detector(s) to run. |
| `--timezone <tz>` | `local`, `utc` | `local` | Timezone mode for timestamp parsing and alert formatting. |

## Example Output

Running `./build/loganalyzer` on `examples/sample.log`:

```text
========== LOG ANALYSIS ==========
Total events:               6
Successful logins:          2
Failed logins:              4


========== FAILED LOGINS BY IP ==========
192.168.1.20         3
192.168.1.40         1

==========  SECURITY ALERTS ==========
[ALERT] 192.168.1.20         3 failed attempts

Total suspicious IP addresses: 1

========== TIME-WINDOW SECURITY ALERTS ==========

[BRUTE FORCE] 192.168.1.20 - 3 failures within 60 seconds

IP addresses with suspicious bursts: 1

========== MULTI-ACCOUNT TARGETING ==========

Total account-targeting alerts: 0
```

## Supported Log Formats

### Simple (`--format simple`)

```text
YYYY-MM-DDTHH:MM:SS IP_ADDRESS EVENT_TYPE
```

Example:

```text
2026-11-06T10:31:00 192.168.1.20 LOGIN_FAILED
```

Supported event types: `LOGIN_SUCCESS`, `LOGIN_FAILED`.

### OpenSSH (`--format ssh --year <YYYY>`)

```text
Nov 10 14:30:15 server1 sshd[1234]: Failed password for root from 192.168.1.20 port 52341 ssh2
Nov 10 14:31:00 server1 sshd[1235]: Failed password for invalid user admin from 192.168.1.20 port 52342 ssh2
Nov 10 14:32:00 server1 sshd[1236]: Accepted password for ante from 192.168.1.30 port 52343 ssh2
```

Non-authentication `sshd` and unrelated syslog lines are safely ignored (`PARSE_IGNORED`), while malformed authentication lines report line-numbered `ParseIssue` warnings to `stderr`.

## Project Structure

```text
.
├── include/                    # Public module headers
│   ├── cli_utils.h
│   ├── detector.h
│   ├── entries.h
│   └── ip_table.h
├── src/                        # C99 implementation
│   ├── cli_utils.c             # Numeric CLI argument validation
│   ├── detector.c              # Count, burst, and account-targeting detectors
│   ├── entries.c               # TokenSpan lexer, simple/SSH parsers, LogStore
│   ├── ip_table.c              # Resizing separate-chaining IP hash table
│   └── main.c                  # CLI entry point and report output
├── tests/                      # Unit, OOM fault-injection, and CLI tests
│   ├── test_allocation_failures.c
│   ├── test_cli.sh
│   ├── test_cli_utils.c
│   ├── test_detector.c
│   ├── test_entries.c
│   └── test_ip_table.c
├── examples/                   # Synthetic example logs
├── .clang-format
└── Makefile
```

## Planned Improvements

- Performance benchmarking on large log files
- Release build target (`-O2`) alongside sanitizer debug builds
- Structured JSON report output
