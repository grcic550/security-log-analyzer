#!/usr/bin/env bash

set -eu

printf '\n'
echo "Running CLI tests..."

if ./build/loganalyzer --threshold 3 > /dev/null 2>&1; then
    echo "PASS: Valid threshold"
else
    echo "FAIL: Valid threshold"
    exit 1
fi

if ./build/loganalyzer --threshold abc > /dev/null 2>&1; then
    echo "FAIL: Invalid threshold was accepted"
    exit 1
else
    echo "PASS: Invalid threshold rejected"
fi

if ./build/loganalyzer --threshold 0 > /dev/null 2>&1; then
    echo "FAIL: Zero threshold was accepted"
    exit 1
else
    echo "PASS: Zero threshold rejected"
fi

if ./build/loganalyzer --threshold -5 > /dev/null 2>&1; then
    echo "FAIL: Negative threshold accepted"
    exit 1
else
    echo "PASS: Negative threshold rejected"
fi

if ./build/loganalyzer --threshold 3abc > /dev/null 2>&1; then
    echo "FAIL: Invalid characters accepted"
    exit 1
else
    echo "PASS: Invalid characters rejected"
fi

if ./build/loganalyzer --unknown > /dev/null 2>&1; then
    echo "FAIL: Unknown argument accepted"
    exit 1
else
    echo "PASS: Unknown argument rejected"
fi

if ./build/loganalyzer --file examples/sample.log > /dev/null 2>&1; then
    echo "PASS: Valid file path"
else
    echo "FAIL: Invalid file path"
    exit 1
fi

if ./build/loganalyzer --file nonexistent.log > /dev/null 2>&1; then
    echo "FAIL: Missing file accepted"
    exit 1
else
    echo "PASS: Missing file rejected"
fi
printf '\n'

output=$(./build/loganalyzer --threshold 3)

if printf '%s\n' "$output" | grep -Fxq "Total suspicious IP addresses: 1"; then
    echo "PASS: Threshold 3 detects one suspicious IP"
else
    echo "FAIL: Incorrect detection result"
    exit 1
fi

output2=$(./build/loganalyzer --threshold 5)

if printf '%s\n' "$output2" | grep -Fxq "Total suspicious IP addresses: 0"; then
    echo "PASS: Threshold 5 detects zero suspicious IPs"
else
    echo "FAIL: Incorrect detection result"
    exit 1
fi
