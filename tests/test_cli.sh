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

if ./build/loganalyzer --file examples/sample.log --format simple > /dev/null 2>&1; then
    echo "PASS: Valid file path"
else
    echo "FAIL: Invalid file path"
    exit 1
fi

if ./build/loganalyzer --file nonexistent.log --format simple > /dev/null 2>&1; then
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

printf '\n'

output3=$(./build/loganalyzer --file examples/window_test.log --format simple --threshold 3)

if printf '%s\n' "$output3" | grep -Fxq "IP addresses with suspicious bursts: 1"; then
    echo "PASS: Time-window detection"
else
    echo "FAIL: Incorrect time-window detection"
    exit 1
fi

if ./build/loganalyzer --window 60 > /dev/null 2>&1; then
    echo "PASS: Valid time window accepted"
else
    echo "FAIL: Valid time window rejected"
    exit 1
fi

if ./build/loganalyzer --window 0 > /dev/null 2>&1; then
    echo "FAIL: Window with value 0 accepted"
    exit 1
else
    echo "PASS: Window with value 0 rejected"
fi

if ./build/loganalyzer --window -10 > /dev/null 2>&1; then
    echo "FAIL: Window with negative value accepted"
    exit 1
else
    echo "PASS: Window with negative value rejected"
fi

if ./build/loganalyzer --window abc > /dev/null 2>&1; then
    echo "FAIL: Non numerical window accepted"
    exit 1
else
    echo "PASS: Non numerical window rejected"
fi

if ./build/loganalyzer --window 30abc > /dev/null 2>&1; then
    echo "FAIL: Not clean numerical window accepted"
    exit 1
else
    echo "PASS: Not clean numerical window rejected"
fi

if ./build/loganalyzer --window nan > /dev/null 2>&1; then
    echo "FAIL: Not-a-Number value accepted"
    exit 1
else
    echo "PASS: Not-a-Number value rejected"
fi

if ./build/loganalyzer --window inf > /dev/null 2>&1; then
    echo "FAIL: Infinity accepted"
    exit 1
else
    echo "PASS: Infinity rejected"
fi

if ./build/loganalyzer --window > /dev/null 2>&1; then
    echo "FAIL: Empty value accepted"
    exit 1
else
    echo "PASS: Empty value rejected"
fi

if ./build/loganalyzer --window 1.5 > /dev/null 2>&1; then
    echo "PASS: Decimal value accepted"
else
    echo "FAIL: Decimal value not accepted"
    exit 1
fi

output4=$(./build/loganalyzer --file examples/window_test.log --format simple --threshold 3 --window 60)

if printf '%s\n' "$output4" | grep -Fq "IP addresses with suspicious bursts: 1"; then
    echo "PASS: Window 60 detects one suspicious IP"
else
    echo "FAIL: Incorrect detection for window 60"
    exit 1
fi

output5=$(./build/loganalyzer --file examples/window_test.log --format simple --threshold 3 --window 50)

if printf '%s\n' "$output5" | grep -Fq "IP addresses with suspicious bursts: 1"; then
    echo "PASS: Window 50 detects one suspicious IP"
else
    echo "FAIL: Incorrect detection for window 50"
    exit 1
fi

output6=$(./build/loganalyzer --file examples/window_test.log --format simple --threshold 3 --window 30)

if printf '%s\n' "$output6" | grep -Fq "IP addresses with suspicious bursts: 0"; then
    echo "PASS: Window 30 detects zero suspicious IP"
else
    echo "FAIL: Incorrect detection for window 30"
    exit 1
fi

output7=$(./build/loganalyzer --file examples/window_test.log --format simple --threshold 3 --window 20)

if printf '%s\n' "$output7" | grep -Fq "IP addresses with suspicious bursts: 0"; then
    echo "PASS: Window 20 detects zero suspicious IP"
else
    echo "FAIL: Incorrect detection for window 20"
    exit 1
fi

if ./build/loganalyzer --file examples/sample.log > /dev/null 2>&1; then
    echo "FAIL: Missing format accepted"
    exit 1
else 
    echo "PASS: Missing format rejected"
fi

if ./build/loganalyzer --file examples/sample.log --format simple --year 2025 > /dev/null 2>&1; then
    echo "FAIL: Unnecessary year accepted"
    exit 1
else
    echo "PASS: Unnecessary year rejected"
fi

if ./build/loganalyzer --year 2025 > /dev/null 2>&1; then
    echo "FAIL: Year for simple log accepted"
    exit 1
else
    echo "PASS: Year for simple log rejected"
fi

if ./build/loganalyzer --file examples/ssh_mixed.log --format ssh --year 2025 > /dev/null 2>&1; then
    echo "PASS: File processed correctly"
else
    echo "FAIL: File not processed correctly"
    exit 1
fi

if ./build/loganalyzer --file examples/ssh_mixed.log --format ssh > /dev/null 2>&1; then
    echo "FAIL: SSH log without year accepted"
    exit 1
else
    echo "PASS: SSH log without year rejected"
fi

if ./build/loganalyzer --file examples/ssh_mixed.log --format ssh --year 1800 > /dev/null 2>&1; then
    echo "FAIL: Year out of range accepted"
    exit 1
else
    echo "PASS: Year out of range rejected"
fi

if ./build/loganalyzer --file examples/ssh_mixed.log --format ssh --year 2200 > /dev/null 2>&1; then
    echo "FAIL: Year out of range accepted"
    exit 1
else
    echo "PASS: Year out of range rejected"
fi

if ./build/loganalyzer --file examples/ssh_mixed.log --format ssh --year > /dev/null 2>&1; then
    echo "FAIL: Year without value accepted"
    exit 1
else
    echo "PASS: Year without value rejected"
fi