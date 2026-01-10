#!/bin/bash
# Quick x86_64 Docker test helper
# Usage: ./docker_test.sh [test_name]
# If no test name given, runs all tests

set -e

echo "Building cot for x86_64-linux..."
zig build -Dtarget=x86_64-linux-gnu

if [ -n "$1" ]; then
    # Run single test
    echo "Running test: $1"
    docker run --platform linux/amd64 -v "$(pwd)":/cot -w /cot cot-zig:0.15.2 \
        sh -c "./zig-out/bin/cot tests/$1.cot -o test 2>/dev/null && \
               zig cc -o test_out $1.o zig-out/lib/libcot_runtime.a && \
               ./test_out; echo Exit: \$?"
else
    # Run all tests
    echo "Running all x86_64 tests in Docker..."
    docker run --platform linux/amd64 -v "$(pwd)":/cot -w /cot cot-zig:0.15.2 ./run_tests_x86_64.sh
fi
