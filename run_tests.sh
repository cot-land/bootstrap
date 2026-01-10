#!/bin/bash
# Test runner for cot compiler
# Each test file should return a specific exit code

set -e

COT="./zig-out/bin/cot"
PASS=0
FAIL=0
SKIP=0

echo "Running cot compiler tests..."
echo "=============================="

# Build cot first
if ! zig build 2>/dev/null; then
    echo "FATAL: zig build failed"
    exit 1
fi

# Function to get expected exit code for a test
get_expected() {
    case "$1" in
        test_return) echo 42 ;;
        test_const) echo 42 ;;
        test_bool) echo 1 ;;
        test_if) echo 42 ;;
        test_if_false) echo 0 ;;
        test_ne) echo 42 ;;
        test_nested_if) echo 42 ;;
        test_call) echo 42 ;;
        test_while_simple) echo 42 ;;
        test_while_true) echo 42 ;;
        test_while) echo 5 ;;
        test_len) echo 5 ;;
        test_len2) echo 12 ;;
        test_string) echo 5 ;;
        test_streq) echo 42 ;;
        test_streq_false) echo 42 ;;
        test_strne) echo 42 ;;
        test_struct) echo 10 ;;
        test_struct2) echo 20 ;;
        test_array) echo 10 ;;
        test_array2) echo 20 ;;
        test_array3) echo 30 ;;
        test_array_dyn) echo 20 ;;
        test_array_dyn2) echo 50 ;;
        test_array_dyn3) echo 20 ;;
        test_5elem) echo 50 ;;
        test_slice) echo 42 ;;
        test_slice_len) echo 3 ;;
        test_slice_len2) echo 3 ;;
        test_slice_index) echo 30 ;;
        test_sub) echo 42 ;;
        test_mul) echo 42 ;;
        test_div) echo 42 ;;
        test_switch) echo 42 ;;
        test_switch_multi) echo 42 ;;
        test_for_array) echo 60 ;;
        test_for_slice) echo 90 ;;
        test_enum) echo 20 ;;
        test_enum_from_int) echo 20 ;;
        test_union) echo 42 ;;
        test_union_switch) echo 42 ;;
        *) echo "" ;;
    esac
}

for test_file in tests/test_*.cot; do
    name=$(basename "$test_file" .cot)

    # Get expected exit code
    expected=$(get_expected "$name")

    # Skip if no expected value defined
    if [ -z "$expected" ]; then
        echo "SKIP $name (no expected value defined)"
        SKIP=$((SKIP + 1))
        continue
    fi

    # Compile the test
    if ! $COT "$test_file" -o test_out 2>/dev/null; then
        # Try linking with gcc if built-in linker fails
        if [ -f "${name}.o" ]; then
            if ! gcc -o test_out "${name}.o" 2>/dev/null; then
                echo "FAIL $name (link failed)"
                FAIL=$((FAIL + 1))
                rm -f "${name}.o"
                continue
            fi
        else
            echo "FAIL $name (compile failed)"
            FAIL=$((FAIL + 1))
            continue
        fi
    fi

    # Run the compiled test
    set +e
    ./test_out
    actual=$?
    set -e

    # Check result
    if [ $actual -eq $expected ]; then
        echo "PASS $name (exit $actual)"
        PASS=$((PASS + 1))
    else
        echo "FAIL $name (expected $expected, got $actual)"
        FAIL=$((FAIL + 1))
    fi

    # Cleanup
    rm -f test_out "${name}.o"
done

echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
