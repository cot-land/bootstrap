#!/bin/bash
# Test runner for cot compiler - x86_64 Linux
# Run inside Docker container or on x86_64 Linux
#
# Usage:
#   ./run_tests_x86_64.sh          # Run comprehensive test only (fast validation)
#   ./run_tests_x86_64.sh --all    # Run all individual tests

set -e

COT="./zig-out/bin/cot"
PASS=0
FAIL=0
SKIP=0
RUN_ALL=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --all)
            RUN_ALL=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

echo "Running cot compiler tests (x86_64)..."
echo "========================================"

# Check if cot binary exists
if [ ! -f "$COT" ]; then
    echo "ERROR: $COT not found. Build with: zig build -Dtarget=x86_64-linux-gnu"
    exit 1
fi

# Run comprehensive test first
echo ""
echo "=== Comprehensive Test ==="
rm -f test_comprehensive.o test_out
if $COT tests/test_comprehensive.cot -o test_out 2>/dev/null; then
    # If cot didn't link, try zig cc
    if [ ! -f test_out ] && [ -f test_comprehensive.o ]; then
        RUNTIME_LIB="./zig-out/lib/libcot_runtime.a"
        if [ -f "$RUNTIME_LIB" ]; then
            zig cc -o test_out test_comprehensive.o "$RUNTIME_LIB" 2>/dev/null || true
        else
            zig cc -o test_out test_comprehensive.o 2>/dev/null || true
        fi
    fi
    if [ -f test_out ]; then
        set +e
        ./test_out
        comp_result=$?
        set -e
        rm -f test_out test_comprehensive.o
        if [ $comp_result -eq 42 ]; then
            echo "PASS test_comprehensive (exit 42) - All features working!"
            if [ "$RUN_ALL" != "true" ]; then
                echo ""
                echo "========================================"
                echo "Fast validation passed! Use --all to run individual tests."
                exit 0
            fi
            echo ""
            echo "=== Individual Tests ==="
        else
            echo "FAIL test_comprehensive (expected 42, got $comp_result)"
            echo "Running individual tests to isolate the failure..."
            echo ""
            RUN_ALL=true
        fi
    else
        echo "FAIL test_comprehensive (link failed)"
        echo "Running individual tests to isolate the failure..."
        echo ""
        RUN_ALL=true
    fi
else
    echo "FAIL test_comprehensive (compile failed)"
    echo "Running individual tests to isolate the failure..."
    echo ""
    RUN_ALL=true
fi

# Exit if not running all tests
if [ "$RUN_ALL" != "true" ]; then
    exit 0
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
        test_for_array) echo 60 ;;
        test_for_slice) echo 90 ;;
        test_len) echo 5 ;;
        test_len2) echo 12 ;;
        test_string) echo 5 ;;
        test_streq) echo 42 ;;
        test_streq_false) echo 42 ;;
        test_strne) echo 42 ;;
        test_str_var_cmp) echo 42 ;;
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
        test_enum) echo 20 ;;
        test_enum_from_int) echo 20 ;;
        test_union) echo 42 ;;
        test_union_switch) echo 42 ;;
        test_map_new) echo 42 ;;
        test_map_methods) echo 42 ;;
        test_list_new) echo 42 ;;
        test_list_simple) echo 42 ;;
        test_list_methods) echo 42 ;;
        test_value_lifetime) echo 42 ;;
        test_method) echo 42 ;;
        test_maxint) echo 42 ;;
        test_minint) echo 42 ;;
        test_interpolation) echo 42 ;;
        test_interp_var) echo 42 ;;
        test_type_alias) echo 42 ;;
        test_u8_local) echo 1 ;;
        test_compound_add) echo 42 ;;
        test_compound_sub) echo 42 ;;
        test_compound_mul) echo 42 ;;
        test_coalesce) echo 42 ;;
        test_var_assign) echo 42 ;;
        test_nested_struct) echo 42 ;;
        test_string_index) echo 42 ;;
        test_string_slice) echo 42 ;;
        test_bool_or) echo 42 ;;
        test_bool_and) echo 42 ;;
        *) echo "" ;;
    esac
}

for test_file in tests/test_*.cot; do
    name=$(basename "$test_file" .cot)

    # Skip comprehensive test (already run separately)
    if [ "$name" = "test_comprehensive" ]; then
        continue
    fi

    # Get expected exit code
    expected=$(get_expected "$name")

    # Skip if no expected value defined
    if [ -z "$expected" ]; then
        echo "SKIP $name (no expected value defined)"
        SKIP=$((SKIP + 1))
        continue
    fi

    # Clean up any previous .o file
    rm -f "${name}.o"

    # Compile the test (cot outputs .o to cwd with input basename)
    if ! $COT "$test_file" -o ignored 2>/dev/null; then
        # Check if .o file was created despite error (linker might fail but .o exists)
        if [ ! -f "${name}.o" ]; then
            echo "FAIL $name (compile failed)"
            FAIL=$((FAIL + 1))
            continue
        fi
    fi

    # Link with zig cc (provides C runtime, consistent with cot linker)
    # Include runtime library for FFI functions if it exists
    RUNTIME_LIB="./zig-out/lib/libcot_runtime.a"
    if [ -f "$RUNTIME_LIB" ]; then
        if ! zig cc -o test_out "${name}.o" "$RUNTIME_LIB" 2>/dev/null; then
            echo "FAIL $name (link failed)"
            FAIL=$((FAIL + 1))
            rm -f "${name}.o"
            continue
        fi
    elif ! zig cc -o test_out "${name}.o" 2>/dev/null; then
        echo "FAIL $name (link failed)"
        FAIL=$((FAIL + 1))
        rm -f "${name}.o"
        continue
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
echo "========================================"
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
