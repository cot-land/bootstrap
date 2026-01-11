# Test runner for cot compiler on Windows
# Each test file should return a specific exit code
#
# Current status: 58/64 tests pass (91%)
# Remaining issues: Some runtime library calls (list/map/string concat)
#
# Run with: powershell -ExecutionPolicy Bypass -File run_tests_windows.ps1

$ErrorActionPreference = "Stop"

$COT = ".\zig-out\bin\cot.exe"
$PASS = 0
$FAIL = 0
$SKIP = 0

Write-Host "Running cot compiler tests (Windows)..."
Write-Host "========================================="

# Build cot first
Write-Host "Building cot..."
try {
    zig build 2>&1 | Out-Null
} catch {
    Write-Host "FATAL: zig build failed"
    exit 1
}

# Expected exit codes for each test
$expected = @{
    "test_return" = 42
    "test_const" = 42
    "test_bool" = 1
    "test_if" = 42
    "test_if_false" = 0
    "test_ne" = 42
    "test_nested_if" = 42
    "test_call" = 42
    "test_while_simple" = 42
    "test_while_true" = 42
    "test_while" = 5
    "test_len" = 5
    "test_len2" = 12
    "test_string" = 5
    "test_streq" = 42
    "test_streq_false" = 42
    "test_strne" = 42
    "test_struct" = 10
    "test_struct2" = 20
    "test_array" = 10
    "test_array2" = 20
    "test_array3" = 30
    "test_array_dyn" = 20
    "test_array_dyn2" = 50
    "test_array_dyn3" = 20
    "test_5elem" = 50
    "test_slice" = 42
    "test_slice_len" = 3
    "test_slice_len2" = 3
    "test_slice_index" = 30
    "test_sub" = 42
    "test_mul" = 42
    "test_div" = 42
    "test_switch" = 42
    "test_switch_multi" = 42
    "test_for_array" = 60
    "test_for_slice" = 90
    "test_enum" = 20
    "test_enum_from_int" = 20
    "test_union" = 42
    "test_union_switch" = 42
    "test_map_new" = 42
    "test_map_methods" = 42
    "test_list_new" = 42
    "test_list_simple" = 42
    "test_list_methods" = 42
    "test_value_lifetime" = 42
    "test_method" = 42
    "test_maxint" = 42
    "test_minint" = 42
    "test_interpolation" = 42
    "test_interp_var" = 42
    "test_type_alias" = 42
    "test_compound_add" = 42
    "test_compound_sub" = 42
    "test_compound_mul" = 42
    "test_coalesce" = 42
    "test_var_assign" = 42
    "test_nested_struct" = 42
    "test_string_index" = 42
    "test_string_slice" = 42
    "test_bool_or" = 42
    "test_bool_and" = 42
}

# Get all test files
$testFiles = Get-ChildItem -Path "tests\test_*.cot"

foreach ($testFile in $testFiles) {
    $name = $testFile.BaseName
    $objFile = "$name.obj"
    $exeFile = "$name.exe"

    # Check if we have expected value
    if (-not $expected.ContainsKey($name)) {
        Write-Host "SKIP $name (no expected value defined)"
        $SKIP++
        continue
    }

    $expectedCode = $expected[$name]

    # Compile the test (generates .obj file)
    try {
        & $COT $testFile.FullName -o $exeFile 2>&1 | Out-Null
    } catch {
        # Compilation generates .obj, linking may fail - that's ok
    }

    # Check if obj file was created
    if (-not (Test-Path $objFile)) {
        Write-Host "FAIL $name (compile failed - no .obj)"
        $FAIL++
        continue
    }

    # Link with zig cc and runtime library
    $runtimeLib = ".\zig-out\lib\cot_runtime.lib"
    $linkResult = zig cc $objFile $runtimeLib -o $exeFile 2>&1
    if (-not (Test-Path $exeFile)) {
        Write-Host "FAIL $name (link failed)"
        $FAIL++
        Remove-Item -Force $objFile -ErrorAction SilentlyContinue
        continue
    }

    # Run the test
    $proc = Start-Process -FilePath ".\$exeFile" -Wait -PassThru -NoNewWindow
    $actual = $proc.ExitCode

    # Check result
    if ($actual -eq $expectedCode) {
        Write-Host "PASS $name (exit $actual)"
        $PASS++
    } else {
        Write-Host "FAIL $name (expected $expectedCode, got $actual)"
        $FAIL++
    }

    # Cleanup
    Remove-Item -Force $objFile -ErrorAction SilentlyContinue
    Remove-Item -Force $exeFile -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "========================================="
Write-Host "Results: $PASS passed, $FAIL failed, $SKIP skipped"

if ($FAIL -gt 0) {
    exit 1
}
