#!/bin/bash
# Test each bootstrap module individually
# Run from repository root: ./test_bootstrap_modules.sh

# Don't exit on first error - we want full results
# set -e
COT="./zig-out/bin/cot"
TESTS_DIR="tests/bootstrap"

mkdir -p "$TESTS_DIR"

echo "=== Testing Bootstrap Modules ==="
echo ""

# Track results
PASSED=0
FAILED=0
declare -a FAILED_TESTS

run_test() {
    local name="$1"
    local test_file="$2"
    local expected="${3:-42}"

    printf "%-30s " "$name:"

    if $COT "$test_file" -o "/tmp/test_boot_$$" 2>/dev/null; then
        result=$("/tmp/test_boot_$$" 2>/dev/null; echo $?)
        rm -f "/tmp/test_boot_$$"
        if [ "$result" = "$expected" ]; then
            echo "PASS"
            ((PASSED++))
            return 0
        else
            echo "FAIL (got $result, expected $expected)"
            ((FAILED++))
            FAILED_TESTS+=("$name")
            return 0
        fi
    else
        echo "FAIL (compile error)"
        ((FAILED++))
        FAILED_TESTS+=("$name")
        return 0
    fi
}

# Test 1: token_boot.cot
cat > "$TESTS_DIR/test_token.cot" << 'EOF'
import "../../src/bootstrap/token_boot.cot"

fn main() int {
    var t: Token = Token.kw_fn
    if tokenIsKeyword(t) {
        var t2: Token = Token.plus
        if not tokenIsKeyword(t2) {
            return 42
        }
    }
    return 1
}
EOF
run_test "token_boot.cot" "$TESTS_DIR/test_token.cot"

# Test 2: source_boot.cot
cat > "$TESTS_DIR/test_source.cot" << 'EOF'
import "../../src/bootstrap/source_boot.cot"

fn main() int {
    var p: Pos = Pos{ .offset = 100 }
    var s: Span = Span{ .start = p, .end = p }
    if p.offset == 100 and s.start.offset == 100 {
        return 42
    }
    return 1
}
EOF
run_test "source_boot.cot" "$TESTS_DIR/test_source.cot"

# Test 3: scanner_boot.cot - test tokenization
cat > "$TESTS_DIR/test_scanner.cot" << 'EOF'
import "../../src/bootstrap/scanner_boot.cot"

fn main() int {
    var content: string = "fn main() { return 42 }"
    var state: ScannerState = scannerInit(content)

    // First token should be 'fn' keyword
    var r1: TokenResult = scanNext(state)
    if r1.tok != Token.kw_fn { return 1 }

    // Advance scanner
    state.pos = r1.end

    // Second token should be identifier 'main'
    var r2: TokenResult = scanNext(state)
    if r2.tok != Token.identifier { return 2 }

    return 42
}
EOF
run_test "scanner_boot.cot" "$TESTS_DIR/test_scanner.cot"

# Test 4: ast_boot.cot - test basic struct
cat > "$TESTS_DIR/test_ast.cot" << 'EOF'
import "../../src/bootstrap/ast_boot.cot"

fn main() int {
    // Just test that a struct from ast_boot works
    var f: Field = Field{
        .name = "test",
        .type_expr = null_node,
        .span = Span{ .start = Pos{ .offset = 0 }, .end = Pos{ .offset = 0 } },
    }
    if f.name == "test" {
        return 42
    }
    return 1
}
EOF
run_test "ast_boot.cot" "$TESTS_DIR/test_ast.cot"

# Test 5: types_boot.cot - test type constants
cat > "$TESTS_DIR/test_types.cot" << 'EOF'
import "../../src/bootstrap/types_boot.cot"

fn main() int {
    // Check built-in type indices
    if TYPE_VOID == 12 and TYPE_BOOL == 1 and TYPE_INT == 5 {
        return 42
    }
    return 1
}
EOF
run_test "types_boot.cot" "$TESTS_DIR/test_types.cot"

# Test 6: errors_boot.cot - test error enum
cat > "$TESTS_DIR/test_errors.cot" << 'EOF'
import "../../src/bootstrap/errors_boot.cot"

fn main() int {
    // Test ErrorCode enum and function
    var code: ErrorCode = ErrorCode.E100
    var val: int = errorCodeValue(code)
    if val == 100 {
        return 42
    }
    return 1
}
EOF
run_test "errors_boot.cot" "$TESTS_DIR/test_errors.cot"

# Test 7: parser_boot.cot - test parsing simple code
cat > "$TESTS_DIR/test_parser.cot" << 'EOF'
import "../../src/bootstrap/parser_boot.cot"

fn main() int {
    var content: string = "fn main() int { return 42 }"
    var state: ParserState = parserInit(content)
    state = parseFile(state)

    // Should have parsed at least one node
    if len(state.nodes) > 0 {
        return 42
    }
    return 1
}
EOF
run_test "parser_boot.cot" "$TESTS_DIR/test_parser.cot"

# Test 8: ir_boot.cot - test IR builder
cat > "$TESTS_DIR/test_ir.cot" << 'EOF'
import "../../src/bootstrap/ir_boot.cot"

fn main() int {
    // Use 5 for return type (equivalent to TYPE_INT in types_boot)
    var fb: IRFuncBuilder = irFuncBuilderInit("test_func", 0, 5, 0, 100)
    if fb.name == "test_func" {
        return 42
    }
    return 1
}
EOF
run_test "ir_boot.cot" "$TESTS_DIR/test_ir.cot"

# Test 9: lower_boot.cot
# lower_boot requires parser_boot to be imported first (for Node, Token types)
cat > "$TESTS_DIR/test_lower.cot" << 'EOF'
import "../../src/bootstrap/parser_boot.cot"
import "../../src/bootstrap/lower_boot.cot"

fn main() int {
    // lower_boot imports ir_boot, test that it loads
    var fb: IRFuncBuilder = irFuncBuilderInit("lowered", 0, TYPE_INT, 0, 50)
    if len(fb.name) > 0 {
        return 42
    }
    return 1
}
EOF
run_test "lower_boot.cot" "$TESTS_DIR/test_lower.cot"

# Test 10: ssa_boot.cot
cat > "$TESTS_DIR/test_ssa.cot" << 'EOF'
import "../../src/bootstrap/ssa_boot.cot"

fn main() int {
    // Test Op enum exists (ssa_boot uses Op not SSAOp)
    var op: Op = Op.const_int
    if @intFromEnum(op) >= 0 {
        return 42
    }
    return 1
}
EOF
run_test "ssa_boot.cot" "$TESTS_DIR/test_ssa.cot"

# Test 11: liveness_boot.cot
cat > "$TESTS_DIR/test_liveness.cot" << 'EOF'
import "../../src/bootstrap/liveness_boot.cot"

fn main() int {
    // Test LivenessInfo struct
    var info: LivenessInfo = LivenessInfo{
        .last_use = new List<int>(),
        .deaths = new List<int>(),
        .inst_index = new List<int>(),
    }
    if len(info.last_use) == 0 {
        return 42
    }
    return 1
}
EOF
run_test "liveness_boot.cot" "$TESTS_DIR/test_liveness.cot"

# Test 12: codegen/backend_boot.cot
cat > "$TESTS_DIR/test_backend.cot" << 'EOF'
import "../../src/bootstrap/codegen/backend_boot.cot"

fn main() int {
    // Test CodeBuffer creation
    var buf: CodeBuffer = codeBufferInit()
    codeBufferEmit8(buf, 144)
    if codeBufferPos(buf) == 1 {
        return 42
    }
    return 1
}
EOF
run_test "backend_boot.cot" "$TESTS_DIR/test_backend.cot"

# Test 13: codegen/aarch64_boot.cot
cat > "$TESTS_DIR/test_aarch64.cot" << 'EOF'
import "../../src/bootstrap/codegen/aarch64_boot.cot"

fn main() int {
    // Test ARM64 register constants
    if REG_X0 == 0 and REG_FP == 29 and REG_LR == 30 {
        return 42
    }
    return 1
}
EOF
run_test "aarch64_boot.cot" "$TESTS_DIR/test_aarch64.cot"

# Test 14: codegen/arm64_boot.cot (full codegen)
cat > "$TESTS_DIR/test_arm64_cg.cot" << 'EOF'
import "../../src/bootstrap/codegen/arm64_boot.cot"

fn main() int {
    // Test FullCodeGen creation
    var cg: FullCodeGen = fullCodeGenInit(64)
    if cg.stack_size == 64 {
        return 42
    }
    return 1
}
EOF
run_test "arm64_boot.cot" "$TESTS_DIR/test_arm64_cg.cot"

# Test 15: codegen/object_boot.cot
cat > "$TESTS_DIR/test_object.cot" << 'EOF'
import "../../src/bootstrap/codegen/object_boot.cot"

fn main() int {
    var obj: ObjectFile = objectFileNew()
    var sec_idx: int = objectAddSection(obj, "__text", SectionKind.text)
    if sec_idx >= 0 {
        return 42
    }
    return 1
}
EOF
run_test "object_boot.cot" "$TESTS_DIR/test_object.cot"

# Test 16: debug_boot.cot
cat > "$TESTS_DIR/test_debug.cot" << 'EOF'
import "../../src/bootstrap/debug_boot.cot"

fn main() int {
    // debug_boot provides debug printing utilities
    // Just test it compiles
    return 42
}
EOF
run_test "debug_boot.cot" "$TESTS_DIR/test_debug.cot"

# Test 17: type_context_boot.cot
cat > "$TESTS_DIR/test_type_context.cot" << 'EOF'
import "../../src/bootstrap/type_context_boot.cot"

fn main() int {
    // Test TypeRegistry creation
    var reg: TypeRegistry = typeRegistryInit()
    // Just verify it compiles and runs
    return 42
}
EOF
run_test "type_context_boot.cot" "$TESTS_DIR/test_type_context.cot"

# Test 18: driver_boot.cot
# driver_boot requires parser, lower, and codegen modules to be imported first
cat > "$TESTS_DIR/test_driver.cot" << 'EOF'
import "../../src/bootstrap/parser_boot.cot"
import "../../src/bootstrap/lower_boot.cot"
import "../../src/bootstrap/codegen/arm64_boot.cot"
import "../../src/bootstrap/codegen/object_boot.cot"
import "../../src/bootstrap/driver_boot.cot"

fn main() int {
    // Test CompileOptions creation
    var opts: CompileOptions = compileOptionsNew("test.cot", "test")
    if opts.input_path == "test.cot" {
        return 42
    }
    return 1
}
EOF
run_test "driver_boot.cot" "$TESTS_DIR/test_driver.cot"

# Test 19: main_boot.cot (integration - compile and run with no args)
printf "%-30s " "main_boot.cot (compile):"
if $COT src/bootstrap/main_boot.cot -o /tmp/cot0_test 2>/dev/null; then
    # Run with no args - should return 42 per the code
    result=$(/tmp/cot0_test 2>/dev/null; echo $?)
    rm -f /tmp/cot0_test
    if [ "$result" = "42" ]; then
        echo "PASS"
        ((PASSED++))
    else
        echo "FAIL (got $result, expected 42)"
        ((FAILED++))
        FAILED_TESTS+=("main_boot.cot (compile)")
    fi
else
    echo "FAIL (compile error)"
    ((FAILED++))
    FAILED_TESTS+=("main_boot.cot (compile)")
fi

# Test 20: main_boot.cot can compile a simple file (self-hosting test)
printf "%-30s " "main_boot.cot (self-host):"
if $COT src/bootstrap/main_boot.cot -o /tmp/cot0 2>/dev/null; then
    # Try to compile a simple test file
    result=$(/tmp/cot0 tests/test_return.cot -o /tmp/test_from_cot0 2>/dev/null; echo $?)
    rm -f /tmp/cot0 /tmp/test_from_cot0
    if [ "$result" = "0" ]; then
        echo "PASS"
        ((PASSED++))
    else
        echo "FAIL (cot0 returned $result)"
        ((FAILED++))
        FAILED_TESTS+=("main_boot.cot (self-host)")
    fi
else
    echo "FAIL (compile error)"
    ((FAILED++))
    FAILED_TESTS+=("main_boot.cot (self-host)")
fi

echo ""
echo "=== Results ==="
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
    echo ""
    echo "Failed tests:"
    for t in "${FAILED_TESTS[@]}"; do
        echo "  - $t"
    done
fi

# Exit with failure if any tests failed
[ $FAILED -eq 0 ]
