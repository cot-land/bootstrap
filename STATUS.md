# Cot Implementation Status

**Last Updated:** 2026-01-14

> **Claude: Update this file whenever you complete a feature or fix a test.**

## Test Results

| Platform | Status | Notes |
|----------|--------|-------|
| ARM64 (macOS) | ✅ 99/99 Pass | All tests pass, 5 skipped (no expected value) |
| x86_64 (Linux) | ✅ 99/99 Pass | All tests pass, 5 skipped (no expected value) |

```bash
# Fast validation (default - runs comprehensive test only)
./run_tests.sh                    # ARM64 native (~2 seconds)
./run_tests_x86_64.sh             # x86_64 in Docker

# Full test suite (if comprehensive fails or debugging)
./run_tests.sh --all              # Run all 65 individual tests

# Zig unit tests
zig build test                    # 135+ embedded tests
```

**Comprehensive test:** `tests/test_comprehensive.cot` exercises ALL language features in a single test. Returns 42 on success, specific error codes (1-52) for failures.

---

## Bootstrap Progress

**Goal:** Self-hosting Cot 0.3 compiler (see ROADMAP.md for details)

| Progress | Count | Status |
|----------|-------|--------|
| Bootstrap .cot files exist | 20/23 | 87% |
| Bootstrap module tests passing | 20/20 | ✅ 100% |
| Self-hosting test | 1/1 | ✅ Pass |
| Zig source files | 22 | Reference implementation |

```bash
# Run bootstrap module tests
./test_bootstrap_modules.sh
```

### Module Test Results (2026-01-13)

**All 20 modules passing:**
- `token_boot.cot` - Token types and keywords
- `source_boot.cot` - Source position tracking
- `scanner_boot.cot` - Lexer/tokenizer
- `ast_boot.cot` - AST node types
- `types_boot.cot` - Type registry
- `errors_boot.cot` - Error reporting
- `parser_boot.cot` - Parser
- `ir_boot.cot` - IR data structures
- `lower_boot.cot` - AST → IR lowering
- `ssa_boot.cot` - SSA conversion
- `liveness_boot.cot` - Liveness analysis
- `backend_boot.cot` - Backend utilities
- `aarch64_boot.cot` - AArch64 instruction encoding
- `arm64_boot.cot` - ARM64 code generation
- `object_boot.cot` - Mach-O output
- `debug_boot.cot` - Debug utilities
- `type_context_boot.cot` - Type context management
- `driver_boot.cot` - Compilation driver
- `main_boot.cot` (compile) - Entry point compiles
- `main_boot.cot` (self-host) - Successfully compiles test_return.cot

**Not yet created:** `amd64_boot.cot`, `x86_64_boot.cot`, `pe_coff_boot.cot`

### Self-Hosting Status

**✅ MILESTONE ACHIEVED (2026-01-14):** The bootstrap compiler (`cot0`) can compile, link, and run cot programs!

```bash
# Build the bootstrap compiler
./zig-out/bin/cot src/bootstrap/main_boot.cot -o cot0

# Compile a cot source file
./cot0 tests/test_return.cot     # produces a.out (Mach-O object)

# Link and run
zig cc -o test_exe a.out && ./test_exe
# Exit code: 42 ✅
```

**Key fixes in this session:**
1. Fixed ARM64 STP/LDP instruction encoding (wrong bit positions)
2. Fixed MOV fp, sp encoding (SP requires ADD not ORR)
3. Fixed number parsing loop (cot `and` in while conditions)
4. Added proper function epilogue emission

### Known Language Bugs (Workarounds Applied)

1. **Large struct by value**: Passing structs > 16 bytes by value corrupts nested List handles. Workaround: pass pointers instead.
2. **Address-of chained field access**: `&state.*.field.subfield` doesn't work correctly. Workaround: copy to local first.
3. **`and` in while loop conditions**: Complex conditions like `while a < b and isDigit(c[i])` may not evaluate correctly. Workaround: use nested if statements inside a `while true` loop.

---

## Language Features

### Types

| Feature | Status | Notes |
|---------|--------|-------|
| `i8, i16, i32, i64` | Done | Signed integers (sign-extending loads) |
| `u8, u16, u32, u64` | Done | Unsigned integers (zero-extending loads) |
| Integer widening | Done | Implicit i8→i64, u8→u64 (same signedness) |
| `int` (alias for i64) | Done | Default integer type |
| `f32, f64, float` | Done | Floating point |
| `bool` | Done | Boolean |
| `string` | Done | Fat pointer (ptr + len) |
| `void` | Done | Void type |
| `?T` (optional) | Done | Optional types |
| `*T` (pointer) | Done | Full support: `&x`, `p.*`, `p.*.field` |
| `[N]T` (array) | Done | Fixed-size arrays |
| `[]T` (slice) | Done | Fat pointer slices |
| `type` aliases | Done | `type NodeIndex = u32` |

### Structs

| Feature | Status | Notes |
|---------|--------|-------|
| Definition | Done | `struct Point { x: i64, y: i64 }` |
| Literal init | Done | `Point{ .x = 1, .y = 2 }` |
| Field access | Done | `p.x` |
| Nested structs | Done | Struct fields containing structs |
| Methods | Done | `fn method(self: *T)` + UFCS |

### Enums

| Feature | Status | Notes |
|---------|--------|-------|
| Simple enum | Done | `enum Color { red, green, blue }` |
| Backing type | Done | `enum Token: u8 { ... }` |
| Explicit values | Done | `E100 = 100` |
| `@intFromEnum` | Done | Convert enum to int |
| `@enumFromInt` | Done | Convert int to enum |

### Tagged Unions

| Feature | Status | Notes |
|---------|--------|-------|
| Definition | Done | `union Result { ok: i64, err: string }` |
| Construction | Done | `Result.ok(42)` |
| Switch + capture | Done | `switch r { .ok \|val\| => val }` |
| Unit variants | Done | `none,` (no payload) |

### Collections (Built-in Generics)

| Feature | Status | Notes |
|---------|--------|-------|
| `List<T>` | Done | 24-byte header, FFI runtime |
| `list.push(item)` | Done | Append with auto-grow |
| `list.get(index)` | Done | Index access |
| `len(list)` | Done | Get length |
| `Map<K, V>` | Done | 2080-byte layout, FNV-1a hash |
| `map.set(k, v)` | Done | Insert/update |
| `map.get(key)` | Done | Lookup |
| `map.has(key)` | Done | Check existence |
| `new List<T>()` | Done | Heap allocation |
| `new Map<K,V>()` | Done | Heap allocation |

### Control Flow

| Feature | Status | Notes |
|---------|--------|-------|
| `if/else` | Done | Full support |
| `while` | Done | Full support |
| `for x in arr` | Done | Arrays and slices |
| `switch` expression | Done | Returns value |
| `switch` statement | Done | No return |
| Multi-case | Done | `.a, .b => x` |
| `break` | Done | Exit loop early |
| `continue` | Done | Skip to next iteration |
| `return` | Done | Full support |

### Operators

| Feature | Status | Notes |
|---------|--------|-------|
| Arithmetic | Done | `+ - * / %` |
| Comparison | Done | `== != < > <= >=` |
| Logical | Done | `and or not` |
| Compound assign | Done | `+= -= *= /=` |
| Null coalescing | Done | `??` |
| Optional unwrap | Done | `.?` |
| String equality | Done | `s1 == s2` |

### Built-ins

| Feature | Status | Notes |
|---------|--------|-------|
| `len(x)` | Done | Array/slice/string length |
| `print(x)` | Done | Output to stdout |
| `println(x)` | Done | Output with newline |
| `@maxInt(T)` | Done | Max value for type |
| `@minInt(T)` | Done | Min value for type |
| `@intFromEnum` | Done | Enum to int |
| `@enumFromInt` | Done | Int to enum |
| `@argsCount()` | Done | Get command-line argument count |
| `@argsGet(i)` | Done | Get command-line argument by index |

### Strings

| Feature | Status | Notes |
|---------|--------|-------|
| Literals | Done | `"hello"` |
| Length | Done | `len(s)` |
| Equality | Done | `s1 == s2` (variable vs literal, variable vs variable) |
| Indexing | Done | `s[i]` returns byte |
| Slicing | Done | `s[i:j]` |
| Interpolation | Done | `"Hello ${name}!"` - chains str_concat calls |
| Concatenation | Done | Via `cot_str_concat` |

---

## Compiler Pipeline

| Phase | File | Status |
|-------|------|--------|
| Scanner | `scanner.zig` | Done |
| Parser | `parser.zig` | Done |
| Type Checker | `check.zig` | Done |
| Lowerer | `lower.zig` | Done |
| IR | `ir.zig` | Done |
| SSA | `ssa.zig` | Done |
| ARM64 Codegen | `arm64_codegen.zig` | Done |
| x86_64 Codegen | `amd64_codegen.zig` | Done |
| Mach-O Output | `object.zig` | Done |
| ELF Output | `object.zig` | Done |
| PE/COFF Output | `pe_coff.zig` | Done |
| Linker | `driver.zig` | Done (uses `zig cc`) |

---

## Runtime Library

Location: `runtime/`

| Function | Purpose |
|----------|---------|
| `cot_str_concat` | String concatenation |
| `cot_map_new` | Create map |
| `cot_map_set` | Map insert (string keys) |
| `cot_map_get` | Map lookup (string keys) |
| `cot_map_has` | Map contains (string keys) |
| `cot_map_set_int` | Map insert (integer keys) |
| `cot_map_get_int` | Map lookup (integer keys) |
| `cot_map_has_int` | Map contains (integer keys) |
| `cot_map_free` | Free map |
| `cot_list_push` | List append |
| `cot_list_get` | List index |
| `cot_list_len` | List length |
| `cot_list_free` | Free list |
| `cot_args_init` | Initialize args storage |
| `cot_args_count` | Get argument count |
| `cot_args_get` | Get argument by index |

Built with: `zig build` (produces `zig-out/lib/libcot_runtime.a`)

---

## Architecture Notes

The codegen uses **MCValue-based tracking** (see `CODEGEN.md`):
- Every value's location is tracked explicitly
- Automatic spilling when registers fill up
- No ad-hoc register guessing

Key files:
- `arm64_codegen.zig` - ARM64 with MCValue
- `amd64_codegen.zig` - x86_64 with MCValue
- `driver.zig` - Compilation orchestration
