# Cot Self-Hosting Roadmap

**Last Updated:** 2026-01-13

> **Claude: Update this file when you start or complete a roadmap item.**

---

## The Bootstrap Strategy

This roadmap follows a disciplined bootstrap strategy to create a self-hosting cot compiler:

### Phase 1: Cot 0.3 - Minimal Self-Hosting Compiler

**Goal:** Create a cot compiler written in cot that can compile itself.

**Approach:**
1. For every `.zig` source file, create a matching `.cot` file in `src/bootstrap/`
2. These `.cot` files use ONLY features the Zig compiler already supports
3. **No feature creep** - don't add features to the Zig compiler unless absolutely required
4. The `.cot` files are a "blueprint" showing Zig → Cot translation

### Phase 2: Sync Cycle

**Goal:** Keep `.zig` and `.cot` files in lockstep.

**Process:**
1. When modifying a `.zig` file, update the corresponding `.cot` file
2. When adding a feature to support bootstrap, add it to BOTH Zig and test with .cot
3. Run comprehensive tests on both platforms after each sync

### Phase 3: Evolution (Post-Bootstrap)

**Goal:** Once self-hosted, evolve the compiler using itself.

**Approach:**
1. Bootstrap compiler (Cot 0.3) compiles itself
2. Add new features to the .cot compiler using the .cot compiler
3. Iterate until the "full featured" wireframe files can compile
4. Eventually retire the Zig bootstrap compiler

---

## File Mapping: Zig → Bootstrap Cot

Every Zig source file needs a corresponding bootstrap .cot file that uses only supported features.

| Zig File | Bootstrap .cot File | Status | Notes |
|----------|---------------------|--------|-------|
| `src/token.zig` | `src/bootstrap/token_boot.cot` | **Done** | Token types and keywords |
| `src/source.zig` | `src/bootstrap/source_boot.cot` | **Done** | Source position tracking |
| `src/scanner.zig` | `src/bootstrap/scanner_boot.cot` | **Done** | Lexer/tokenizer |
| `src/ast.zig` | `src/bootstrap/ast_boot.cot` | **Done** | AST node types |
| `src/types.zig` | `src/bootstrap/types_boot.cot` | **Done** | Type registry with 14-variant union |
| `src/parser.zig` | `src/bootstrap/parser_boot.cot` | **Done** | Parser |
| `src/check.zig` | `src/bootstrap/check_boot.cot` | **Done** | Type checker (basic tests) |
| `src/errors.zig` | `src/bootstrap/errors_boot.cot` | **Done** | Error handling |
| `src/ir.zig` | `src/bootstrap/ir_boot.cot` | **Done** | IR definitions |
| `src/lower.zig` | `src/bootstrap/lower_boot.cot` | **Done** | AST → IR lowering |
| `src/ssa.zig` | `src/bootstrap/ssa_boot.cot` | **Done** | SSA conversion |
| `src/liveness.zig` | `src/bootstrap/liveness_boot.cot` | **Done** | Liveness analysis |
| `src/driver.zig` | `src/bootstrap/driver_boot.cot` | **Done** | Compilation orchestration |
| `src/main.zig` | `src/bootstrap/main_boot.cot` | **Done** | Entry point |
| `src/codegen/backend.zig` | `src/bootstrap/codegen/backend_boot.cot` | **Done** | Backend abstraction |
| `src/codegen/arm64_codegen.zig` | `src/bootstrap/codegen/arm64_boot.cot` | **Done** | ARM64 code generation |
| `src/codegen/amd64_codegen.zig` | `src/bootstrap/codegen/amd64_boot.cot` | TODO | x86_64 code generation |
| `src/codegen/aarch64.zig` | `src/bootstrap/codegen/aarch64_boot.cot` | **Done** | ARM64 instruction encoding |
| `src/codegen/x86_64.zig` | `src/bootstrap/codegen/x86_64_boot.cot` | TODO | x86_64 instruction encoding |
| `src/codegen/object.zig` | `src/bootstrap/codegen/object_boot.cot` | **Done** | Mach-O output (ARM64) |
| `src/codegen/pe_coff.zig` | `src/bootstrap/codegen/pe_coff_boot.cot` | TODO | Windows PE/COFF output |
| `src/debug.zig` | `src/bootstrap/debug_boot.cot` | **Done** | Debug output utilities |
| `src/type_context.zig` | `src/bootstrap/type_context_boot.cot` | **Done** | Type context for checker |

**Progress: 20/23 files complete (ARM64 bootstrap ready)**

---

## Minimal Language Subset for Bootstrap

The bootstrap .cot files must use ONLY these features (already working in Zig compiler):

### Currently Supported ✅

**Imports (Bootstrap Only):**
- `import "path/to/file.cot"` - textual inclusion (like C's #include)
- Recursive imports supported
- Duplicate detection (same file not included twice)
- Note: This is temporary for bootstrap. Cot 1.0 will have proper Go-style modules.

**Types:**
- `i64`, `int`, `u8`, `bool`, `void`
- `string` (fat pointer: ptr + len)
- `[]T` slices
- `[N]T` arrays (inferred size: `[1, 2, 3]`)
- `struct { fields }`
- `enum: T { variants }`
- `union { variants }`
- `type` aliases
- `Map<K, V>`, `List<T>` (runtime FFI)

**Expressions:**
- Arithmetic: `+ - * /`
- Comparison: `== != < > <= >=`
- Logical: `and or` (short-circuit)
- Boolean: `true false`
- Literals: integers, strings, chars (`'a'`)
- Indexing: `arr[i]`, `s[i]`, `list[i]`
- List indexed assignment: `list[i] = value`
- Slicing: `arr[start:end]`
- Field access: `obj.field`
- Method calls: `obj.method(args)`
- Struct literals: `Point{ .x = 1, .y = 2 }`
- Null coalescing: `x ?? default`
- Address-of: `&x` (get pointer)
- Dereference: `p.*` (access through pointer)
- Pointer field access: `p.*.field`

**Statements:**
- `var x = value;` / `const x = value;`
- `x = value;` (reassignment)
- `x += 1;` (compound assignment)
- `if cond { } else { }`
- `while cond { }`
- `for item in iterable { }`
- `switch value { cases }`
- `return value;`

**Functions:**
- `fn name(params) ReturnType { body }`
- Function calls: `name(args)`

**Builtins:**
- `len(x)` - length of string/array/slice
- `@intFromEnum(e)` - enum to int
- `@enumFromInt(T, i)` - int to enum
- `@maxInt(T)` / `@minInt(T)`
- `print()` / `println()`

### NOT Supported (Must Avoid in Bootstrap) ❌

These features exist in wireframe .cot files but are NOT in Zig compiler yet:

- `if x |val| { }` - optional capture
- `while iter() |item| { }` - while capture
- `for item, i in arr { }` - for with index
- `!T` / `try` / `catch` - error handling
- `fn(T) R` - function types as values
- `defer` - deferred execution
- `?.` - optional chaining
- `@sizeof(T)` / `@alignOf(T)`
- `@intCast(T, v)` - explicit casts

---

## Implementation Phases

### Phase 1: Complete Bootstrap Files (Current Priority)

**Objective:** Create all `*_boot.cot` files using only supported features.

**Order of implementation:**
1. ✅ `token_boot.cot` - Token types (DONE)
2. ✅ `source_boot.cot` - Source positions (DONE)
3. ✅ `scanner_boot.cot` - Lexer (DONE)
4. ✅ `ast_boot.cot` - AST nodes (DONE)
5. ✅ `types_boot.cot` - Type registry (DONE)
6. ✅ `errors_boot.cot` - Error types (DONE)
7. ✅ `parser_boot.cot` - Parser (DONE)
8. ✅ `check_boot.cot` - Type checker (DONE)
9. ✅ `ir_boot.cot` - IR definitions (DONE)
10. ✅ `lower_boot.cot` - Lowering (DONE)
11. ✅ `ssa_boot.cot` - SSA conversion (DONE)
12. ✅ `liveness_boot.cot` - Liveness analysis (DONE)
13. ✅ `codegen/*_boot.cot` - Code generation (ARM64 DONE)
14. ✅ `driver_boot.cot` - Orchestration (DONE)
15. ✅ `main_boot.cot` - Entry point (DONE)

### Phase 2: Add Missing Features (Only If Blocking)

Only add features if they're absolutely required and can't be worked around:

| Feature | Priority | Workaround Available? |
|---------|----------|----------------------|
| For with index | Medium | Use counter variable |
| Bitwise operators | Medium | Runtime FFI calls |
| ~~Address-of `&x`~~ | ~~Low~~ | ✅ **DONE** - Full pointer support added |

### Phase 3: Self-Hosting Test

Once all bootstrap files are complete:

1. Compile `main_boot.cot` with Zig compiler → produces `cot0` binary
2. Use `cot0` to compile `main_boot.cot` → produces `cot1` binary
3. Verify `cot0` and `cot1` produce identical output
4. `cot1` is the first self-hosted cot compiler (Cot 0.3)

### Phase 4: Evolution

After successful self-hosting:

1. Add features to `cot1` using `cot1` itself
2. Each iteration: `cotN` compiles `cotN+1`
3. Eventually support all features in wireframe .cot files
4. Deprecate Zig bootstrap compiler

---

## Post-Bootstrap: Register Allocation Improvement

### Current State (Bootstrap)

The ARM64 codegen uses an ad-hoc register allocation strategy:
- **x0-x7**: Function arguments and return values (ABI-defined)
- **x9-x15**: Caller-saved temporaries (used for intermediate values)
- **x16/x17**: IP (intra-procedure call) scratch registers
- **x19-x28**: Callee-saved (spilled in prologue/restored in epilogue)

**Bootstrap Fix (2026-01-13):** Arithmetic operations (genDiv, genAdd, genSub, genMul) were updated to use x16/x17 as scratch instead of x9. This prevents register clobbering bugs where x9 held a live value needed for later operations.

### Post-Bootstrap: Go's Linear Scan Register Allocation

After bootstrap is complete, implement proper register allocation following Go's approach:

**1. Liveness Analysis** (`src/liveness.zig` / `liveness_boot.cot`)
- Already implemented for basic live range tracking
- Extend to track precise use/def points for each SSA value

**2. Register Allocator** (new file: `src/regalloc.zig`)
- **Linear scan algorithm:**
  1. Sort SSA values by live range start position
  2. Maintain "active" list of values currently in registers
  3. For each value: expire old intervals, allocate register or spill
- **Spill management:**
  - When no registers available, spill least-recently-used value to stack
  - Track spill slots to avoid reloading unnecessarily

**3. Codegen Integration**
- Replace `getValue()` → `getLocation()` that returns register or stack slot
- Remove ad-hoc scratch register usage
- Generate spill/reload code as directed by allocator

**Reference Implementation:**
- Go: `cmd/compile/internal/ssa/regalloc.go`
- Zig: `lib/std/Target.zig` register definitions
- LLVM: `lib/CodeGen/RegAllocLinearScan.cpp` (historical)

**Benefits:**
- Eliminates register clobbering bugs by design
- Better code quality (fewer spills, better register utilization)
- Cleaner codegen (no manual scratch register juggling)

---

## Sync Process

When modifying the Zig compiler:

```
1. Make change to .zig file
2. Run: zig build test
3. Run: ./run_tests.sh
4. Update corresponding *_boot.cot file
5. Test: ./zig-out/bin/cot src/bootstrap/*_boot.cot -o test
6. Run x86_64 tests in Docker
7. Commit both .zig and .cot changes together
```

**Rule:** Never commit a .zig change without updating its .cot counterpart (if it exists).

---

## Wireframe vs Bootstrap Files

There are two sets of .cot files:

| Location | Purpose | Uses |
|----------|---------|------|
| `src/*.cot` | **Wireframes** - Ideal syntax | All language features (future) |
| `src/bootstrap/*.cot` | **Bootstrap** - Minimal syntax | Only supported features |

The wireframe files show what the language WILL look like. The bootstrap files show what we can compile TODAY.

After self-hosting, we can gradually migrate from bootstrap files to wireframe files as we add features.

---

## Current Blockers

| Blocker | Impact | Solution |
|---------|--------|----------|
| ~~No address-of `&x`~~ | ~~Can't take pointers~~ | ✅ **RESOLVED** - Full pointer support |
| No error handling | Can't propagate errors | Return error codes |
| No imports | Single file compilation | File concatenation |

---

## Success Criteria

Cot 0.3 is complete when:

1. All 22 bootstrap .cot files exist and compile
2. The resulting binary can compile the bootstrap files
3. Output is identical whether compiled by Zig or Cot compiler
4. Tests pass on ARM64 and x86_64
5. No features added to Zig compiler that aren't in bootstrap .cot

---

## Notes for Claude

When working on bootstrap:

1. **Check STATUS.md** for current feature support before writing .cot code
2. **Use test_comprehensive.cot** as syntax reference for what works
3. **Avoid** features listed in "NOT Supported" section
4. **Propose workarounds** rather than adding new Zig features
5. **Keep files in sync** - update .cot when changing .zig
