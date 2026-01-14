# Bootstrap Bug Tracking

**Process:** Discover bug -> Add to this list -> Add a test -> Fix the bug -> Mark complete

This is the ONLY way to achieve a stable self-hosting compiler.

---

## Active Bugs

### BUG-001: Transitive imports - VERIFIED WORKING
- **Status:** CLOSED (not a bug)
- **Discovered:** 2026-01-14
- **Location:** Import chain: `parser_boot.cot` -> `scanner_boot.cot` -> `token_boot.cot`
- **Description:** Suspected transitive imports weren't working. Investigation confirmed they DO work correctly.
- **Impact:** None - feature works as expected
- **Test:** `tests/test_return.cot` now passes with cot0 (returns 42)
- **Resolution:** Transitive imports work. The original parsing issue was unrelated debug output confusion.

### BUG-002: `lowerVarStmtNode` uses wrong field
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `main_boot.cot:439`
- **Description:** Parser stores initializer in `node.left` but lowering reads `node.right`
- **Impact:** Variable initialization broken (`var x: int = 42` won't initialize x)
- **Test:** `tests/test_var_init.cot`
- **Fix:** Changed `node.right` to `node.left`

### BUG-003: Function call args not stored
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `parser_boot.cot:799`
- **Description:** `parseCallExpr` creates args list but never assigns to `node.args`
- **Impact:** Function calls with arguments won't work
- **Test:** `tests/test_call_args.cot`
- **Fix:** Added `node.args = args` before returning

### BUG-004: Function parameters parsed but discarded
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `parser_boot.cot:1582-1614`
- **Description:** Parameters are parsed in loop but never stored in fn_decl node
- **Impact:** Functions with parameters won't work
- **Test:** `tests/test_fn_params.cot`
- **Fix:** Added `param` NodeTag, store params in list, assign to `node.args`

### BUG-005: Struct init fields not stored
- **Status:** PARTIAL FIX (deferred)
- **Discovered:** 2026-01-14
- **Location:** `parser_boot.cot:624-672`
- **Description:** Struct field initializers were parsed but not stored in node
- **Impact:** Struct initialization won't work in cot0-compiled programs
- **Test:** `tests/test_struct_init.cot`
- **Fix (Parser):** Added `struct_init_field` NodeTag, parse each `.field = value` into field nodes, store in `struct_init.args`
- **Remaining:** Lowering needs TypeRegistry with struct definitions to get field offsets
- **Note:** Deferred - cot0 currently only compiles simple programs. Struct init in bootstrap .cot files is compiled by Zig compiler, not cot0.

### BUG-006: Duplicate entry block in IR
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `ir_boot.cot:534` and `lower_boot.cot:856`
- **Description:** `irFuncBuilderInit` creates block 0, then `lowerFnDeclNode` created block 1
- **Impact:** Wastes memory, block 0 unused
- **Test:** N/A (not a correctness bug)
- **Fix:** Removed duplicate block creation in `lowerFnDeclNode` - now uses block 0 from init

### BUG-007: Slice expression in struct init field returns wrong value
- **Status:** FIXED (was never reproducible with isolated test)
- **Discovered:** 2026-01-14
- **Location:** Zig compiler - `lower.zig` struct initialization handling
- **Description:** Suspected that slice expressions directly in struct init fields returned wrong values.
- **Impact:** None - issue couldn't be reproduced
- **Test:** `tests/test_slice_in_struct.cot` - passes
- **Resolution:** Removed workaround from `parser_boot.cot:parserAdvance` - direct slice in struct init now works correctly. The original issue may have been caused by a different bug that has since been fixed.

### BUG-008: Chained pointer field access for strings crashes
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `src/codegen/arm64_codegen.zig:genPtrField`
- **Description:** When accessing a string field through a pointer dereference chain (`ptr.*.struct_field.string_field`), only the first 8 bytes (ptr) were loaded. The length was set to 0, causing `@fileRead` to receive an empty path and crash.
- **Impact:** cot0 bootstrap compiler crashed when trying to read input files
- **Test:** `tests/test_chained_ptr_field.cot`
- **Fix:** In `genPtrField`, for multi-word fields (>8 bytes), load both words to a temp stack slot instead of just one register. This allows `loadSliceToRegs` to find both ptr and len.

### BUG-009: field_value type not resolved for non-local bases
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `src/lower.zig:lowerFieldAccess`
- **Description:** When accessing fields on non-local values (e.g., `list.get(0).field`), the type and offset were not resolved, causing size=0 in codegen. This led to incorrect code generation where stack data was treated as pointers.
- **Impact:** Any code with `list.get().field` or similar patterns would crash
- **Test:** `tests/test_list_get_field.cot`, `tests/test_fn_call.cot`
- **Fix:** Modified fallback in lowerFieldAccess to get base type from expr_types and resolve field offset/type properly

### BUG-010: cot0 local variable lookup uses invalid map handle
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `arm64_codegen.zig:genPtrLoad`, `amd64_codegen.zig:genPtrLoad`
- **Description:** When a pointer to a large struct (>8 bytes) was dereferenced (`ptr.*`) for use as a function argument, `genPtrLoad` only loaded the first 8 bytes into a register. When passing the address of this partial copy to a function expecting the full struct, the callee would read garbage data.
- **Impact:** cot0 crashed when calling functions with large struct by-value parameters (like `irFuncBuilderLookupLocal(fb.*, name)`)
- **Test:** `tests/test_fn_call.cot`
- **Fix:** Modified `genPtrLoad` to copy the entire struct to a stack slot for types >8 bytes, then return that stack location as the MCValue. Applied to both ARM64 and AMD64 codegen.

### BUG-011: cot0 codegen doesn't handle function calls
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `driver_boot.cot:generateNodeFromIR`, `arm64_boot.cot`
- **Description:** The `generateNodeFromIR` function didn't handle `Op.call`, and `cgGenCallDirect` was missing.
- **Impact:** cot0 couldn't compile programs with function calls
- **Test:** `tests/test_fn_call.cot`
- **Fix:** Added `cgGenCallDirect` function and `Op.call` handling in driver

### BUG-012: Function parameters not added to local_map in cot0 lowerer
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `lower_boot.cot:lowerFnDeclNode`
- **Description:** The function `lowerFnDeclNode` creates an IRFuncBuilder but doesn't add function parameters to the local_map. When the function body references parameters, they can't be found.
- **Impact:** cot0 can't compile functions with parameters - identifiers like `a` and `b` are not found
- **Test:** `tests/test_fn_call.cot`
- **Fix:** Added parameter handling loop in `lowerFnDeclNode` to iterate over `fn_decl.args` and call `irFuncBuilderAddParam`

### BUG-013: Call relocations not added to object file
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `driver_boot.cot`, `object_boot.cot`
- **Description:** Function call instructions (BL) were emitted but relocations weren't added to the object file, causing incorrect branch targets.
- **Impact:** Function calls jumped to wrong addresses, causing crashes
- **Test:** `tests/test_fn_call.cot`
- **Fix:** Added call relocation tracking in codegen and `applyLocalRelocations` in object writer

### BUG-016: String params overflow x0-x7 registers
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `arm64_boot.cot:cgGenCallDirect`
- **Description:** String parameters use 2 registers (ptr+len). With too many int params after a string, args overflowed x0-x7.
- **Impact:** Function calls with string + multiple int params corrupted registers
- **Test:** `tests/test_fn_call.cot`
- **Fix:** Reordered `cgGenCallDirect` params to put string (func_name) first

### BUG-017: List index assignment fails without preceding function call
- **Status:** OPEN (workaround in place)
- **Discovered:** 2026-01-14
- **Location:** Zig compiler codegen for `list[idx] = value`
- **Description:** In `applyLocalRelocations`, the `sec.data[reloc_offset] = b0` assignments produce incorrect values unless preceded by a function call (e.g., `println("")`).
- **Impact:** BL instruction encoding was corrupted (0x97b0ffe3 instead of 0x97ffffe3)
- **Test:** `tests/test_fn_call.cot`
- **Workaround:** Added `println("")` at start of `applyLocalRelocations`
- **Fix:** TBD - needs investigation in Zig compiler's list_set codegen

### BUG-018: cot1 crashes in parserExpect when compiling main_boot.cot
- **Status:** BLOCKED (depends on BUG-019, BUG-020, BUG-021)
- **Discovered:** 2026-01-14
- **Location:** `parser_boot.cot:parserExpect`
- **Description:** cot1 (self-hosted compiler) crashes with SEGFAULT when compiling main_boot.cot.
- **Impact:** cot1 cannot compile itself - blocks full self-hosting
- **Root Cause:** More fundamental bugs (var declarations, enums, switch) need fixing first

### BUG-019: var declarations crash cot0
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `lower_boot.cot` or `driver_boot.cot`
- **Description:** `var x: int = 10` causes cot0 to crash with SIGBUS (exit 138)
- **Impact:** Cannot use local variables in cot0-compiled programs
- **Test:** `tests/bootstrap/test_var_decl.cot`
- **Fix:** Issue resolved - var declarations now work correctly in cot0

### BUG-020: enum usage crashes cot0
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** Parser or lowerer
- **Description:** Any enum declaration or usage causes cot0 to crash
- **Impact:** Cannot use enums in cot0-compiled programs
- **Test:** `tests/bootstrap/test_enum_usage.cot`
- **Fix:** Issue resolved - enum declarations and usage now work correctly in cot0

### BUG-021: switch expression returns wrong values
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `parser_boot.cot:parseSwitchExpr`, `lower_boot.cot:lowerSwitchExpr`
- **Description:** `switch x { 1 => 10, 2 => 20, else => 0 }` with x=2 returns 2 instead of 20
- **Impact:** Switch expressions produce incorrect results
- **Test:** `tests/bootstrap/test_switch_expr.cot`
- **Fix:** Three-part fix:
  1. Parser: Modified `parseSwitchExpr` to store case values and bodies using `switch_case` nodes in `node.args`
  2. Lowerer: Added `lowerSwitchExpr` function that generates nested `select` operations
  3. Codegen: Added `generateSelect` function and fixed `encodeCondSelect` (missing bit 23) and `cgLoadToReg` (scratch register clobbering)

### BUG-022: Comparison operators `>`, `>=`, `<=` crash cot0
- **Status:** WORKAROUND IN PLACE
- **Discovered:** 2026-01-14
- **Location:** `scanner_boot.cot` - Zig compiler codegen issue
- **Description:** `if 10 > 5 { ... }` crashes with SIGBUS (exit 138). `<` and `==` work fine.
- **Impact:** Cannot use `>`, `>=`, `<=` operators in cot0-compiled programs without workaround
- **Test:** `tests/bootstrap/test_cmp_greater.cot`
- **Pattern:**
  - `if 5 < 10` - WORKS
  - `if 5 == 5` - WORKS
  - `if 10 > 5` - CRASHES (exit 138 SIGBUS) without workaround
  - `if 10 >= 5` - CRASHES (exit 138 SIGBUS) without workaround
  - `if 5 <= 10` - CRASHES (exit 139 SIGSEGV) without workaround
- **Root Cause:** Suspected Zig compiler codegen bug when handling `>` character (code 62) in scanner
- **Workaround:** Added `println(" ")` in scanner_boot.cot line 413. This prevents the crash by changing stack layout or timing.
- **Proper Fix:** Investigate Zig compiler's codegen for scanner_boot.cot

### BUG-023: cot0 branch codegen produces illegal opcodes
- **Status:** OPEN
- **Discovered:** 2026-01-14
- **Location:** `driver_boot.cot` generateBranch/generateFunctionFromIR
- **Description:** cot0 generates garbage opcodes (e.g., 0x0f0e0dc0) instead of proper ARM64 branch instructions. Also fails to load condition values before comparisons.
- **Impact:** Any if statement in cot0-compiled programs produces illegal instructions (SIGILL exit 132)
- **Test:** `fn main() int { if true { return 42 } return 1 }` returns SIGILL
- **Root Cause:** Branch patching or instruction encoding bugs in driver_boot.cot
- **Debug Info:**
  ```
  Expected: B.cond or B instruction
  Actual: 0x0f0e0dc0 (unknown opcode - looks like ASCII garbage)
  ```

### BUG-024: cot0 crashes on if statements (control flow corruption)
- **Status:** OPEN
- **Discovered:** 2026-01-14
- **Location:** `driver_boot.cot` - comparison or branch codegen
- **Description:** cot0 crashes when compiling files with if statements. Simple programs (return literal, var decl) work. PC jumps to invalid addresses like 0x15.
- **Impact:** cot0 cannot compile any program with control flow (if, while, etc.)
- **Test Cases:**
  - `fn main() int { return 42 }` - WORKS
  - `fn main() int { var i: int = 42; return i }` - WORKS
  - `fn main() int { if 1 < 2 { return 42 } return 1 }` - CRASHES (exit 138/SIGBUS, PC=0x15)
- **Root Cause:** Stack corruption or incorrect codegen for comparisons/branches. The program counter jumps to small addresses like 0x15 which could be enum values or struct field offsets being misinterpreted as code addresses.
- **Note:** This is separate from BUG-023 (illegal branch opcodes) - here the instructions are valid but the data/control flow is corrupted.
- **Previous Investigation:** Initially thought to be BUG-024 (list element size), but that was ruled out - the Zig compiler handles List<LargeStruct> correctly. The issue is in cot0's own codegen for control flow.

---

## Completed Bugs

| Bug ID | Description | Fixed Date |
|--------|-------------|------------|
| BUG-002 | lowerVarStmtNode wrong field | 2026-01-14 |
| BUG-003 | Call args not stored | 2026-01-14 |
| BUG-004 | Fn params discarded | 2026-01-14 |
| BUG-006 | Duplicate entry block in IR | 2026-01-14 |
| BUG-007 | Slice in struct init (was not reproducible) | 2026-01-14 |
| BUG-008 | Chained pointer field access for strings | 2026-01-14 |
| BUG-009 | field_value type not resolved for non-local bases | 2026-01-14 |
| BUG-010 | genPtrLoad only loaded 8 bytes for large structs | 2026-01-14 |
| BUG-011 | cot0 codegen doesn't handle function calls | 2026-01-14 |
| BUG-012 | Function parameters not in local_map | 2026-01-14 |
| BUG-013 | Call relocations not added to object file | 2026-01-14 |
| BUG-016 | String params overflow x0-x7 registers | 2026-01-14 |
| BUG-019 | var declarations crash cot0 | 2026-01-14 |
| BUG-020 | enum usage crashes cot0 | 2026-01-14 |
| BUG-021 | switch expression returns wrong values | 2026-01-14 |

---

## Bug Template

```markdown
### BUG-XXX: Short description
- **Status:** OPEN / FIXED
- **Discovered:** YYYY-MM-DD
- **Location:** `file.cot:line`
- **Description:** What's wrong
- **Impact:** What breaks because of this
- **Test:** `tests/test_xxx.cot`
- **Fix:** How it was/will be fixed
```

---

## Testing Commands

```bash
# Build Zig compiler
zig build

# Compile cot0 bootstrap
./zig-out/bin/cot src/bootstrap/main_boot.cot -o cot0

# Test specific bug fix
./cot0 tests/test_xxx.cot -o test.o
zig cc -o test test.o && ./test
echo "Exit: $?"

# Full test suite
./run_tests.sh
```
