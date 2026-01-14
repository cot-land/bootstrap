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

### BUG-022: Comparison operators crash cot0 (scanner codegen issue)
- **Status:** WORKAROUND IN PLACE
- **Discovered:** 2026-01-14
- **Location:** `scanner_boot.cot` - Zig compiler codegen issue in long if-else chains
- **Description:** Certain comparison operators caused cot0 to crash with SIGBUS (exit 138). The issue was in the scanner's handling of `<` and `>` tokens - the long if-else chain for operator detection triggers a Zig codegen bug that corrupts the stack.
- **Impact:** Without workaround, cannot use `<`, `<=`, `>=` operators in cot0-compiled programs
- **Test:** `tests/bootstrap/test_cmp_greater.cot`
- **Pattern (before fix):**
  - `if 5 == 5` - WORKS
  - `if 5 != 5` - WORKS
  - `if 10 > 5` - CRASHES without workaround
  - `if 5 < 10` - CRASHES without workaround
  - `if 10 >= 5` - CRASHES without workaround
  - `if 5 <= 10` - CRASHES without workaround
- **Root Cause:** Zig compiler codegen bug in scanner_boot.cot. The long if-else chain checking for operators appears to cause stack corruption. Adding any println before the problematic conditions changes stack layout and prevents the crash.
- **Workaround:** Added `println(" ")` before the `<` check (line 407-408) and `>` check (line 413) in scanner_boot.cot. This prevents the crash by changing stack layout or timing.
- **Proper Fix:** Refactor scanner to avoid the problematic if-else chain, or investigate Zig compiler bug

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
- **Status:** FIXED (same root cause as BUG-022)
- **Discovered:** 2026-01-14
- **Location:** `scanner_boot.cot` - Zig compiler codegen issue
- **Description:** cot0 crashed when compiling files with `<` operator. Crash occurred in scanner when tokenizing `<`, not in codegen as initially suspected.
- **Impact:** cot0 could not compile any program using `<`, `<=`, or `>=` operators
- **Test Cases:**
  - `fn main() int { return 42 }` - WORKS
  - `fn main() int { var i: int = 42; return i }` - WORKS
  - `fn main() int { var x: int = 1 < 2; return 42 }` - NOW WORKS (previously crashed)
- **Root Cause:** Same as BUG-022 - Zig compiler codegen bug in scanner_boot.cot's long if-else chain for operator detection. The crash occurred during scanning of `<` token, not during IR/codegen as initially thought.
- **Fix:** Applied same workaround as BUG-022 - added `println(" ")` before the `<` check in scanner_boot.cot
- **Investigation Notes:**
  - Initial theory: codegen or control flow corruption
  - Narrowed down with debug prints: crash happened in parserAdvance -> scanNext when seeing `<` token
  - Confirmed BUG-022 workaround pattern also fixed this issue

### BUG-025: cot0 function calls produce infinite loops (BL jumps to itself)
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `driver_boot.cot`
- **Description:** BL instructions for function calls were emitted with offset 0, causing infinite loops. Two issues:
  1. `emitCallPlaceholder` was called but no relocation was recorded
  2. `applyLocalRelocations` was never called to patch the BL instructions
- **Impact:** Any function call in cot0-compiled programs caused infinite loop
- **Test:** `tests/test_fn_call.cot` (now in /tmp)
- **Fix:**
  1. Added `CallRelocation` struct to track call sites
  2. Modified `generateCall` to record relocations in `call_relocs` list
  3. Added call to `applyLocalRelocations(&obj)` before `writeMachO64`

### BUG-026: cot0 function parameters not spilled to stack
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `driver_boot.cot:generateFunctionFromIR`, `arm64_boot.cot`
- **Description:** ARM64 calling convention passes first 8 args in x0-x7, but `Op.local` reads from stack slots. Parameters were never copied from registers to their stack slots.
- **Impact:** Functions with parameters returned garbage values (read uninitialized stack)
- **Test:** `fn add(a: int, b: int) int { return a + b }` returned wrong values
- **Fix:**
  1. Added `cgSpillParamToStack` function to arm64_boot.cot
  2. Modified `generateFunctionFromIR` to spill x0-x3 to stack slots after prologue

### BUG-027: cot0 field_access returns 0 (node.left appears null)
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `parser_boot.cot:469-486` (was in parseOperand)
- **Description:** When parsing `identifier.identifier` patterns (like `s.x`), the parser in parseOperand was incorrectly handling them as enum variant access. This created field_access nodes using `makeNode()` which sets `left = null_node`. Actual struct field access (like `s.x`) should be handled by parseFieldAccess which sets `left = base` correctly.
- **Impact:** Any struct field access in cot0-compiled programs returned 0 (exit 111)
- **Test:** `tests/bootstrap/test_field_access.cot`
- **Root Cause:** The code at parseOperand lines 469-486 was meant for enum variant access like `NodeTag.field_access`, but it caught ALL `identifier.identifier` patterns including struct field access.
- **Fix:** Removed the special `identifier.identifier` handling from parseOperand. Now ALL `.field` patterns go through parseFieldAccess in the postfix loop, which correctly sets `.left = base`.

### BUG-028: cot0 struct field offsets assume all fields are 8 bytes
- **Status:** WORKAROUND IN PLACE
- **Discovered:** 2026-01-14
- **Location:** `lower_boot.cot:924,933`
- **Description:** `lowerVarStmtAST` uses `struct_size = num_fields * 8` and `field_offset = i * 8`. This is wrong for structs with string fields (16 bytes) or other multi-word types.
- **Impact:** Struct initialization with string fields stores values at wrong offsets; field access reads from wrong offsets
- **Test:** `tests/bootstrap/test_string_struct.cot`
- **Workaround:** Added hardcoded `getNodeFieldOffset`, `getSpanFieldOffset`, `getPosFieldOffset` functions with manually computed offsets for known struct types.
- **Proper Fix:** Implement proper type registry lookup in cot0 lowerer to compute field offsets dynamically.
- **Debug Info:**
  - For `struct { tag: int, name: string, left: int }`, left should be at offset 24 (8+16), not offset 16 (8+8)
  - Disassembly shows same value stored to multiple consecutive slots

### BUG-029: Inconsistent null_node definitions across modules
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `ast_boot.cot:10`, `parser_boot.cot:43`, `check_boot.cot:44`
- **Description:** `null_node` is defined with different types and values in different files:
  - `ast_boot.cot`: `const null_node: u32 = @maxInt(u32)` = 4294967295 (was wrong)
  - `parser_boot.cot`: `const null_node: int = @maxInt(int)` = 9223372036854775807
  - `check_boot.cot`: `const null_node: NodeIndex = @maxInt(i64)` = 9223372036854775807
- **Impact:** When comparing node indices across modules, comparison may fail if one module stores u32 max and another expects i64 max.
- **Test:** `tests/bootstrap/test_field_access.cot`
- **Fix:** Changed `ast_boot.cot` to use `type NodeIndex = int` and `const null_node: int = @maxInt(int)` to match parser_boot.cot and check_boot.cot. All modules now use 64-bit null_node value consistently.

### BUG-030: generateListPush doesn't pass pointer for large structs
- **Status:** OPEN
- **Discovered:** 2026-01-14
- **Location:** `driver_boot.cot:379-386`
- **Description:** For structs >8 bytes, `cot_list_push` expects x1 to contain a POINTER to the struct data. But `generateListPush` just loads the value into x1 via `cgPrepareArg`. This causes only 8 bytes to be pushed instead of the full struct.
- **Impact:** List<Node> and other large struct lists have corrupted data after push operations.
- **Test:** `tests/bootstrap/test_large_struct_list.cot` (TBD)
- **Fix:** In `generateListPush`, check elem_size. If >8 bytes, compute address of value on stack and pass that in x1 instead of loading the value.

### BUG-031: lowerListGet doesn't pass elem_size to codegen
- **Status:** PARTIAL FIX
- **Discovered:** 2026-01-14
- **Location:** `lower_boot.cot:519-523`, callers of lowerListGet
- **Description:** `lowerListGet` signature was updated to take `elem_size` parameter and store it in `node.aux`, but callers haven't been updated to pass the correct elem_size.
- **Impact:** `generateListGet` reads elem_size from aux field, but it's not set correctly, so large struct handling doesn't trigger.
- **Test:** TBD
- **Fix:** Find all callers of lowerListGet and update them to pass the correct element size.

### BUG-032: Multiple ret nodes in same IR block - only last takes effect
- **Status:** WORKAROUND IN PLACE
- **Discovered:** 2026-01-14
- **Location:** `driver.zig:convertToSSA`
- **Description:** When if/else branches both have return statements, the IR has multiple ret nodes in the same block. Only the last ret is processed because ret is a terminator. Earlier rets are silently ignored.
- **Impact:** Functions with `if x { return a } else { return b }` pattern always return from the else branch.
- **Workaround:** Added `terminated_blocks` HashMap to track which blocks have been terminated, skip duplicate terminators.
- **Proper Fix:** Restructure IR lowering to create separate basic blocks for each return path, or ensure proper control flow graph structure.

### BUG-033: cot0 struct arguments to functions return wrong values
- **Status:** OPEN
- **Discovered:** 2026-01-14
- **Location:** `lower_boot.cot` and/or `driver_boot.cot`
- **Description:** When a struct is passed to a function, accessing fields of that struct returns 0 instead of the correct value.
- **Impact:** Functions that take struct arguments can't access their fields correctly
- **Test:** `fn getX(p: Point) int { return p.x }` with Point{.x=42, .y=0} returns 0 instead of 42
- **Root Cause:** TBD - likely related to how struct parameters are handled in callee (spilling, local lookup, or field access)
- **Debug Info:**
  - Struct field access on local variables works (`var p: Point = ...; return p.x` returns 42)
  - The issue is specific to struct parameters

### BUG-034: fullCodeGenInit argument mismatch in driver_boot.cot
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `driver_boot.cot:156`
- **Description:** `fullCodeGenInit` was called with only 1 argument (stack_size) but the function requires 2 arguments (stack_size and locals).
- **Impact:** Bootstrap modules failed to compile with "wrong number of arguments" error
- **Test:** `./test_bootstrap_modules.sh` - main_boot.cot compile test
- **Fix:** Added `func.locals` as second argument to `fullCodeGenInit(func.frame_size, func.locals)`

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
| BUG-024 | cot0 crashes on `<` operator (same as BUG-022) | 2026-01-14 |
| BUG-025 | Function calls produce infinite loops | 2026-01-14 |
| BUG-026 | Function parameters not spilled to stack | 2026-01-14 |
| BUG-027 | cot0 field_access returns 0 (parser bug) | 2026-01-14 |
| BUG-029 | Inconsistent null_node definitions | 2026-01-14 |
| BUG-034 | fullCodeGenInit argument mismatch | 2026-01-14 |

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
