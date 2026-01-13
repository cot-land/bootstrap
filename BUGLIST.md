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
- **Status:** OPEN
- **Discovered:** 2026-01-14
- **Location:** `ir_boot.cot:534` and `main_boot.cot:544`
- **Description:** `irFuncBuilderInit` creates block 0, then `lowerFnDecl` creates block 1
- **Impact:** Wastes memory, block 0 unused
- **Test:** N/A (not a correctness bug)
- **Fix:** Remove one of the block creations

### BUG-007: Slice expression in struct init field returns wrong value
- **Status:** OPEN (workaround applied)
- **Discovered:** 2026-01-14
- **Location:** Zig compiler - `lower.zig` struct initialization handling
- **Description:** When a slice expression like `content[start:end]` is used directly in a struct field initialization, it returns wrong/empty values. Extracting to a local variable first works correctly.
- **Impact:** Struct fields with inline slice expressions get wrong values
- **Test:** `tests/test_slice_in_struct.cot`
- **Workaround Applied:** In `parser_boot.cot:parserAdvance`, extracted slice to local var before struct init
- **Proper Fix:** Investigate lowering of struct init with complex field expressions in Zig compiler

```cot
// BROKEN - returns empty/wrong value:
return ParserState{ .tok_text = content[start:end], ... }

// WORKS - extract first:
var slice_text: string = content[start:end]
return ParserState{ .tok_text = slice_text, ... }
```

### BUG-008: Chained pointer field access for strings crashes
- **Status:** FIXED
- **Discovered:** 2026-01-14
- **Location:** `src/codegen/arm64_codegen.zig:genPtrField`
- **Description:** When accessing a string field through a pointer dereference chain (`ptr.*.struct_field.string_field`), only the first 8 bytes (ptr) were loaded. The length was set to 0, causing `@fileRead` to receive an empty path and crash.
- **Impact:** cot0 bootstrap compiler crashed when trying to read input files
- **Test:** `tests/test_chained_ptr_field.cot`
- **Fix:** In `genPtrField`, for multi-word fields (>8 bytes), load both words to a temp stack slot instead of just one register. This allows `loadSliceToRegs` to find both ptr and len.

---

## Completed Bugs

| Bug ID | Description | Fixed Date |
|--------|-------------|------------|
| BUG-002 | lowerVarStmtNode wrong field | 2026-01-14 |
| BUG-003 | Call args not stored | 2026-01-14 |
| BUG-004 | Fn params discarded | 2026-01-14 |
| BUG-008 | Chained pointer field access for strings | 2026-01-14 |

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
