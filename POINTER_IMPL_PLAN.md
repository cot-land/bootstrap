# Pointer Parameters Implementation Plan

## Overview

Adding pointer support to Cot for pass-by-reference semantics:
1. **Pointer type syntax**: `*T` for pointer to T
2. **Address-of operator**: `&x` to get pointer to x
3. **Dereference operator**: `p.*` to access pointed-to value (Zig-style)
4. **Pointer parameter passing**: Already works (pointers are 8 bytes, passed in registers)

## Phase 1: Type System Changes

**File: `src/types.zig`**

- [x] Verify `.pointer` exists in TypeInfo union
- [x] Add helper functions:
  - `isPointer(idx) bool` ✅ Added
  - `pointerElem(idx) TypeIndex` ✅ Added
  - `makePointer(elem) TypeIndex` (already existed)

## Phase 2: Parser Changes

**File: `src/ast.zig`**

- [ ] Add new expression types:
  ```zig
  .addr_of,      // &x - address of expression
  .deref,        // p.* - dereference pointer
  .ptr_type,     // *T - pointer type expression (if not already present)
  ```

**File: `src/parser.zig`**

- [ ] Parse `*T` in type position:
  - In `parseType()`, check for `*` token
  - If found, parse the element type recursively
  - Return a pointer type AST node

- [ ] Parse `&expr` (address-of):
  - In `parseUnaryExpr()`, check for `&` token
  - Parse the operand expression
  - Return an address-of AST node

- [ ] Parse `expr.*` (dereference):
  - In `parsePrimaryExpr()` postfix handling
  - After parsing primary, check for `.` followed by `*`
  - Return a dereference AST node

## Phase 3: Type Checker Changes

**File: `src/check.zig`**

- [ ] **Type expression handling** (`checkTypeExpr`):
  - Handle `.ptr_type` - create pointer type from element type

- [ ] **Address-of checking** (`checkAddrOf`):
  - Verify operand is an lvalue (variable, field, array element)
  - Result type is `*T` where T is operand type
  - Error if taking address of rvalue

- [ ] **Dereference checking** (`checkDeref`):
  - Verify operand is a pointer type
  - Result type is the pointer's element type
  - Error: "cannot dereference non-pointer type"

- [ ] **Assignment through pointer**:
  - `p.* = value` - verify p is `*T` (mutable), value is T

- [ ] **Parameter type checking**:
  - Allow `*T` as parameter type
  - Track mutability for error messages

## Phase 4: IR Lowering Changes

**File: `src/ir.zig`**

- [ ] Add new IR operations:
  ```zig
  .local_addr,   // Get address of local variable
  .field_addr,   // Get address of struct field
  .ptr_load,     // Load through pointer
  .ptr_store,    // Store through pointer
  ```

**File: `src/lower.zig`**

- [ ] **Lower `&x` (address-of)**:
  - If x is a local variable: emit `local_addr` IR op
  - If x is a field: emit `field_addr` IR op
  - Result is pointer to the location

- [ ] **Lower `p.*` (dereference)**:
  - For read: emit `ptr_load` IR op
  - For write (assignment target): emit `ptr_store` IR op

- [ ] **Lower pointer parameters**:
  - Same as regular parameters (pointers are 8 bytes)
  - Caller passes address, callee receives pointer

## Phase 5: SSA Conversion

**File: `src/ssa.zig`**

- [ ] Add new SSA operations:
  ```zig
  .addr,         // Get address of local
  .load_ptr,     // Load from pointer
  .store_ptr,    // Store to pointer
  ```

**File: `src/driver.zig`**

- [ ] Convert IR ops to SSA:
  - `local_addr` → SSA `addr` op with local index
  - `ptr_load` → SSA `load_ptr` op
  - `ptr_store` → SSA `store_ptr` op

## Phase 6: Code Generation

**File: `src/codegen/arm64_codegen.zig`**

- [ ] **`genAddr`**: Compute address of local
  - `add dest, fp, #offset` (or sp-relative)

- [ ] **`genLoadPtr`**: Load through pointer
  - Get pointer value to register
  - `ldr dest, [ptr_reg]` (with correct width based on pointee type)

- [ ] **`genStorePtr`**: Store through pointer
  - Get pointer and value to registers
  - `str value_reg, [ptr_reg]` (with correct width)

## Phase 7: Update check_boot.cot

Once pointers work, update the failing functions:

```cot
fn checkerPushScope(checker: *Checker) void {
    // Now mutations persist!
    checker.*.current_scope_idx = len(checker.*.scopes)
    // ...
}

fn checkerPopScope(checker: *Checker) void {
    var idx: int = checker.*.current_scope_idx
    var current: Scope = checker.*.scopes.get(idx)
    checker.*.current_scope_idx = current.parent_idx
}
```

## Testing Strategy

1. **Unit tests** for each phase (in Zig test blocks)
2. **Integration tests**:
   - `test_pointer_basic.cot` - simple pointer operations
   - `test_pointer_param.cot` - pointer parameters
   - `test_pointer_struct.cot` - pointers to structs

## Execution Order

| Step | Phase | File(s) | Description | Status |
|------|-------|---------|-------------|--------|
| 1 | 1 | types.zig | Add pointer type helpers | [x] |
| 2 | 2 | ast.zig | Add AST nodes for pointer ops | [x] |
| 3 | 2 | parser.zig | Parse `*T`, `&x`, `p.*` | [x] |
| 4 | 3 | check.zig | Type check pointer operations | [x] |
| 5 | 4 | ir.zig | Add IR operations | [x] |
| 6 | 4 | lower.zig | Lower pointer ops to IR | [x] |
| 7 | 5 | ssa.zig | Add SSA operations | [x] |
| 8 | 5 | driver.zig | Convert IR to SSA | [x] |
| 9 | 6 | arm64_codegen.zig | Generate machine code | [x] |
| 10 | 7 | tests/ | Add test files | [x] |
| 11 | 7 | check_boot.cot | Update to use pointers | [x] |

## Additional Work Completed

- [x] Pointer assignment (`p.* = value`) - implemented in lowerAssignment
- [x] Field access through pointer (`p.*.field`) - implemented with ptr_field and ptr_field_store
- [x] Integer-keyed map support - added cot_map_set_int, cot_map_get_int, cot_map_has_int
- [x] len() for pointer field access - handled in lowerBuiltinCall

## Research Notes

### From Go Compiler:
- Pointer types use `Ptr` wrapper struct with element type reference
- Caching of pointer types for efficiency
- All pointers are `PtrSize` (8 bytes on 64-bit)
- `intRegs = 1` for ABI (single register for pointer)
- `tcStar` handles dereference, validates operand is pointer

### From Zig Compiler:
- `PtrType` in InternPool with flags for const/mutable
- Different sizes: `.one` (single), `.many`, `.slice`, `.c`
- `is_const` flag distinguishes `*T` from `*const T`
- `childType()` extracts pointed-to type
- `isSinglePointer()` for validation

### Design Decisions for Cot:
- Use Zig-style `p.*` for dereference (clearer than `*p`)
- Start with single pointers only (`.one` equivalent)
- No const pointers initially (can add later)
- Pointers passed in registers like other 8-byte values
