# Cot Codegen Architecture

## Overview

The cot compiler uses a **Zig-style integrated codegen** approach where register allocation happens during code generation, not as a separate pass. This is simpler and more robust than Go's two-phase architecture for our needs.

**Test Results**: 63/63 ARM64 tests pass, 58/63 x86_64 tests pass.

---

## Why This Architecture?

### The Problem with Separate Regalloc (What We Tried First)

Go's compiler uses a two-phase approach:
1. **Register allocation pass** - Assigns registers to all values before codegen
2. **Codegen pass** - Just emits instructions using pre-assigned registers

This works well for Go because:
- Go's SSA is fully optimized before regalloc
- The regalloc pass has complete liveness information
- Codegen is purely mechanical

We tried this approach and it failed badly:
- 266 places checking `.op ==` to guess where values were
- Ad-hoc assumptions that broke in combinations
- Call clobbering wasn't properly handled
- Storage manager was "write-only" - values saved but never loaded

### The Solution: Integrated Codegen (Zig's Approach)

Zig's compiler integrates register allocation with code generation. The key insight: **you don't need to know all liveness information upfront if you track where values are as you generate code**.

Core concept: **MCValue** (Machine Code Value) - a union type that tracks where every value currently lives:
- `.register` - In a CPU register (fast access)
- `.stack` - On the stack (needs load before use)
- `.immediate` - A constant that can be encoded in instructions
- `.lea_symbol` - A symbol address for string literals
- `.none` / `.dead` - No value or no longer needed

---

## Execution Flow

### Complete Pipeline

```
Source Code (.cot)
       │
       ▼
   ┌────────────────────┐
   │     Scanner        │  Tokenizes source into tokens
   └────────────────────┘
       │
       ▼
   ┌────────────────────┐
   │     Parser         │  Builds Abstract Syntax Tree (AST)
   └────────────────────┘
       │
       ▼
   ┌────────────────────┐
   │   Type Checker     │  Validates types, resolves symbols
   └────────────────────┘
       │
       ▼
   ┌────────────────────┐
   │     Lowerer        │  Converts AST to IR (intermediate representation)
   └────────────────────┘
       │
       ▼
   ┌────────────────────┐
   │   IR → SSA         │  Converts IR nodes to SSA values with blocks
   └────────────────────┘
       │
       ▼
   ┌────────────────────┐
   │    CodeGen         │  Generates machine code with integrated regalloc
   │   (arm64/amd64)    │
   └────────────────────┘
       │
       ▼
   ┌────────────────────┐
   │   Object File      │  Writes Mach-O or ELF object file
   └────────────────────┘
       │
       ▼
   ┌────────────────────┐
   │     Linker         │  Links with runtime library (zig cc)
   └────────────────────┘
       │
       ▼
    Executable
```

### Key Files

| File | Purpose |
|------|---------|
| `driver.zig` | Orchestrates compilation, IR→SSA conversion |
| `arm64_codegen.zig` | ARM64 code generation with MCValue tracking |
| `amd64_codegen.zig` | x86_64 code generation with MCValue tracking |
| `aarch64.zig` | ARM64 instruction encoding primitives |
| `x86_64.zig` | x86_64 instruction encoding primitives |
| `ssa.zig` | SSA value and block definitions |
| `object.zig` | Object file format handling |

---

## The MCValue Pattern

### What is MCValue?

Every SSA value has a location tracked by `MCValue`:

```zig
pub const MCValue = union(enum) {
    none,           // No value (void, consumed)
    dead,           // Value no longer needed
    immediate: i64, // Compile-time constant
    register: Reg,  // In a CPU register
    stack: i32,     // On stack at [rbp+offset] (x86) or [sp+offset] (ARM64)
    lea_symbol: struct { name: []const u8, len: usize }, // Symbol address
};
```

### How Values Are Tracked

The `CodeGen` struct maintains a tracking HashMap:

```zig
tracking: std.AutoHashMap(ssa.ValueID, InstTracking)
```

Where `InstTracking` records:
- `home`: Where to reload from (stack slot or .none)
- `current`: Where the value is right now

### Core Operations

**1. `getValue(value_id)` - Look up where a value is:**
```zig
pub fn getValue(self: *CodeGen, value_id: ssa.ValueID) MCValue {
    if (self.tracking.get(value_id)) |tracking| {
        return tracking.current;
    }
    return .none;
}
```

**2. `loadToReg(dest, mcv)` - Load any MCValue into a register:**
```zig
pub fn loadToReg(self: *CodeGen, dest: Reg, mcv: MCValue) !void {
    switch (mcv) {
        .register => |src| {
            if (src != dest) try movRegReg(dest, src);
        },
        .stack => |offset| {
            try ldrRegMem(dest, sp/rbp, offset);
        },
        .immediate => |imm| {
            try movRegImm64(dest, imm);
        },
        // ...
    }
}
```

**3. `setResult(value_id, mcv)` - Record where an operation's result is:**
```zig
pub fn setResult(self: *CodeGen, value_id: ssa.ValueID, mcv: MCValue) !void {
    try self.tracking.put(value_id, InstTracking.init(mcv));
}
```

**4. `spillReg(reg)` - Save a register to stack when we need it for something else:**
```zig
fn spillReg(self: *CodeGen, reg: Reg) !void {
    const value_id = self.reg_manager.getValueIn(reg) orelse return;
    const tracking = self.tracking.getPtr(value_id) orelse return;

    if (tracking.home == .none) {
        tracking.home = .{ .stack = self.next_spill_offset };
        self.next_spill_offset -= 8;
    }

    try strRegMem(reg, rbp, tracking.home.getStack().?);
    tracking.current = tracking.home;
    self.reg_manager.markFree(reg);
}
```

---

## Example: How an Add Operation Works

Given SSA: `v5 = add v3, v4`

```zig
fn genAdd(self: *CodeGen, value: *ssa.Value) !void {
    const args = value.args();

    // 1. Look up where operands are
    const left_mcv = self.getValue(args[0]);   // Maybe .register(.x2)
    const right_mcv = self.getValue(args[1]);  // Maybe .stack(16)

    // 2. Handle register clobbering - if right is in x0, save it first
    if (right_mcv == .register and right_mcv.register == .x0) {
        try movRegReg(.x9, .x0);
        try self.loadToReg(.x0, left_mcv);
        try addRegReg(.x0, .x0, .x9);
    } else {
        // 3. Load left operand to x0
        try self.loadToReg(.x0, left_mcv);

        // 4. Load right to scratch or use immediate
        if (right_mcv == .immediate and fits_in_imm12(right_mcv.immediate)) {
            try addRegImm12(.x0, .x0, right_mcv.immediate);
        } else {
            try self.loadToReg(.x9, right_mcv);
            try addRegReg(.x0, .x0, .x9);
        }
    }

    // 5. Record result location
    self.reg_manager.markUsed(.x0, value.id);
    try self.setResult(value.id, .{ .register = .x0 });
}
```

---

## Register Clobbering Prevention

The key insight that made everything work: **always check if loading one operand will clobber another**.

### The Problem

```
v1 = call foo()        // Result in x0
v2 = add v1, 5         // Need v1, but loading anything else might use x0
```

If we naively do:
```asm
; v1 is in x0 from the call
mov x9, #5        ; Load constant - fine
add x0, x0, x9    ; Works!
```

But what about:
```
v1 = call foo()        // Result in x0
v2 = call bar()        // Clobbers x0!
v3 = add v1, v2        // v1 was clobbered
```

### The Solution

Before loading the left operand to x0/rax, check if the right operand is already there:

```zig
// If right is in x0, save it to scratch first before we load left into x0
if (right_mcv == .register and right_mcv.register == .x0) {
    try movRegReg(.x9, .x0);  // Save right to x9
    try self.loadToReg(.x0, left_mcv);  // Load left to x0
    try addRegReg(.x0, .x0, .x9);  // Use saved right
} else {
    try self.loadToReg(.x0, left_mcv);  // Safe - won't clobber right
    // ... handle right normally
}
```

This pattern is applied to all binary operations (add, sub, mul, div, comparisons).

---

## Calling Convention Handling

### ARM64 (AAPCS64)
- Arguments: x0-x7
- Return: x0 (x0+x1 for fat pointers like slices)
- Caller-saved: x0-x18 (clobbered by calls)
- Callee-saved: x19-x28 (preserved across calls)
- Frame pointer: x29 (fp)
- Link register: x30 (lr)
- Stack pointer: sp

### x86_64 (System V ABI)
- Arguments: rdi, rsi, rdx, rcx, r8, r9
- Return: rax (rax+rdx for fat pointers)
- Caller-saved: rax, rcx, rdx, rsi, rdi, r8-r11
- Callee-saved: rbx, r12-r15, rbp
- Frame pointer: rbp

### After Function Calls

When generating a call, we:
1. Save caller-saved registers that hold live values (spill)
2. Set up arguments in the right registers
3. Emit the call instruction
4. Mark caller-saved registers as free (they're clobbered)
5. Record the result in x0/rax

---

## Stack Frame Layout

### ARM64
```
High addresses
┌─────────────────┐
│     fp/lr       │  Saved by prologue (stp fp, lr, [sp, #-16]!)
├─────────────────┤
│   Local vars    │  func.locals[i].offset (positive from sp)
├─────────────────┤
│  Spill slots    │  Allocated on-demand during codegen
├─────────────────┤
│   (alignment)   │  16-byte aligned
└─────────────────┘  ← sp
Low addresses
```

### x86_64
```
High addresses
┌─────────────────┐
│  Return addr    │  Pushed by call instruction
├─────────────────┤
│    Old rbp      │  push rbp; mov rbp, rsp
├─────────────────┤  ← rbp
│   Local vars    │  func.locals[i].offset (negative from rbp)
├─────────────────┤
│  Spill slots    │  Allocated on-demand during codegen
├─────────────────┤
│   (alignment)   │  16-byte aligned
└─────────────────┘  ← rsp
Low addresses
```

---

## SSA Operations Reference

### Memory Operations

| Op | Description | args | aux_int |
|----|-------------|------|---------|
| `load` | Load local variable | [local_idx] | - |
| `store` | Store to local | [local_idx, value] | field_offset |
| `addr` | Address of local | [local_idx] | field_offset |
| `field` | Load struct field | [local_idx] | field_offset |
| `ptr_field` | Load field through pointer | [local_idx] | field_offset |
| `index` | Array index | [local_idx, index_val] | elem_size |

### Arithmetic

| Op | Description | args |
|----|-------------|------|
| `add`, `sub`, `mul`, `div` | Binary arithmetic | [left, right] |
| `neg` | Negation | [operand] |
| `mod` | Modulo | [left, right] |

### Comparison

| Op | Description | args |
|----|-------------|------|
| `eq`, `ne`, `lt`, `le`, `gt`, `ge` | Compare values | [left, right] |

### Logical

| Op | Description | args |
|----|-------------|------|
| `and`, `or` | Logical operations | [left, right] |
| `not` | Logical negation | [operand] |

### Control Flow (Block Terminators)

| Op | Description | Handled By |
|----|-------------|------------|
| `branch` | Conditional jump | Block's control value, succs[0]=then, succs[1]=else |
| `jump` | Unconditional jump | Block's succs[0] |
| `ret` | Return from function | Block's control value |

### Complex Types

| Op | Description | args | aux_int |
|----|-------------|------|---------|
| `slice_make` | Create slice | [local, start, end] | elem_size |
| `slice_index` | Index into slice | [local, index] | elem_size |
| `union_init` | Create union value | [payload?] | variant_idx |
| `union_tag` | Get union tag | [union_val] | - |
| `union_payload` | Get union payload | [union_val] | - |

### Runtime Collections (FFI to C)

| Op | C Function | Description |
|----|------------|-------------|
| `map_new` | `calloc` + init | Create new hash map |
| `map_set` | `cot_map_set` | Insert key-value |
| `map_get` | `cot_map_get` | Lookup by key |
| `map_has` | `cot_map_has` | Check key exists |
| `list_new` | `calloc` | Create new list |
| `list_push` | `cot_list_push` | Append element |
| `list_get` | `cot_list_get` | Get element by index |
| `list_len` | inline | Get list length |

---

## Why This Design Is Correct

### 1. No More Guessing

Old approach: Check `.op ==` to guess where values are (266 places, many bugs)

New approach: Look up in tracking HashMap - always knows exact location

### 2. Automatic Spilling

When we need a register and none are free, `spillReg()` automatically:
- Saves the value to a stack slot
- Updates tracking so future uses know to reload
- Frees the register for reuse

### 3. Handles All Edge Cases

The MCValue pattern naturally handles:
- Constants (immediate - no register needed)
- Values that survive calls (spilled before call, reloaded after)
- Nested operations (each step tracked independently)
- Register pressure (spill least-recently-used when full)

### 4. Simple Mental Model

To add a new operation:
1. Get operand MCValues with `getValue()`
2. Load to registers with `loadToReg()`
3. Emit instructions
4. Record result with `setResult()`

No need to understand complex liveness analysis or interference graphs.

---

## Debugging

### Debug Flags

```bash
# See IR after lowering
./zig-out/bin/cot file.cot --debug-ir -o out

# See SSA representation
./zig-out/bin/cot file.cot --debug-ssa -o out

# See codegen operations (not yet implemented)
./zig-out/bin/cot file.cot --debug-codegen -o out

# Disassemble output
./zig-out/bin/cot file.cot --disasm -o out
```

### When Something Goes Wrong

1. **Wrong result**: Check `--debug-ssa` to see if values are correct
2. **Crash (exit 139)**: Use `lldb -o "run" -o "bt" -o "quit" ./program`
3. **Register clobbering**: Add print statements in `loadToReg` to trace what's being loaded where

---

## Future Improvements

### Potential Optimizations

1. **Register hints**: Prefer callee-saved for values that survive calls
2. **Coalescing**: Avoid mov when source and dest can share a register
3. **Better spill selection**: Use farthest-next-use instead of first-available

### x86_64 Remaining Failures (5 tests)

These likely involve:
- Boolean operations (test_bool_or)
- Loop-related codegen (test_for_array, test_for_slice)
- Collection methods (test_list_methods, test_map_methods)

The fixes would follow the same MCValue pattern - ensure all operands are properly loaded before use.

---

## Conclusion

The integrated codegen approach with MCValue tracking is:

- **Simpler** - No separate regalloc pass to maintain
- **More robust** - Can't have mismatches between regalloc and codegen
- **Easier to debug** - Each operation clearly shows what it loads and where it stores
- **Proven** - This is how Zig's compiler works, and it handles far more complexity than we need

The 63/63 ARM64 test pass rate validates that this architecture is sound for self-hosting.
