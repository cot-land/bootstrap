# Stage 6: Code Generation

**Files:** `src/codegen/*.zig`

**Purpose:** Convert SSA into machine code

---

## What is Code Generation?

Code generation (codegen) is the final transformation: from abstract SSA values to actual machine instructions that the CPU can execute.

```
SSA:                         ARM64 Machine Code:

%1 = const_int 42            mov x0, #42
%2 = const_int 10            mov x1, #10
%3 = add %1, %2              add x0, x0, x1
ret %3                       ret
```

The codegen must:
1. **Allocate registers** - Decide which SSA values live in which CPU registers
2. **Select instructions** - Choose the right machine instruction for each operation
3. **Manage the stack** - Allocate space for locals, save/restore registers
4. **Handle calling conventions** - Know how to call other functions

---

## Target Architectures

Cot supports two architectures:

| Architecture | Used In | Files |
|-------------|---------|-------|
| **ARM64 (AArch64)** | Mac M1/M2/M3, iPhones, Raspberry Pi | `arm64_codegen.zig`, `aarch64.zig` |
| **x86_64 (AMD64)** | Intel/AMD PCs, older Macs, servers | `amd64_codegen.zig`, `x86_64.zig` |

Each has different:
- Registers (names, counts)
- Instruction encoding (how bytes represent instructions)
- Calling conventions (how to pass arguments)

---

## MCValue: Where Values Live

The `MCValue` type tracks where each SSA value is stored:

```zig
pub const MCValue = union(enum) {
    none,                     // Value doesn't exist
    dead,                     // Value is no longer needed
    immediate: i64,           // Value is a constant
    register: Reg,            // Value is in a CPU register
    stack: u12,               // Value is on the stack (offset from sp)
    lea_symbol: struct {      // Value is a symbol address
        name: []const u8,
        len: usize,
    },
};
```

Examples:
- `42` is `MCValue{ .immediate = 42 }`
- `x + y` result might be `MCValue{ .register = .x0 }`
- A local variable might be `MCValue{ .stack = 16 }`

---

## Register Allocation

### The Problem

SSA can have unlimited values. CPUs have limited registers (ARM64 has ~30, x86_64 has ~16). We need to decide:
1. Which values get registers
2. What to do when we run out

### ARM64 Registers

```zig
pub const allocatable_regs = [_]aarch64.Reg{
    // Callee-saved (survive function calls)
    .x19, .x20, .x21, .x22, .x23, .x24, .x25, .x26, .x27, .x28,
    // Caller-saved (clobbered by calls)
    .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7,
    .x9, .x10, .x11, .x12, .x13, .x14, .x15,
};
```

Special registers:
- `x0-x7`: Function arguments and return values
- `x29 (fp)`: Frame pointer (points to stack frame)
- `x30 (lr)`: Link register (return address)
- `sp`: Stack pointer

### The Register Manager

```zig
pub const RegisterManager = struct {
    /// Which value is in each register (null if free)
    registers: [allocatable_regs.len]?ssa.ValueID,
    /// Bitmap of free registers
    free_regs: u32,
    /// Bitmap of locked registers (can't be spilled)
    locked_regs: u32,

    pub fn tryAlloc(self: *RegisterManager, value_id: ?ssa.ValueID) ?aarch64.Reg {
        const available = self.free_regs & ~self.locked_regs;
        if (available == 0) return null;

        // Find first free register
        const idx = @ctz(available);  // Count trailing zeros
        const reg = allocatable_regs[idx];

        self.markUsed(reg, value_id.?);
        return reg;
    }

    pub fn isFree(self: *const RegisterManager, reg: Reg) bool {
        const idx = indexOf(reg) orelse return true;
        return (self.free_regs >> idx) & 1 == 1;
    }
};
```

### Spilling

When all registers are in use, we **spill**: save a register to the stack and free it.

```zig
pub fn spillReg(self: *CodeGen, reg: aarch64.Reg) !void {
    // Get the value currently in this register
    const value_id = self.reg_manager.getValueIn(reg) orelse return;

    // Find or allocate a spill slot
    const offset = self.next_spill_offset;
    self.next_spill_offset += 8;

    // Emit store instruction
    try aarch64.strImmU(self.buf, reg, .sp, offset);

    // Update tracking
    try self.tracking.put(value_id, .{ .home = .{ .stack = offset } });
    self.reg_manager.markFree(reg);
}
```

The **farthest-next-use heuristic** picks which register to spill: we choose the one whose value won't be needed for the longest.

---

## Instruction Selection

Each SSA operation maps to one or more machine instructions:

### Constants

```zig
fn genConstInt(self: *CodeGen, value: *ssa.Value) !void {
    const imm = value.aux_int;
    const dest = try self.allocReg(value.id);

    if (imm >= 0 and imm <= 65535) {
        // Small constant: use MOVZ
        try aarch64.movz(self.buf, dest, @intCast(imm));
    } else {
        // Large constant: use multiple instructions
        try aarch64.loadImm64(self.buf, dest, imm);
    }

    try self.setResult(value.id, .{ .register = dest });
}
```

### Arithmetic

```zig
fn genAdd(self: *CodeGen, value: *ssa.Value) !void {
    const args = value.args();

    // Get operand locations
    const left_mcv = self.getValue(args[0]);
    const right_mcv = self.getValue(args[1]);

    // Load left into register
    const dest = try self.allocReg(value.id);
    try self.loadToReg(dest, left_mcv);

    // Add right operand
    switch (right_mcv) {
        .immediate => |imm| {
            if (imm >= 0 and imm < 4096) {
                try aarch64.addImm(self.buf, dest, dest, @intCast(imm));
            } else {
                const temp = try self.allocReg(null);
                try self.loadToReg(temp, right_mcv);
                try aarch64.addReg(self.buf, dest, dest, temp);
                self.reg_manager.markFree(temp);
            }
        },
        .register => |right_reg| {
            try aarch64.addReg(self.buf, dest, dest, right_reg);
        },
        .stack => |offset| {
            const temp = try self.allocReg(null);
            try aarch64.ldrImmU(self.buf, temp, .sp, offset);
            try aarch64.addReg(self.buf, dest, dest, temp);
            self.reg_manager.markFree(temp);
        },
        else => {},
    }

    try self.setResult(value.id, .{ .register = dest });
}
```

### Comparisons

```zig
fn genCmp(self: *CodeGen, value: *ssa.Value, cond: aarch64.Cond) !void {
    const args = value.args();

    // Load operands
    const left_reg = try self.ensureInReg(args[0]);
    const right_reg = try self.ensureInReg(args[1]);

    // Emit compare instruction
    try aarch64.cmpReg(self.buf, left_reg, right_reg);

    // Set result based on condition code
    const dest = try self.allocReg(value.id);
    try aarch64.cset(self.buf, dest, cond);

    try self.setResult(value.id, .{ .register = dest });
}
```

---

## Function Prologue and Epilogue

Every function needs setup (prologue) and cleanup (epilogue):

### ARM64 Prologue

```asm
; Save frame pointer and link register
stp x29, x30, [sp, #-frame_size]!
; Set up frame pointer
mov x29, sp
; Save callee-saved registers we use
stp x19, x20, [sp, #16]
stp x21, x22, [sp, #32]
; ...
```

```zig
fn emitPrologue(self: *CodeGen) !void {
    // Pre-index store of fp and lr, allocating stack
    try aarch64.stpPre(self.buf, .x29, .x30, .sp, -@intCast(self.stack_size));
    // Set frame pointer
    try aarch64.movReg(self.buf, .x29, .sp);

    // Save callee-saved registers we use
    // ...
}
```

### ARM64 Epilogue

```asm
; Restore callee-saved registers
ldp x19, x20, [sp, #16]
ldp x21, x22, [sp, #32]
; Restore frame pointer and link register, deallocate stack
ldp x29, x30, [sp], #frame_size
; Return
ret
```

---

## Calling Conventions

### ARM64 (AAPCS64)

| Registers | Purpose |
|-----------|---------|
| x0-x7 | Arguments and return values |
| x8 | Indirect result location (large struct returns) |
| x9-x15 | Caller-saved temporaries |
| x19-x28 | Callee-saved |
| x29 | Frame pointer |
| x30 | Link register (return address) |

```zig
fn genCall(self: *CodeGen, value: *ssa.Value) !void {
    const args = value.args();
    const func_name = value.aux_str;

    // Place arguments in x0, x1, x2, ... (up to 8)
    for (args[1..], 0..) |arg_id, i| {
        const arg_reg = aarch64.Reg.fromInt(@intCast(i));  // x0, x1, ...
        const arg_mcv = self.getValue(arg_id);
        try self.loadToReg(arg_reg, arg_mcv);
    }

    // Call the function (with relocation)
    try aarch64.bl(self.buf, 0);  // Placeholder, linker fills in
    try self.addRelocation(func_name, .branch);

    // Result is in x0
    try self.setResult(value.id, .{ .register = .x0 });
}
```

### x86_64 (System V AMD64)

| Registers | Purpose |
|-----------|---------|
| rdi, rsi, rdx, rcx, r8, r9 | Arguments (in order) |
| rax | Return value |
| rbx, r12-r15 | Callee-saved |
| rsp | Stack pointer |
| rbp | Frame pointer |

---

## Instruction Encoding

### ARM64 Encoding

ARM64 instructions are always 4 bytes. The instruction format encodes:
- Operation type (add, sub, load, etc.)
- Register numbers
- Immediate values
- Shift/extend options

```zig
/// ADD Xd, Xn, Xm (64-bit register add)
pub fn addReg(buf: *CodeBuffer, rd: Reg, rn: Reg, rm: Reg) !void {
    // Encoding: 0b10001011000 Rm (5) 000000 Rn (5) Rd (5)
    const inst: u32 = 0x8B000000 |
        (@as(u32, rm.enc()) << 16) |
        (@as(u32, rn.enc()) << 5) |
        @as(u32, rd.enc());
    try buf.emitU32(inst);
}
```

### x86_64 Encoding

x86_64 instructions are variable length (1-15 bytes). The format uses:
- Prefixes (REX for 64-bit, etc.)
- Opcode bytes
- ModR/M byte (register/memory selection)
- SIB byte (complex addressing)
- Immediate values

```zig
/// ADD r64, r64
pub fn addRegReg(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    // REX.W prefix for 64-bit
    const rex = 0x48 | (src.isExt() << 2) | dst.isExt();
    try buf.emit(rex);
    try buf.emit(0x01);  // ADD opcode
    try buf.emit(0xC0 | (src.enc3() << 3) | dst.enc3());  // ModR/M
}
```

---

## The Code Buffer

Machine code is emitted to a buffer:

```zig
pub const CodeBuffer = struct {
    data: []u8,
    pos: usize,
    allocator: Allocator,

    pub fn emit(self: *CodeBuffer, byte: u8) !void {
        if (self.pos >= self.data.len) {
            try self.grow();
        }
        self.data[self.pos] = byte;
        self.pos += 1;
    }

    pub fn emitU32(self: *CodeBuffer, val: u32) !void {
        const bytes = std.mem.toBytes(val);
        for (bytes) |b| {
            try self.emit(b);
        }
    }

    pub fn currentOffset(self: *const CodeBuffer) usize {
        return self.pos;
    }
};
```

---

## Relocations

Some addresses aren't known until link time. We record them as relocations:

```zig
pub const Relocation = struct {
    offset: u32,           // Where in the code
    symbol: []const u8,    // What symbol we need
    kind: RelocKind,       // Type of relocation
};

pub const RelocKind = enum {
    branch,      // Function call (BL instruction)
    page,        // ADRP instruction (high bits)
    pageoff,     // ADD instruction (low bits)
    got,         // GOT entry reference
};
```

When we call `print`:

```zig
// Emit: bl print  (but we don't know the offset yet)
try aarch64.bl(self.buf, 0);  // Placeholder

// Record that linker needs to fill this in
try self.addRelocation("_print", .branch);
```

---

## Complete Example

Let's trace codegen for:

```cot
fn add(a: i64, b: i64) i64 {
    return a + b
}
```

### Input SSA

```
func add(a, b) -> i64:
  entry (block 0):
    %0 = arg 0          ; a
    %1 = arg 1          ; b
    %2 = add %0, %1
    ret %2
```

### Codegen Steps

```
1. Emit prologue:
   stp x29, x30, [sp, #-16]!
   mov x29, sp

2. Process %0 = arg 0
   - Arguments arrive in x0, x1, ...
   - setResult(%0, .{ .register = .x0 })

3. Process %1 = arg 1
   - setResult(%1, .{ .register = .x1 })

4. Process %2 = add %0, %1
   - getValue(%0) = .register(.x0)
   - getValue(%1) = .register(.x1)
   - Allocate dest register: x2
   - Emit: add x2, x0, x1
   - setResult(%2, .{ .register = .x2 })

5. Process ret %2
   - getValue(%2) = .register(.x2)
   - Move result to x0: mov x0, x2
   - Emit epilogue:
     ldp x29, x30, [sp], #16
     ret
```

### Output Machine Code

```asm
_add:
    stp x29, x30, [sp, #-16]!   ; FD 7B BF A9
    mov x29, sp                  ; FD 03 00 91
    add x2, x0, x1               ; 02 00 01 8B
    mov x0, x2                   ; E0 03 02 AA
    ldp x29, x30, [sp], #16     ; FD 7B C1 A8
    ret                          ; C0 03 5F D6
```

Total: 24 bytes of machine code.

---

## Key Takeaways

1. **Register allocation happens during codegen** - not as a separate pass.

2. **MCValue tracks where each value lives** - register, stack, or immediate.

3. **Spilling saves registers to stack** when we run out.

4. **Each architecture has different encoding** - ARM64 is fixed-width, x86_64 is variable.

5. **Relocations defer address resolution** to link time.

6. **Calling conventions** determine how functions communicate.

---

## Next Steps

The codegen produces machine code in a buffer. The next stage, **linking**, packages this into an executable file.

See: [16_LINKING.md](16_LINKING.md)
