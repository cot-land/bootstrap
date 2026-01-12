# Calling Conventions

**Purpose:** How functions pass arguments and return values

---

## What is a Calling Convention?

When function A calls function B, they need to agree on:
- **Where to put arguments** (which registers? which stack slots?)
- **Where to find the return value** (which register?)
- **Who saves which registers** (caller or callee?)

This agreement is the **calling convention** (or ABI - Application Binary Interface).

---

## ARM64 Calling Convention (AAPCS64)

### Argument Passing

| Register | Purpose |
|----------|---------|
| `x0` | 1st argument / return value |
| `x1` | 2nd argument / return value (high 64 bits) |
| `x2` | 3rd argument |
| `x3` | 4th argument |
| `x4` | 5th argument |
| `x5` | 6th argument |
| `x6` | 7th argument |
| `x7` | 8th argument |

Arguments beyond the 8th go on the stack.

### Example: Many Arguments

```cot
fn many(a: i64, b: i64, c: i64, d: i64, e: i64, f: i64, g: i64, h: i64, i: i64) i64 {
    return a + b + c + d + e + f + g + h + i
}
```

```asm
; Caller
mov x0, #1              ; a in x0
mov x1, #2              ; b in x1
mov x2, #3              ; c in x2
mov x3, #4              ; d in x3
mov x4, #5              ; e in x4
mov x5, #6              ; f in x5
mov x6, #7              ; g in x6
mov x7, #8              ; h in x7
mov x9, #9              ; i needs stack
str x9, [sp, #-16]!     ; Push i to stack
bl _many
add sp, sp, #16         ; Clean up stack

; Callee
_many:
    ; x0-x7 have first 8 args
    ; 9th arg is at [sp + frame_size]
    ldr x9, [sp, #32]   ; Load i from stack
    add x0, x0, x1
    add x0, x0, x2
    ; ... add all args ...
    ret
```

### Return Values

| Size | Registers |
|------|-----------|
| 1-64 bits | `x0` |
| 65-128 bits | `x0` (low), `x1` (high) |
| > 128 bits | Caller passes pointer in `x8` |

### Large Struct Returns

```cot
struct BigStruct {
    a: i64
    b: i64
    c: i64
}

fn make_big() BigStruct {
    return BigStruct{ .a = 1, .b = 2, .c = 3 }
}
```

```asm
; Caller
sub sp, sp, #32         ; Space for result
mov x8, sp              ; Pass pointer to result space
bl _make_big
; Result is at [sp]

; Callee
_make_big:
    ; x8 points to where we should write
    mov x9, #1
    str x9, [x8, #0]    ; a = 1
    mov x9, #2
    str x9, [x8, #8]    ; b = 2
    mov x9, #3
    str x9, [x8, #16]   ; c = 3
    ret
```

### Register Categories

| Registers | Category | Description |
|-----------|----------|-------------|
| `x0-x7` | Caller-saved | Arguments, may be modified |
| `x8` | Caller-saved | Indirect result pointer |
| `x9-x15` | Caller-saved | Temporaries |
| `x16-x17` | Caller-saved | Intra-procedure scratch |
| `x18` | Platform | Reserved (don't use) |
| `x19-x28` | Callee-saved | Must preserve if used |
| `x29` | Special | Frame pointer |
| `x30` | Special | Link register (return address) |

---

## x86_64 Calling Convention (System V AMD64)

### Argument Passing

| Register | Purpose |
|----------|---------|
| `rdi` | 1st argument |
| `rsi` | 2nd argument |
| `rdx` | 3rd argument |
| `rcx` | 4th argument |
| `r8` | 5th argument |
| `r9` | 6th argument |

Arguments beyond the 6th go on the stack, **right to left**.

### Example

```cot
fn add_three(a: i64, b: i64, c: i64) i64 {
    return a + b + c
}
```

```asm
; Caller
mov rdi, 10             ; a
mov rsi, 20             ; b
mov rdx, 30             ; c
call _add_three
; Result in rax

; Callee
_add_three:
    mov rax, rdi        ; rax = a
    add rax, rsi        ; rax += b
    add rax, rdx        ; rax += c
    ret
```

### Return Values

| Size | Registers |
|------|-----------|
| 1-64 bits | `rax` |
| 65-128 bits | `rax` (low), `rdx` (high) |
| > 128 bits | Caller passes pointer as hidden 1st arg |

### Register Categories

| Registers | Category |
|-----------|----------|
| `rax` | Caller-saved, return value |
| `rdi, rsi, rdx, rcx, r8, r9` | Caller-saved, arguments |
| `r10, r11` | Caller-saved, scratch |
| `rbx` | Callee-saved |
| `r12, r13, r14, r15` | Callee-saved |
| `rbp` | Callee-saved (or frame pointer) |
| `rsp` | Special, stack pointer |

---

## Floating Point Arguments

Both architectures have separate registers for floating point:

### ARM64

| Register | Purpose |
|----------|---------|
| `v0-v7` (or `d0-d7`) | Float arguments 1-8 |
| `v0` (or `d0`) | Float return value |

### x86_64

| Register | Purpose |
|----------|---------|
| `xmm0-xmm7` | Float arguments 1-8 |
| `xmm0` | Float return value |

---

## Stack Alignment

Both ABIs require **16-byte stack alignment** at the point of a `call` instruction.

### ARM64
```asm
; Before call, sp must be 16-byte aligned
; stp/ldp instructions help maintain this
stp x29, x30, [sp, #-16]!   ; -16 keeps alignment
```

### x86_64
```asm
; call pushes 8 bytes (return address)
; So sp must be 16-byte aligned AFTER push
; Callee may need to sub rsp, 8 for alignment
sub rsp, 8                  ; Align to 16
call some_func
add rsp, 8
```

---

## Variadic Functions

Functions like `printf` take variable number of arguments.

### ARM64
```asm
; All variadic args go on the stack
; x0-x7 for named parameters only
mov x0, format_string       ; First named arg
str x1, [sp, #-16]!        ; First variadic arg
bl _printf
```

### x86_64
```asm
; AL register holds number of vector registers used
; Variadic args in normal registers then stack
mov rdi, format_string      ; Format string
mov rsi, 42                 ; First variadic arg
mov al, 0                   ; 0 floating point args
call _printf
```

---

## Calling Convention Summary

| Aspect | ARM64 | x86_64 |
|--------|-------|--------|
| Int args | x0-x7 | rdi, rsi, rdx, rcx, r8, r9 |
| Float args | v0-v7 | xmm0-xmm7 |
| Return | x0 (x1 for 128-bit) | rax (rdx for 128-bit) |
| Callee-saved | x19-x28 | rbx, r12-r15 |
| Frame pointer | x29 | rbp |
| Link register | x30 | (on stack) |
| Stack alignment | 16 bytes | 16 bytes |

---

## How Cot Handles This

In `arm64_codegen.zig`:

```zig
fn genCall(self: *CodeGen, value: *ssa.Value) !void {
    const args = value.args();
    const func_name = value.aux_str;

    // Place arguments in x0-x7
    for (args[1..], 0..) |arg_id, i| {
        if (i >= 8) break;  // Stack args not implemented yet
        const arg_reg = aarch64.Reg.fromInt(@intCast(i));
        const arg_mcv = self.getValue(arg_id);
        try self.loadToReg(arg_reg, arg_mcv);
    }

    // Emit BL instruction
    try aarch64.bl(self.buf, 0);  // Offset filled by linker
    try self.addRelocation(func_name, .branch);

    // Result is in x0
    try self.setResult(value.id, .{ .register = .x0 });
}
```

---

## Key Takeaways

1. **Registers for speed** - First N arguments go in registers.

2. **Stack for overflow** - Extra arguments go on the stack.

3. **Caller-saved = volatile** - Function calls may destroy them.

4. **Callee-saved = preserved** - Must save before using, restore after.

5. **Alignment matters** - 16-byte alignment at call site.

6. **Large returns use pointers** - Caller provides space.

---

## Next Steps

- **[Instruction Encoding](23_ENCODING.md)** - How instructions become bytes
- **[Worked Example](../30_WORKED_EXAMPLE.md)** - Complete compilation trace
