# CPU Fundamentals

**Purpose:** Understand how the CPU actually executes your compiled code

---

## What is a CPU?

The **Central Processing Unit (CPU)** is the brain of your computer. It does three things:

1. **Fetch** - Read the next instruction from memory
2. **Decode** - Figure out what the instruction means
3. **Execute** - Do what the instruction says

```
Memory:                          CPU:
+------------------+            +------------------+
| mov x0, #42      | ───Fetch──>| Instruction Reg  |
| add x1, x0, #10  |            | mov x0, #42      |
| ret              |            +------------------+
+------------------+                    |
                                       Decode
                                        |
                                        v
                              +------------------+
                              | x0 = 42          |
                              +------------------+
```

This **fetch-decode-execute cycle** repeats billions of times per second.

---

## Registers

**Registers** are tiny storage locations inside the CPU. They're incredibly fast - accessing a register takes about 1 cycle, while accessing main memory takes hundreds of cycles.

### ARM64 Registers

ARM64 has 31 general-purpose 64-bit registers:

| Registers | Purpose |
|-----------|---------|
| `x0-x7` | Function arguments, return values |
| `x8` | Indirect result (large struct returns) |
| `x9-x15` | Temporary values (caller-saved) |
| `x16-x17` | Scratch registers (IP0, IP1) |
| `x18` | Platform reserved |
| `x19-x28` | Saved registers (callee-saved) |
| `x29` | Frame pointer (fp) |
| `x30` | Link register (lr) - return address |
| `sp` | Stack pointer |
| `pc` | Program counter (instruction address) |

**Caller-saved** means: if you call a function, these registers might change.
**Callee-saved** means: if you call a function, these will be preserved.

### x86_64 Registers

x86_64 has 16 general-purpose 64-bit registers:

| Register | Purpose |
|----------|---------|
| `rax` | Return value, temporary |
| `rbx` | Callee-saved |
| `rcx` | 4th argument |
| `rdx` | 3rd argument, return value (high) |
| `rsi` | 2nd argument |
| `rdi` | 1st argument |
| `rbp` | Frame pointer |
| `rsp` | Stack pointer |
| `r8-r9` | 5th, 6th arguments |
| `r10-r11` | Caller-saved |
| `r12-r15` | Callee-saved |

---

## The Stack

The **stack** is a region of memory used for:
- Local variables
- Saved registers
- Function call information

It grows **downward** (toward lower addresses):

```
High addresses
+------------------+
|                  |
| Stack grows      |
|      ↓           |
|------------------| <- Stack Pointer (sp)
| Local variables  |
| Saved registers  |
| Return address   |
|------------------|
|                  |
| Free space       |
|                  |
+------------------+
Low addresses
```

### Stack Operations

**Push** - Put a value on the stack:
```asm
; ARM64
str x0, [sp, #-16]!   ; Decrement sp by 16, store x0

; x86_64
push rax              ; Decrement rsp by 8, store rax
```

**Pop** - Take a value off the stack:
```asm
; ARM64
ldr x0, [sp], #16     ; Load x0, increment sp by 16

; x86_64
pop rax               ; Load rax, increment rsp by 8
```

---

## Stack Frames

Each function call creates a **stack frame** containing:
- Saved frame pointer
- Return address
- Local variables
- Saved registers

```
                      +------------------+
                      | Caller's frame   |
                      +------------------+
          fp (x29) -> | Saved fp         | <- Previous frame pointer
                      | Return address   | <- Where to return
                      +------------------+
                      | Local var 1      |
                      | Local var 2      |
                      | Saved x19        | <- Callee-saved registers
                      | Saved x20        |
          sp       -> +------------------+
```

### Function Prologue (Setting Up)

```asm
; ARM64 prologue
stp x29, x30, [sp, #-32]!   ; Save fp and lr, allocate 32 bytes
mov x29, sp                  ; Set new frame pointer
stp x19, x20, [sp, #16]     ; Save callee-saved registers
```

```asm
; x86_64 prologue
push rbp                     ; Save old frame pointer
mov rbp, rsp                 ; Set new frame pointer
sub rsp, 32                  ; Allocate 32 bytes for locals
push rbx                     ; Save callee-saved registers
```

### Function Epilogue (Cleaning Up)

```asm
; ARM64 epilogue
ldp x19, x20, [sp, #16]     ; Restore callee-saved
ldp x29, x30, [sp], #32     ; Restore fp and lr, deallocate
ret                          ; Return (uses lr)
```

```asm
; x86_64 epilogue
pop rbx                      ; Restore callee-saved
mov rsp, rbp                 ; Deallocate locals
pop rbp                      ; Restore old frame pointer
ret                          ; Return (pops address from stack)
```

---

## Calling Conventions

**Calling conventions** define how functions communicate:
- How to pass arguments
- How to return values
- What registers to preserve

### ARM64 Calling Convention (AAPCS64)

**Arguments:**
- First 8 arguments in `x0-x7`
- Additional arguments on the stack

**Return value:**
- `x0` (and `x1` for 128-bit values)

**Example:**
```cot
fn add(a: i64, b: i64, c: i64) i64 {
    return a + b + c
}
```

```asm
; Caller
mov x0, #1          ; a = 1
mov x1, #2          ; b = 2
mov x2, #3          ; c = 3
bl _add             ; Call add
; Result is in x0

; add function
add x0, x0, x1      ; x0 = a + b
add x0, x0, x2      ; x0 = a + b + c
ret                 ; Return with result in x0
```

### x86_64 Calling Convention (System V AMD64)

**Arguments:**
- `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` (first 6 integers)
- Additional arguments on the stack

**Return value:**
- `rax` (and `rdx` for 128-bit values)

**Example:**
```asm
; Caller
mov rdi, 1          ; a = 1
mov rsi, 2          ; b = 2
mov rdx, 3          ; c = 3
call _add           ; Call add
; Result is in rax

; add function
add rdi, rsi        ; rdi = a + b
add rdi, rdx        ; rdi = a + b + c
mov rax, rdi        ; Move result to rax
ret                 ; Return
```

---

## Common Instructions

### ARM64 Instructions

| Instruction | Description | Example |
|-------------|-------------|---------|
| `mov` | Copy value | `mov x0, x1` (x0 = x1) |
| `movz` | Move immediate | `movz x0, #42` (x0 = 42) |
| `add` | Add | `add x0, x1, x2` (x0 = x1 + x2) |
| `sub` | Subtract | `sub x0, x1, x2` (x0 = x1 - x2) |
| `mul` | Multiply | `mul x0, x1, x2` (x0 = x1 * x2) |
| `cmp` | Compare | `cmp x0, x1` (set flags) |
| `b` | Branch | `b label` (jump to label) |
| `b.eq` | Branch if equal | `b.eq label` |
| `bl` | Branch and link | `bl func` (call function) |
| `ret` | Return | `ret` (return to caller) |
| `ldr` | Load from memory | `ldr x0, [x1]` (x0 = *x1) |
| `str` | Store to memory | `str x0, [x1]` (*x1 = x0) |
| `stp` | Store pair | `stp x0, x1, [sp]` |
| `ldp` | Load pair | `ldp x0, x1, [sp]` |

### x86_64 Instructions

| Instruction | Description | Example |
|-------------|-------------|---------|
| `mov` | Copy value | `mov rax, rbx` (rax = rbx) |
| `add` | Add | `add rax, rbx` (rax += rbx) |
| `sub` | Subtract | `sub rax, rbx` (rax -= rbx) |
| `imul` | Signed multiply | `imul rax, rbx` (rax *= rbx) |
| `cmp` | Compare | `cmp rax, rbx` (set flags) |
| `jmp` | Jump | `jmp label` |
| `je` | Jump if equal | `je label` |
| `call` | Call function | `call func` |
| `ret` | Return | `ret` |
| `push` | Push to stack | `push rax` |
| `pop` | Pop from stack | `pop rax` |

---

## Condition Codes (Flags)

Comparison and arithmetic instructions set **flags**:

| Flag | Meaning | Set when |
|------|---------|----------|
| **Z** (Zero) | Result is zero | `cmp 5, 5` |
| **N** (Negative) | Result is negative | `cmp 3, 5` (3-5 < 0) |
| **C** (Carry) | Unsigned overflow | Depends on operation |
| **V** (Overflow) | Signed overflow | Depends on operation |

Conditional branches check these flags:

| ARM64 | x86_64 | Condition |
|-------|--------|-----------|
| `b.eq` | `je` | Equal (Z=1) |
| `b.ne` | `jne` | Not equal (Z=0) |
| `b.lt` | `jl` | Less than (signed) |
| `b.gt` | `jg` | Greater than (signed) |
| `b.le` | `jle` | Less or equal (signed) |
| `b.ge` | `jge` | Greater or equal (signed) |

---

## Memory Addressing

### ARM64 Addressing Modes

```asm
; Base register
ldr x0, [x1]              ; x0 = *(x1)

; Base + immediate offset
ldr x0, [x1, #16]         ; x0 = *(x1 + 16)

; Base + register offset
ldr x0, [x1, x2]          ; x0 = *(x1 + x2)

; Pre-index (update base before)
ldr x0, [x1, #16]!        ; x1 += 16; x0 = *x1

; Post-index (update base after)
ldr x0, [x1], #16         ; x0 = *x1; x1 += 16

; PC-relative
adrp x0, symbol@PAGE      ; Load page address
add x0, x0, symbol@PAGEOFF ; Add offset
```

### x86_64 Addressing Modes

```asm
; Base register
mov rax, [rbx]            ; rax = *rbx

; Base + displacement
mov rax, [rbx + 16]       ; rax = *(rbx + 16)

; Base + index
mov rax, [rbx + rcx]      ; rax = *(rbx + rcx)

; Base + index*scale + displacement
mov rax, [rbx + rcx*8 + 16]  ; rax = *(rbx + rcx*8 + 16)

; RIP-relative (PC-relative)
mov rax, [rip + symbol]   ; Load from symbol address
```

---

## Example: Complete Function

Let's trace this function:

```cot
fn sum(n: i64) i64 {
    var total: i64 = 0
    var i: i64 = 1
    while i <= n {
        total = total + i
        i = i + 1
    }
    return total
}
```

### ARM64 Assembly

```asm
_sum:
    ; Prologue
    stp x29, x30, [sp, #-32]!   ; Save fp, lr
    mov x29, sp
    stp x19, x20, [sp, #16]     ; Save callee-saved

    ; x0 = n (argument)
    mov x19, x0                  ; Save n in callee-saved register

    ; total = 0
    mov x20, #0                  ; x20 = total

    ; i = 1
    mov x1, #1                   ; x1 = i

.loop:
    ; while i <= n
    cmp x1, x19                  ; Compare i with n
    b.gt .done                   ; If i > n, exit loop

    ; total = total + i
    add x20, x20, x1             ; total += i

    ; i = i + 1
    add x1, x1, #1               ; i++

    b .loop                      ; Repeat

.done:
    ; Return total
    mov x0, x20                  ; Put result in x0

    ; Epilogue
    ldp x19, x20, [sp, #16]     ; Restore callee-saved
    ldp x29, x30, [sp], #32     ; Restore fp, lr
    ret
```

---

## Key Takeaways

1. **Registers are fast** - Use them for frequently accessed values.

2. **The stack grows down** - `push` decrements the stack pointer.

3. **Calling conventions** define argument/return registers.

4. **Prologue/epilogue** set up and tear down stack frames.

5. **Flags** are set by arithmetic/compare operations.

6. **Addressing modes** let you access memory in various ways.

---

## Next Steps

- **[Stack Frames Deep Dive](21_STACK_FRAMES.md)** - Detailed frame layout
- **[Calling Conventions](22_CALLING_CONVENTIONS.md)** - Cross-platform details
- **[Instruction Encoding](23_ENCODING.md)** - How instructions become bytes
