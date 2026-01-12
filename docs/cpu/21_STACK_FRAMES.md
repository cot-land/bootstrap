# Stack Frames Deep Dive

**Purpose:** Understand exactly how function calls use the stack

---

## What is a Stack Frame?

When you call a function, the CPU needs to remember:
- **Where to return** after the function finishes
- **Local variables** the function uses
- **Saved registers** the function promises to preserve

All this information is organized in a **stack frame**.

---

## Anatomy of a Stack Frame

```
                Higher addresses
            +-------------------------+
            |   Caller's frame        |
            +-------------------------+
    fp ---> | Saved frame pointer     | <- Points to caller's frame
            | Return address (lr)     | <- Where to return
            +-------------------------+
            | Local variable 1        |
            | Local variable 2        |
            | Local variable 3        |
            +-------------------------+
            | Saved callee-saved regs |
            | (x19, x20, etc.)        |
            +-------------------------+
    sp ---> | (Spill slots/padding)   |
            +-------------------------+
                Lower addresses
```

---

## Frame Pointer vs Stack Pointer

**Stack Pointer (sp/rsp):**
- Always points to the top (lowest address) of the stack
- Changes as we push/pop or allocate locals
- Relative offsets to locals change during function

**Frame Pointer (fp/x29/rbp):**
- Points to a fixed location in the frame
- Doesn't change during function execution
- Makes accessing locals easier (fixed offsets)

### With Frame Pointer

```asm
; Access local at offset -16 from frame pointer
ldr x0, [x29, #-16]    ; ARM64
mov rax, [rbp - 16]    ; x86_64
```

Offset is constant throughout the function.

### Without Frame Pointer (Stack Pointer Only)

```asm
; Access local - offset depends on current sp
ldr x0, [sp, #48]      ; Before allocating 16 bytes
ldr x0, [sp, #32]      ; After allocating 16 bytes
```

Offset changes when we push/pop or call functions.

---

## Frame Creation: ARM64

```cot
fn example(a: i64, b: i64) i64 {
    var x: i64 = a + 1
    var y: i64 = b * 2
    return x + y
}
```

### Stack Layout

```
Offset from fp    Contents
+16               b (parameter, passed in x1)
+8                a (parameter, passed in x0)
0                 Saved frame pointer (caller's x29)
-8                Return address (x30)
-16               x (local variable)
-24               y (local variable)
-32               (alignment padding)
```

### Generated Code

```asm
_example:
    ; === Prologue ===
    ; Allocate frame and save fp/lr
    stp x29, x30, [sp, #-32]!  ; sp -= 32; store x29,x30 at sp
    mov x29, sp                 ; fp = sp

    ; === Function body ===
    ; x0 = a, x1 = b (from caller)

    ; x = a + 1
    add x2, x0, #1              ; x2 = a + 1
    str x2, [x29, #-16]         ; Store x at fp-16

    ; y = b * 2
    lsl x3, x1, #1              ; x3 = b * 2 (shift left = multiply by 2)
    str x3, [x29, #-24]         ; Store y at fp-24

    ; return x + y
    ldr x4, [x29, #-16]         ; Load x
    ldr x5, [x29, #-24]         ; Load y
    add x0, x4, x5              ; x0 = x + y (result)

    ; === Epilogue ===
    ldp x29, x30, [sp], #32     ; Restore fp/lr; sp += 32
    ret
```

---

## Frame Creation: x86_64

### Stack Layout

```
Offset from rbp   Contents
+24               b (parameter 2 - would be on stack if >6 args)
+16               a (parameter 1 - would be on stack if >6 args)
+8                Return address (pushed by call)
0                 Saved frame pointer (caller's rbp)
-8                x (local variable)
-16               y (local variable)
-24               (padding to 16-byte alignment)
-32               (end of frame)
```

Note: First 6 integer arguments are in registers on x86_64, so a and b are in rdi/rsi.

### Generated Code

```asm
_example:
    ; === Prologue ===
    push rbp                    ; Save caller's frame pointer
    mov rbp, rsp                ; Set up our frame pointer
    sub rsp, 32                 ; Allocate locals (aligned to 16)

    ; === Function body ===
    ; rdi = a, rsi = b (from caller)

    ; x = a + 1
    lea rax, [rdi + 1]          ; rax = a + 1
    mov [rbp - 8], rax          ; Store x

    ; y = b * 2
    lea rax, [rsi * 2]          ; rax = b * 2
    mov [rbp - 16], rax         ; Store y

    ; return x + y
    mov rax, [rbp - 8]          ; Load x
    add rax, [rbp - 16]         ; rax += y

    ; === Epilogue ===
    mov rsp, rbp                ; Deallocate locals
    pop rbp                     ; Restore caller's frame pointer
    ret                         ; Return (pops return address)
```

---

## Nested Function Calls

When function A calls function B, frames chain together:

```
            +-------------------------+
            |   main's frame          |
            +-------------------------+
 A's fp --> | main's fp               |
            | Return to main          |
            | A's locals              |
            +-------------------------+
 B's fp --> | A's fp                  | <-- Linked!
            | Return to A             |
            | B's locals              |
            +-------------------------+
 sp     --> |                         |
```

Each frame pointer points to the previous frame. This creates a **call stack** you can walk to generate backtraces.

```asm
; Walk the stack (pseudo-code)
current_fp = fp
while current_fp != 0:
    return_addr = load [current_fp + 8]   ; Get return address
    print "Called from", return_addr
    current_fp = load [current_fp]        ; Follow chain
```

---

## Saving Callee-Saved Registers

If a function uses callee-saved registers, it must save and restore them:

```asm
_uses_x19_x20:
    ; Prologue - save fp/lr AND callee-saved we'll use
    stp x29, x30, [sp, #-48]!
    mov x29, sp
    stp x19, x20, [sp, #16]    ; Save x19, x20
    stp x21, x22, [sp, #32]    ; Save x21, x22

    ; Function body uses x19, x20, x21, x22 freely
    mov x19, #100
    mov x20, #200
    ; ...

    ; Epilogue - restore everything
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #48
    ret
```

The caller's values in x19-x22 are preserved.

---

## Stack Alignment

Modern ABIs require the stack to be **16-byte aligned** at function call points.

Why?
- SIMD instructions require aligned data
- Some operations assume alignment
- Cache efficiency

```asm
; Bad: Stack might not be aligned
sub sp, sp, #8              ; sp now misaligned!

; Good: Always allocate in multiples of 16
sub sp, sp, #16             ; sp still aligned
```

The frame size calculation:
```
frame_size = round_up(locals + saved_regs, 16)
```

---

## Variable-Length Frames (alloca)

Some functions need dynamic stack space:

```cot
fn make_buffer(size: i64) []u8 {
    var buf: [size]u8  // Variable-length array
    return buf
}
```

This uses the frame pointer:

```asm
; With frame pointer, we can adjust sp freely
sub sp, sp, x0              ; Allocate 'size' bytes
; Access locals via fp, not sp
ldr x1, [x29, #-16]         ; Works regardless of sp position
```

Without a frame pointer, this would be very difficult.

---

## Red Zone (x86_64)

On x86_64 (System V ABI), there's a 128-byte **red zone** below the stack pointer:

```
    rsp  --> +-------------------------+
             | Red zone (128 bytes)    |
             | Can be used without     |
             | adjusting rsp           |
             +-------------------------+
```

Leaf functions (that don't call other functions) can use this space without adjusting rsp:

```asm
; Leaf function - use red zone
mov [rsp - 8], rax          ; OK! No need to sub rsp first
mov [rsp - 16], rbx
; ... do work ...
ret
```

ARM64 doesn't have a red zone - you must always allocate before using.

---

## Omitting the Frame Pointer

Compilers can omit the frame pointer for optimization:

**Benefits:**
- One more register available (rbp/x29)
- Fewer prologue/epilogue instructions

**Drawbacks:**
- Harder to debug (no stack traces)
- Variable-sized allocations become complex

```asm
; Without frame pointer
_optimized:
    sub sp, sp, #32           ; Allocate
    ; Access locals via sp offsets
    str x0, [sp, #0]
    str x1, [sp, #8]
    ; ...
    add sp, sp, #32           ; Deallocate
    ret
```

Cot always uses frame pointers for simpler codegen and debugging.

---

## Frame Layout in Cot

The IR builder computes frame layout:

```zig
pub fn build(self: *FuncBuilder) !Func {
    var frame_offset: i32 = 0;

    for (self.locals.items) |*local| {
        // Align to 8 bytes
        frame_offset = roundUp(frame_offset, 8);
        // Assign offset (negative from fp)
        local.offset = -frame_offset - @intCast(local.size);
        frame_offset += @intCast(local.size);
    }

    // Round to 16-byte alignment
    const frame_size = roundUp(frame_offset, 16);

    return Func{ .frame_size = frame_size, ... };
}
```

---

## Example: Recursive Function

```cot
fn factorial(n: i64) i64 {
    if n <= 1 {
        return 1
    }
    return n * factorial(n - 1)
}
```

Each recursive call creates a new frame:

```
factorial(4):
+------------------+
| n = 4            |
| return to main   |
+------------------+
  factorial(3):
  +------------------+
  | n = 3            |
  | return to fact(4)|
  +------------------+
    factorial(2):
    +------------------+
    | n = 2            |
    | return to fact(3)|
    +------------------+
      factorial(1):
      +------------------+
      | n = 1            |
      | return to fact(2)|
      +------------------+
      returns 1
    returns 2 * 1 = 2
  returns 3 * 2 = 6
returns 4 * 6 = 24
```

---

## Key Takeaways

1. **Stack frames organize function state** - locals, saved registers, return info.

2. **Frame pointer provides stable base** for accessing locals.

3. **Frames chain together** via saved frame pointers.

4. **Stack must be 16-byte aligned** at function calls.

5. **Callee-saved registers** must be preserved across function calls.

6. **Red zone** (x86_64 only) allows quick access without adjusting sp.

---

## Next Steps

- **[Calling Conventions](22_CALLING_CONVENTIONS.md)** - Argument passing in detail
- **[Instruction Encoding](23_ENCODING.md)** - How instructions become bytes
