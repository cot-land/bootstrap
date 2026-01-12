# Worked Example: Tracing Through the Pipeline

**Purpose:** Follow a complete program through every compilation stage

---

## The Program

Let's trace this simple program through the entire compiler:

```cot
fn main() i64 {
    var x: i64 = 40;
    var y: i64 = 2;
    return x + y;
}
```

Expected result: The program exits with code 42.

---

## Stage 1: Scanning

The scanner reads characters and produces tokens:

### Input

```
fn main() i64 {\n    var x: i64 = 40;\n    var y: i64 = 2;\n    return x + y;\n}
```

### Process

```
Character: 'f' → Start identifier
Character: 'n' → Continue identifier
Character: ' ' → End identifier, lookup "fn" → keyword!

Character: 'm' → Start identifier
Character: 'a' → Continue
Character: 'i' → Continue
Character: 'n' → Continue
Character: '(' → End identifier "main"

... and so on ...
```

### Output: Token Stream

```
[kw_fn]
[identifier: "main"]
[lparen]
[rparen]
[identifier: "i64"]  → resolves to kw_i64
[lbrace]
[kw_var]
[identifier: "x"]
[colon]
[identifier: "i64"]  → resolves to kw_i64
[equal]
[int_literal: "40"]
[semicolon]
[kw_var]
[identifier: "y"]
[colon]
[identifier: "i64"]  → resolves to kw_i64
[equal]
[int_literal: "2"]
[semicolon]
[kw_return]
[identifier: "x"]
[plus]
[identifier: "y"]
[semicolon]
[rbrace]
[eof]
```

---

## Stage 2: Parsing

The parser builds an Abstract Syntax Tree from tokens.

### Process

```
parseFile():
  Token is 'fn' → parseDecl() → parseFnDecl()

parseFnDecl():
  Consume 'fn'
  Name = "main"
  Consume '('
  parseFieldList() → [] (no parameters)
  Consume ')'
  parseType() → "i64"
  parseBlock():
    Consume '{'
    parseStmt() → VarStmt(x, i64, 40)
    parseStmt() → VarStmt(y, i64, 2)
    parseStmt() → ReturnStmt(Binary(+, x, y))
    Consume '}'
```

### Output: AST

```
File
└── FnDecl
    ├── name: "main"
    ├── params: []
    ├── return_type: TypeExpr("i64")
    └── body: Block
          ├── VarStmt
          │   ├── name: "x"
          │   ├── type: TypeExpr("i64")
          │   └── value: Literal(40)
          ├── VarStmt
          │   ├── name: "y"
          │   ├── type: TypeExpr("i64")
          │   └── value: Literal(2)
          └── ReturnStmt
                └── value: Binary
                      ├── op: +
                      ├── left: Identifier("x")
                      └── right: Identifier("y")
```

---

## Stage 3: Type Checking

The checker verifies types and resolves names.

### Pass 1: Collect Declarations

```
collectDecl(FnDecl "main"):
  - Build function type: fn() -> i64
  - Register symbol: main -> TypeIndex(14)
```

### Pass 2: Check Body

```
checkFnDecl("main"):
  Create function scope
  Set current_return_type = I64

checkVarStmt(x):
  - type annotation: i64 → TypeIndex(5)
  - check value: Literal(40) → UNTYPED_INT
  - isAssignable(UNTYPED_INT, I64)? Yes
  - Add symbol: x → I64

checkVarStmt(y):
  - type annotation: i64 → TypeIndex(5)
  - check value: Literal(2) → UNTYPED_INT
  - isAssignable(UNTYPED_INT, I64)? Yes
  - Add symbol: y → I64

checkReturnStmt:
  checkExpr(Binary):
    - checkExpr(left): lookup "x" → I64
    - checkExpr(right): lookup "y" → I64
    - Both numeric? Yes
    - Binary result type: I64
  - return type I64 matches function return type I64? Yes
```

### Output: Annotated AST

Same structure but with type information attached:
- `x` → TypeIndex(5) (I64)
- `y` → TypeIndex(5) (I64)
- `x + y` → TypeIndex(5) (I64)

---

## Stage 4: IR Lowering

The lowerer transforms AST into flat IR operations.

### Process

```
lowerFnDecl("main"):
  Start function builder
  Return type: I64

lowerVarStmt(x, i64, 40):
  - Add local: x, type=I64, size=8 → local_idx=0
  - emit: const_int 40 → node_idx=0
  - emit: store local[0], node[0]

lowerVarStmt(y, i64, 2):
  - Add local: y, type=I64, size=8 → local_idx=1
  - emit: const_int 2 → node_idx=2
  - emit: store local[1], node[2]

lowerReturnStmt:
  lowerBinary(+):
    - lowerIdentifier("x"):
        lookup local "x" → local_idx=0
        emit: local 0 → node_idx=4
    - lowerIdentifier("y"):
        lookup local "y" → local_idx=1
        emit: local 1 → node_idx=5
    - emit: add node[4], node[5] → node_idx=6
  - emit: ret node[6]
```

### Output: IR

```
func main() -> i64:
  locals:
    [0] x: i64, mutable, size=8, offset=-8
    [1] y: i64, mutable, size=8, offset=-16
  frame_size: 16

  block 0 (entry):
    %0 = const_int 40
    %1 = store local[0], %0
    %2 = const_int 2
    %3 = store local[1], %2
    %4 = local 0              ; load x
    %5 = local 1              ; load y
    %6 = add %4, %5
    ret %6
```

---

## Stage 5: SSA Conversion

Convert to Static Single Assignment form.

### Process

```
Convert entry block:
  %0 = const_int 40
    → ssa_val 0 = const_int, aux=40

  store local[0], %0
    → current_def["x"] = ssa_val 0

  %2 = const_int 2
    → ssa_val 1 = const_int, aux=2

  store local[1], %2
    → current_def["y"] = ssa_val 1

  local 0
    → lookup current_def["x"] = ssa_val 0

  local 1
    → lookup current_def["y"] = ssa_val 1

  add %4, %5
    → ssa_val 2 = add, args=[0, 1]

  ret %6
    → ssa_val 3 = ret, args=[2]
```

### Output: SSA

```
func main() -> i64:
  locals: [x: i64, y: i64]
  frame_size: 16

  block 0 (entry), kind=ret:
    %0 = const_int 40        ; (uses: 1)
    %1 = const_int 2         ; (uses: 1)
    %2 = add %0, %1          ; (uses: 1)
    ret %2
```

Note how the store/load pairs are eliminated - we directly use the const values.

---

## Stage 6: Code Generation

Convert SSA to ARM64 machine code.

### Prologue

```
emitPrologue(frame_size=16):
  stp x29, x30, [sp, #-16]!   ; Save fp/lr, allocate 16 bytes
  mov x29, sp                  ; Set frame pointer
```

Machine code: `FD 7B BF A9  FD 03 00 91`

### Generate Operations

```
genConstInt(%0, value=40):
  - Allocate register: x0
  - emit: movz x0, #40
  - setResult(%0, register=x0)

Machine code: `80 05 80 D2`  (movz x0, #0x28)

genConstInt(%1, value=2):
  - Allocate register: x1
  - emit: movz x1, #2
  - setResult(%1, register=x1)

Machine code: `41 00 80 D2`  (movz x1, #2)

genAdd(%2, args=[%0, %1]):
  - getValue(%0) = register(x0)
  - getValue(%1) = register(x1)
  - Allocate register: x2
  - emit: add x2, x0, x1
  - setResult(%2, register=x2)

Machine code: `02 00 01 8B`  (add x2, x0, x1)

genRet(%3, args=[%2]):
  - getValue(%2) = register(x2)
  - emit: mov x0, x2        ; Result in x0
  - emit epilogue

Machine code: `E0 03 02 AA`  (mov x0, x2)
```

### Epilogue

```
emitEpilogue():
  ldp x29, x30, [sp], #16     ; Restore fp/lr, deallocate
  ret

Machine code: `FD 7B C1 A8  C0 03 5F D6`
```

### Output: Machine Code

```
Offset  Bytes           Instruction
0x00    FD 7B BF A9    stp x29, x30, [sp, #-16]!
0x04    FD 03 00 91    mov x29, sp
0x08    80 05 80 D2    movz x0, #40
0x0c    41 00 80 D2    movz x1, #2
0x10    02 00 01 8B    add x2, x0, x1
0x14    E0 03 02 AA    mov x0, x2
0x18    FD 7B C1 A8    ldp x29, x30, [sp], #16
0x1c    C0 03 5F D6    ret
```

Total: 32 bytes of machine code.

---

## Stage 7: Linking

Create an executable from the machine code.

### Object File Structure

```
=== Mach-O Object File ===

Header:
  magic: 0xFEEDFACF
  cputype: ARM64
  filetype: MH_OBJECT (1)
  ncmds: 4

Segment __TEXT:
  Section __text:
    size: 32 bytes
    offset: 0x200

Symbols:
  [0] _main:
      type: N_SECT | N_EXT (defined, external)
      sect: 1 (__text)
      value: 0

No relocations (no external calls)
```

### Linking

```bash
zig cc main.o -o main
```

The linker:
1. Adds startup code (`_start` calls `_main`)
2. Adds C library (for `exit()` syscall)
3. Resolves symbol addresses
4. Creates executable header

---

## Stage 8: Execution

When you run `./main`:

### OS Loader

1. Read executable header
2. Map code into memory at virtual address (e.g., 0x100000000)
3. Set up stack
4. Jump to entry point (`_start`)

### C Runtime Startup

```asm
_start:
    ; Set up argc, argv, envp
    bl _main            ; Call your main function
    ; main's return value is in x0
    mov x16, #1         ; syscall: exit
    svc #0x80           ; Make syscall with x0 as exit code
```

### Your Code Runs

```
PC=0x100000000: stp x29, x30, [sp, #-16]!
  - sp = 0x7FFF1000
  - Store x29 at 0x7FFF0FF0
  - Store x30 at 0x7FFF0FF8
  - sp = 0x7FFF0FF0

PC=0x100000004: mov x29, sp
  - x29 = 0x7FFF0FF0

PC=0x100000008: movz x0, #40
  - x0 = 40

PC=0x10000000c: movz x1, #2
  - x1 = 2

PC=0x100000010: add x2, x0, x1
  - x2 = 40 + 2 = 42

PC=0x100000014: mov x0, x2
  - x0 = 42

PC=0x100000018: ldp x29, x30, [sp], #16
  - x29 = (restored)
  - x30 = (restored)
  - sp = 0x7FFF1000

PC=0x10000001c: ret
  - Jump to address in x30 (return to _start)
```

### Return to OS

```asm
; Back in _start, x0 = 42
mov x16, #1         ; exit syscall
svc #0x80           ; Exit with code 42
```

### Shell Sees Result

```bash
$ ./main
$ echo $?
42
```

---

## Summary: The Complete Journey

```
Source Code        "var x: i64 = 40; var y: i64 = 2; return x + y;"
    │
    ▼ Scanner
Tokens             [kw_var][identifier:x][colon][identifier:i64]...
    │
    ▼ Parser
AST                VarStmt(x,i64,40) → VarStmt(y,i64,2) → Return(x+y)
    │
    ▼ Type Checker
Annotated AST      Same structure + types: x:I64, y:I64, (x+y):I64
    │
    ▼ IR Lowering
IR                 const_int 40 → store → const_int 2 → store → add → ret
    │
    ▼ SSA Conversion
SSA                %0=40, %1=2, %2=add(%0,%1), ret(%2)
    │
    ▼ Code Generation
Machine Code       FD7BBFA9 FD030091 800580D2 410080D2 0200018B E00302AA...
    │
    ▼ Linking
Executable         main (Mach-O executable)
    │
    ▼ Execution
Result             Exit code: 42
```

---

## Key Insights

1. **Each stage transforms data** - input format to output format.

2. **Information is refined** - vague source becomes precise machine code.

3. **Complexity is hidden** - `x + y` becomes register allocation, instruction selection.

4. **Types guide optimization** - knowing `x` is `i64` means we can use 64-bit instructions.

5. **The pipeline is composable** - each stage is independent, testable.

---

## Debug It Yourself

Run Cot with debug flags to see each stage:

```bash
# See IR after lowering
./zig-out/bin/cot program.cot --debug-ir -o out

# See SSA after conversion
./zig-out/bin/cot program.cot --debug-ssa -o out

# See instruction selection
./zig-out/bin/cot program.cot --debug-codegen -o out

# See actual machine code
./zig-out/bin/cot program.cot --disasm -o out

# See everything
./zig-out/bin/cot program.cot --debug-ir --debug-ssa --debug-codegen --disasm -o out
```
