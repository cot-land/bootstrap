# Cot Compiler: From Source Code to Running Program

**Purpose:** This document explains the entire journey of how your Cot source code becomes a running program on your computer. No prior compiler knowledge required.

---

## What is a Compiler?

A compiler is a program that translates code written in one language (like Cot) into another language (machine code that your CPU understands). Think of it like a translator who converts a book from English to French - the meaning stays the same, but the representation changes.

```
┌─────────────┐                              ┌─────────────┐
│  Your Code  │  ──────── Compiler ────────▶ │  Machine    │
│  (Cot)      │                              │  Code       │
└─────────────┘                              └─────────────┘

fn main() i64 {              ───▶           01001000 10001001
    return 42                                11111000 10110000
}                                            00101010 11000011
```

The machine code on the right is what your CPU actually executes. It's just numbers (shown in binary), but those numbers tell your CPU exactly what to do.

---

## The Compiler Pipeline

The Cot compiler doesn't do everything in one step. Instead, it uses a **pipeline** - a series of stages where each stage transforms the code into a different representation. This makes the compiler easier to understand, test, and maintain.

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  Source  │───▶│  Tokens  │───▶│   AST    │───▶│   IR     │───▶│   SSA    │───▶│  Machine │───▶│  Binary  │
│  Code    │    │          │    │          │    │          │    │          │    │   Code   │    │          │
└──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
     │               │               │               │               │               │               │
     │               │               │               │               │               │               │
  Scanner         Parser          Checker         Lowerer           SSA           Codegen         Linker
                                                                 Conversion
```

Let's understand each stage:

---

## Stage 1: Scanning (Lexical Analysis)

**What it does:** Breaks source code into tokens (words)

**Analogy:** Reading a sentence and identifying each word and punctuation mark.

```
Source Code:                     Tokens:

fn main() i64 {          ───▶    [fn] [main] [(] [)] [i64] [{]
    return 42                    [return] [42]
}                                [}]
```

The scanner reads your source code character by character and groups them into meaningful units called **tokens**:

| Token Type | Examples |
|------------|----------|
| Keywords | `fn`, `return`, `if`, `while`, `struct` |
| Identifiers | `main`, `foo`, `myVariable` |
| Literals | `42`, `3.14`, `"hello"`, `true` |
| Operators | `+`, `-`, `*`, `==`, `>=` |
| Punctuation | `(`, `)`, `{`, `}`, `:`, `,` |

**Key insight:** The scanner doesn't understand what your code *means*. It just breaks it into pieces. `fn main()` and `fn 42()` both produce valid tokens, even though the second makes no sense.

**Files involved:**
- `src/scanner.zig` - The Zig implementation
- `src/scanner.cot` - The Cot wireframe (blueprint for self-hosting)
- `src/token.zig` / `src/token.cot` - Token type definitions

---

## Stage 2: Parsing (Syntactic Analysis)

**What it does:** Builds a tree structure from tokens

**Analogy:** Diagramming a sentence to show how words relate to each other.

```
Tokens:                          AST (Abstract Syntax Tree):

[fn] [main] [(] [)] [i64]        FnDecl
[{] [return] [42] [;] [}]          ├── name: "main"
                                   ├── params: []
                         ───▶      ├── return_type: i64
                                   └── body: Block
                                         └── ReturnStmt
                                               └── value: IntLiteral(42)
```

The parser takes the flat list of tokens and builds a **tree** that shows the structure of your code. This tree is called an **Abstract Syntax Tree (AST)**.

Why a tree? Because code has nested structure:
- A function contains a body
- The body contains statements
- Statements contain expressions
- Expressions can contain other expressions

```
// This expression: (1 + 2) * 3
// Becomes this tree:

        Multiply
        /      \
     Add        3
    /   \
   1     2
```

**Key insight:** The parser checks *syntax* (grammar), not *meaning*. It will reject `fn fn fn` because that's not valid grammar. But it will accept `fn main() { return "hello"; }` even if main is supposed to return an integer.

**Files involved:**
- `src/parser.zig` - The Zig implementation
- `src/parser.cot` - The Cot wireframe
- `src/ast.zig` / `src/ast.cot` - AST node definitions

---

## Stage 3: Type Checking (Semantic Analysis)

**What it does:** Verifies that the code makes sense

**Analogy:** Proofreading to make sure sentences are meaningful, not just grammatically correct.

```
AST (unchecked):                 AST (with types):

FnDecl                           FnDecl
  ├── name: "main"                 ├── name: "main"
  ├── return_type: i64             ├── return_type: i64
  └── body:                        └── body:
        ReturnStmt         ───▶          ReturnStmt
          └── IntLiteral(42)               └── IntLiteral(42)
                                               type: i64 ✓ matches!
```

The type checker walks through the AST and:

1. **Resolves names:** When you write `x + 1`, it finds what `x` refers to
2. **Infers types:** Figures out that `42` is an integer, `3.14` is a float
3. **Checks compatibility:** Makes sure you're not adding a string to a number
4. **Reports errors:** "Cannot return string from function expecting i64"

```cot
fn add(a: i64, b: i64) i64 {
    return a + b      // ✓ OK: a and b are both i64, result is i64
}

fn broken() i64 {
    return "hello"    // ✗ ERROR: expected i64, got string
}
```

**Key concepts introduced:**
- **Symbol table:** A map from names to their definitions
- **Scope:** Where a name is visible (local variables, function parameters, globals)
- **Type registry:** A database of all types in the program

**Files involved:**
- `src/check.zig` - The Zig implementation
- `src/checker.cot` - The Cot wireframe
- `src/types.zig` / `src/types.cot` - Type definitions

---

## Stage 4: IR Lowering

**What it does:** Simplifies the AST into a lower-level representation

**Analogy:** Converting a recipe with fancy techniques into basic step-by-step instructions.

```
AST:                             IR (Intermediate Representation):

ForStmt                          Block 0:
  ├── binding: "i"                 local.0 = const 0        ; i = 0
  ├── range: 0..3          ───▶  Block 1 (loop_header):
  └── body:                        cmp local.0, 3           ; i < 3?
        print(i)                   branch Block2, Block3
                                 Block 2 (loop_body):
                                   call print, local.0      ; print(i)
                                   local.0 = add local.0, 1 ; i++
                                   jump Block1
                                 Block 3 (loop_exit):
                                   ...
```

The IR is simpler than the AST:
- **No fancy loops:** `for x in 0..10` becomes `while` with explicit counter
- **No compound assignments:** `x += 1` becomes `x = x + 1`
- **No method syntax:** `obj.method(arg)` becomes `method(obj, arg)`
- **Explicit control flow:** Uses basic blocks with jumps and branches

**Why bother?** This simpler form is easier to:
1. Optimize (find patterns to make code faster)
2. Convert to machine code (fewer cases to handle)

**Key concepts introduced:**
- **Basic blocks:** Sequences of instructions with one entry and one exit
- **Control flow graph:** How blocks connect via jumps and branches
- **Operations (Ops):** Simple instructions like `add`, `sub`, `call`, `load`, `store`

**Files involved:**
- `src/lower.zig` - The Zig implementation
- `src/ir.zig` / `src/ir.cot` - IR definitions

---

## Stage 5: SSA Conversion

**What it does:** Renames variables so each is assigned only once

**Analogy:** Instead of reusing a variable name, give each value a unique ID.

```
IR:                              SSA:

x = 1                            x.1 = 1
x = x + 1            ───▶        x.2 = x.1 + 1
x = x * 2                        x.3 = x.2 * 2
return x                         return x.3
```

SSA stands for **Static Single Assignment**. The rule is simple: every variable is assigned exactly once.

Why? It makes optimization much easier:
- You can see exactly where each value comes from
- You can safely reorder or eliminate code
- You can allocate registers more efficiently

**The tricky part:** What about conditionals?

```cot
var x: i64
if condition {
    x = 1
} else {
    x = 2
}
// Which x do we use here?
```

SSA solves this with **phi nodes** (φ):

```
if condition:
    x.1 = 1
    jump merge
else:
    x.2 = 2
    jump merge
merge:
    x.3 = φ(x.1, x.2)    // "x.3 is x.1 if we came from 'if', x.2 if from 'else'"
```

**Files involved:**
- `src/ssa.zig` - SSA conversion

---

## Stage 6: Code Generation

**What it does:** Converts SSA into actual machine instructions

**Analogy:** Translating instructions into the specific language your CPU speaks.

```
SSA:                             ARM64 Assembly:

x.1 = const 42                   mov x0, #42
x.2 = x.1 + 1          ───▶      add x0, x0, #1
return x.2                       ret
```

This is where the compiler finally produces something the CPU can execute. Different CPUs understand different instructions:

| CPU Architecture | Used In | Our Files |
|-----------------|---------|-----------|
| ARM64 (AArch64) | Mac M1/M2/M3, iPhones, most phones | `src/codegen/arm64.zig` |
| x86_64 | Intel/AMD PCs, older Macs | `src/codegen/x86_64.zig` |

**Key concepts:**
- **Registers:** Tiny, super-fast storage locations in the CPU (ARM64 has x0-x30, x86_64 has rax, rbx, etc.)
- **Stack:** Memory for local variables, function calls
- **Instructions:** Operations the CPU can perform (mov, add, sub, cmp, jmp, call, ret)

**The code generator must handle:**
1. **Register allocation:** Deciding which values live in which registers
2. **Instruction selection:** Choosing the right CPU instruction for each operation
3. **Calling conventions:** How to pass arguments to functions, where return values go
4. **Stack frame layout:** Where local variables are stored in memory

**Files involved:**
- `src/codegen/arm64.zig` - ARM64 code generation
- `src/codegen/x86_64.zig` - x86_64 code generation
- `src/codegen.zig` - Shared codegen infrastructure

---

## Stage 7: Linking

**What it does:** Combines object files into an executable

**Analogy:** Assembling chapters into a complete book with a table of contents.

```
Object Files:                    Executable:

┌─────────────┐                  ┌─────────────────┐
│  main.o     │                  │  Header         │
│  (your code)│                  │  (metadata)     │
└─────────────┘                  ├─────────────────┤
       +            ───▶         │  Code Section   │
┌─────────────┐                  │  (machine code) │
│  runtime.o  │                  ├─────────────────┤
│  (print,etc)│                  │  Data Section   │
└─────────────┘                  │  (strings, etc) │
                                 └─────────────────┘
```

The linker (we use `zig cc` which wraps the system linker):
1. **Resolves symbols:** Connects function calls to function definitions
2. **Assigns addresses:** Decides where each piece of code lives in memory
3. **Creates executable:** Produces a file the operating system can run

---

## Putting It All Together

Let's trace a simple program through the entire pipeline:

```cot
fn main() i64 {
    return 42
}
```

### Stage 1: Scanning
```
"fn main() i64 { return 42 }"
    ↓
[fn] [main] [(] [)] [i64] [{] [return] [42] [}] [EOF]
```

### Stage 2: Parsing
```
FnDecl {
    name: "main",
    params: [],
    return_type: TypeExpr("i64"),
    body: Block {
        stmts: [
            ReturnStmt {
                value: IntLiteral(42)
            }
        ]
    }
}
```

### Stage 3: Type Checking
```
FnDecl {
    name: "main",
    type: fn() -> i64,        // Added!
    body: Block {
        stmts: [
            ReturnStmt {
                value: IntLiteral(42),
                type: i64             // Added! Matches return type ✓
            }
        ]
    }
}
```

### Stage 4: IR Lowering
```
func main() -> i64:
    block0:
        v0 = const_int 42
        ret v0
```

### Stage 5: SSA
```
func main() -> i64:
    block0:
        v0 = const_int 42
        ret v0
(Already in SSA form - each value assigned once)
```

### Stage 6: Code Generation (ARM64)
```asm
_main:
    mov x0, #42     ; Put 42 in register x0 (return value register)
    ret             ; Return to caller
```

### Stage 7: Linking
```
Executable created: ./program
```

### Execution
```
$ ./program
$ echo $?
42
```

The program runs! The operating system loads it into memory, jumps to `_main`, the CPU executes `mov x0, #42` and `ret`, and the shell displays the exit code 42.

---

## What Makes Cot Special?

Cot is designed to be **self-hosting** - the Cot compiler will eventually be written in Cot itself. This is called **bootstrapping**.

Currently:
```
┌─────────────┐         ┌─────────────┐
│  Cot Source │ ──────▶ │  Executable │
│   (.cot)    │   Zig   │             │
└─────────────┘ Compiler└─────────────┘
```

Goal (after bootstrap):
```
┌─────────────┐         ┌─────────────┐
│  Cot Source │ ──────▶ │  Executable │
│   (.cot)    │   Cot   │             │
└─────────────┘ Compiler└─────────────┘
```

The `.cot` files in `src/` are **wireframes** - they define how the compiler *will* look in Cot, and guide the Zig implementation.

---

## Next Steps

Now that you understand the big picture, you can dive deeper:

1. **[02_ZIG_PRIMER.md](02_ZIG_PRIMER.md)** - Learn Zig concepts used in the implementation
2. **[pipeline/10_SCANNING.md](pipeline/10_SCANNING.md)** - Deep dive into the scanner
3. **[cpu/20_CPU_BASICS.md](cpu/20_CPU_BASICS.md)** - Understanding how CPUs work

---

## Glossary

| Term | Definition |
|------|------------|
| **AST** | Abstract Syntax Tree - tree representation of code structure |
| **Basic Block** | Sequence of instructions with single entry/exit |
| **Codegen** | Code generation - producing machine code |
| **IR** | Intermediate Representation - simplified code between AST and machine code |
| **Lexer/Scanner** | Breaks source code into tokens |
| **Linker** | Combines object files into executable |
| **Parser** | Builds AST from tokens |
| **Register** | Fast storage location in CPU |
| **SSA** | Static Single Assignment - each variable assigned once |
| **Symbol Table** | Map from names to their definitions |
| **Token** | Smallest meaningful unit (keyword, identifier, operator) |
| **Type Checker** | Verifies code makes sense (types match, names exist) |
