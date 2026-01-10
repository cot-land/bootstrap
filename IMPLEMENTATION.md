# Cot 0.2 Implementation Guide

How each file maps Go's compiler design to Zig.

## Roadmap to Self-Hosting

### Phase 1: Working Zig Compiler (Current)

Build a complete compiler in Zig that can compile simple cot programs.

**Milestone 1.1: Core Pipeline** ✓ Complete
- [x] Scanner/lexer (scanner.zig)
- [x] Parser (parser.zig)
- [x] Type checker (check.zig)
- [x] IR generation (ir.zig)
- [x] SSA form (ssa.zig)
- [x] x86-64 codegen (codegen/x86_64.zig)
- [x] ARM64 codegen (codegen/aarch64.zig)
- [x] Object file generation (codegen/object.zig)
- [x] Debug infrastructure (debug.zig)

**Milestone 1.2: Working CLI** ✓ Complete
- [x] Driver (driver.zig) - orchestrate full pipeline
- [x] Linker integration - shell out to system linker (cc)
- [x] CLI arguments - `cot build file.cot`
- [x] Test with simple programs (parses and type-checks)

**Milestone 1.3: Language Completeness**
- [x] String handling and string literals in codegen
- [x] len() builtin for strings
- [x] String equality (==, !=) with constant folding
- [x] Function calls with arguments
- [x] If/else control flow in codegen
- [x] While loops in codegen
- [x] Struct support (definition, literal init, field access)
- [x] Array literals and constant indexing
- [x] Dynamic array indexing (runtime index) - ARM64 working, x86_64 has stack layout issues with large arrays
- [x] Slice support (compile-time) - arr[i:j] syntax, len() constant folding
- [x] Slice support (runtime) - ptr+len storage (16 bytes), len() on slice variables
- [x] Slice indexing (runtime) - s[i] access
- [x] Switch expressions - switch x { 1 => a, 2 => b, else => c }
- [x] For-in loops - `for x in arr { ... }` (arrays and slices)
- [ ] Standard library basics (print, memory)

**Automated Test Runner**

A test runner script (`run_tests.sh`) verifies all tests produce expected exit codes:
```bash
./run_tests.sh  # Runs all tests, reports pass/fail
```

**Unhandled SSA Op Detection**

Running with `--debug-codegen` will show warnings for any unhandled SSA operations:
```bash
./zig-out/bin/cot tests/test_file.cot --debug-codegen -o test
# Output: [WARN] Unhandled AArch64 SSA op: <op_name>
```

### Verified Test Results (January 2026)

**Test Counts:**
- 129 Zig embedded tests (unit tests in source files)
- 36 binary tests (.cot test files)

**Both ARM64 and x86_64** - 36/36 tests pass

| Test File | Expected | ARM64 | x86_64 |
|-----------|----------|-------|--------|
| test_return.cot (return 42) | 42 | PASS | PASS |
| test_const.cot (return 42) | 42 | PASS | PASS |
| test_bool.cot (return true as int) | 1 | PASS | PASS |
| test_call.cot (function call) | 42 | PASS | PASS |
| test_len.cot (len("hello")) | 5 | PASS | PASS |
| test_len2.cot (len("hello world!")) | 12 | PASS | PASS |
| test_string.cot (string length) | 5 | PASS | PASS |
| test_struct.cot (struct field .x access) | 10 | PASS | PASS |
| test_struct2.cot (struct field .y access) | 20 | PASS | PASS |
| test_array.cot (arr[0]) | 10 | PASS | PASS |
| test_array2.cot (arr[1]) | 20 | PASS | PASS |
| test_array3.cot (arr[2]) | 30 | PASS | PASS |
| test_array_dyn.cot (arr[i] where i=1) | 20 | PASS | PASS |
| test_array_dyn2.cot (arr[i] where i=4, 5-elem) | 50 | PASS | PASS |
| test_array_dyn3.cot (arr[i] where i=1, 2-elem) | 20 | PASS | PASS |
| test_5elem.cot (5-element array) | 50 | PASS | PASS |
| test_slice.cot (create slice arr[1:3]) | 42 | PASS | PASS |
| test_slice_len.cot (len(s) where s=arr[1:4]) | 3 | PASS | PASS |
| test_slice_len2.cot (len(arr[1:4]) inline) | 3 | PASS | PASS |
| test_sub.cot (50 - 8) | 42 | PASS | PASS |
| test_mul.cot (6 * 7) | 42 | PASS | PASS |
| test_div.cot (84 / 2) | 42 | PASS | PASS |
| test_switch.cot (switch expression) | 42 | PASS | PASS |
| test_slice_index.cot (s[i] access) | 30 | PASS | PASS |
| test_for_array.cot (for x in arr) | 60 | PASS | PASS |
| test_for_slice.cot (for x in slice) | 90 | PASS | PASS |

**All tests pass** - conditionals, while loops, string comparisons, switch expressions, slice indexing, and for-in loops now working.

### Testing Commands

```bash
# Run ARM64 tests (native macOS)
./run_tests.sh

# Run x86_64 tests (Docker)
./docker_test.sh

# Build x86_64 and run all tests (builds Docker image if needed)
./docker_test.sh --build-image
```

**Docker Setup for x86_64 Testing**

The project includes a pre-configured Docker setup for x86_64 testing:
- `Dockerfile.x86_64` - Debian-based image with gcc, libc6-dev, binutils pre-installed
- `run_tests_x86_64.sh` - Test runner script for use inside Docker container
- `docker_test.sh` - Convenience script that builds cot, manages Docker image, and runs tests

```bash
# Single test on ARM64 (native macOS)
zig build && ./zig-out/bin/cot tests/test_file.cot -o test && ./test; echo "Exit: $?"

# Single test on x86_64 (Docker)
zig build -Dtarget=x86_64-linux-gnu
docker run --platform linux/amd64 -v $(pwd):/cot -w /cot cot-x86_64 \
  sh -c "./zig-out/bin/cot tests/test_file.cot -o ignored; gcc -o test test_file.o && ./test; echo Exit: \$?"
```

**Note**: Must use `gcc` to link (not bare `ld`) because `main` returns a value.
The C runtime's `_start` calls `exit(main())`. Using `ld -e main` causes segfault.

### Phase 2: Bootstrap Preparation ✓ Complete

Write cot source files that will form the self-hosted compiler.

**Milestone 2.1: Core Data Structures** ✓ Complete
- [x] token.cot - Token enum and keyword table
- [x] source.cot - Source text handling
- [x] ast.cot - AST node types

**Milestone 2.2: Frontend** ✓ Complete
- [x] scanner.cot - Lexer
- [x] parser.cot - Parser
- [x] errors.cot - Error handling

**Milestone 2.3: Middle-end** ✓ Complete
- [x] types.cot - Type system
- [x] checker.cot - Type checker (maps to check.zig)
- [x] ir.cot - IR generation

### Phase 3: Self-Hosting

Use the Zig compiler to compile the cot compiler written in cot.

**Milestone 3.1: Compile cot with Zig**
- [ ] Compile token.cot, scanner.cot, etc. to object files
- [ ] Link into working cot-stage1 executable
- [ ] Verify cot-stage1 can parse itself

**Milestone 3.2: Full Bootstrap**
- [ ] cot-stage1 compiles cot source → cot-stage2
- [ ] cot-stage2 compiles cot source → cot-stage3
- [ ] Verify stage2 == stage3 (bootstrap complete)

### Phase 4: Post-Bootstrap (Future)

Features that can wait until after self-hosting.

- [ ] Optimization passes (constant folding, DCE, etc.)
- [ ] ARC memory management
- [ ] Traits/interfaces
- [ ] Generics
- [ ] Package system
- [ ] REPL
- [ ] LSP server

---

## Current Status

```
cot/
  build.zig       ✓ Project configuration
  src/
    main.zig      ✓ Entry point
    token.zig     ✓ Token definitions (4 tests passing)
    source.zig    ✓ Source text handling (4 tests passing)
    scanner.zig   ✓ Lexer (6 tests passing)
    errors.zig    ✓ Error handling (4 tests passing)
    ast.zig       ✓ AST nodes (4 tests passing)
    parser.zig    ✓ Parser (7 tests passing)
    types.zig     ✓ Type representation (6 tests passing)
    check.zig     ✓ Type checker (6 tests passing)
    ir.zig        ✓ Intermediate representation (6 tests passing)
    ssa.zig       ✓ SSA form (6 tests passing)
    debug.zig     ✓ Debug/trace infrastructure (3 tests passing)
    driver.zig    ✓ Compilation driver (3 tests passing)
    codegen/
      backend.zig   ✓ Backend interface & storage (3 tests passing)
      x86_64.zig    ✓ x86-64 assembler (7 tests passing)
      aarch64.zig   ✓ ARM64 assembler (5 tests passing)
      object.zig    ✓ ELF/Mach-O generation (5 tests passing)

    # Bootstrap wireframes (.cot files for self-hosting)
    token.cot     ✓ Token definitions (wireframe)
    source.cot    ✓ Source text handling (wireframe)
    ast.cot       ✓ AST node types (wireframe)
    scanner.cot   ✓ Lexer (wireframe)
    parser.cot    ✓ Parser (wireframe)
    errors.cot    ✓ Error handling (wireframe)
    types.cot     ✓ Type system (wireframe)
    checker.cot   ✓ Type checker (wireframe)
    ir.cot        ✓ IR generation (wireframe)
```

## File Descriptions

### build.zig

**Purpose:** Zig build configuration.

**Commands:**
- `zig build` - compile the compiler
- `zig build run -- file.cot` - run compiler on a file
- `zig build test` - run all tests

---

### src/main.zig

**Purpose:** Compiler entry point. Parses command-line args, orchestrates compilation.

**Go equivalent:** `cmd/compile/main.go`

---

### src/token.zig (next)

**Purpose:** Defines all tokens in the language.

**Go equivalent:** `cmd/compile/internal/syntax/tokens.go`

**What it contains:**
- Token enum (keywords, operators, literals, delimiters)
- Operator precedence levels
- Keyword lookup table

**Key pattern from Go:**
```go
// Go uses iota for sequential token values
const (
    _EOF token = iota
    _Name
    _Literal
    // ...
)
```

**Zig equivalent:**
```zig
// Zig uses enum with explicit values
pub const Token = enum(u8) {
    eof,
    identifier,
    literal,
    // ...
};
```

---

### src/source.zig

**Purpose:** Manages source text, tracks positions for error messages.

**Go equivalent:** `cmd/compile/internal/syntax/source.go`, `cmd/internal/src/pos.go`

**What it contains:**
- Source struct (holds file content)
- Position tracking (line, column)
- Span for error ranges

**Key pattern from Go:**
Go uses `src.XPos` which is a compact position encoding. We'll use a simpler struct initially.

---

### src/scanner.zig

**Purpose:** Lexer - converts source text into tokens.

**Go equivalent:** `cmd/compile/internal/syntax/scanner.go`

**What it contains:**
- Scanner struct with source and position
- `next()` function to advance and return token
- Character classification helpers
- String/number literal parsing

**Key pattern from Go:**
```go
func (s *scanner) next() {
    // skip whitespace
    // identify token type
    // consume token characters
}
```

---

### src/errors.zig

**Purpose:** Error handling infrastructure for consistent error reporting.

**Go equivalent:** Error handling patterns from `cmd/compile/internal/syntax/syntax.go` and `parser.go`

**What it contains:**
- Error struct with span, message, and optional error code
- ErrorCode enum for categorized errors (scanner: 1xx, parser: 2xx, type: 3xx)
- ErrorHandler callback type for external error handling
- ErrorReporter struct for collecting and displaying errors
- Trace mode flag for debug output

**Key pattern from Go:**
```go
// Go's simple error struct
type Error struct {
    Pos Pos
    Msg string
}

// ErrorHandler callback
type ErrorHandler func(err error)
```

**Zig equivalent:**
```zig
pub const Error = struct {
    span: Span,
    msg: []const u8,
    code: ?ErrorCode = null,
};

pub const ErrorHandler = *const fn (err: Error) void;

pub const ErrorReporter = struct {
    src: *Source,
    handler: ?ErrorHandler,
    first: ?Error,
    count: u32,
    // ...
};
```

---

### src/ast.zig

**Purpose:** Defines all AST node types.

**Go equivalent:** `cmd/compile/internal/syntax/nodes.go`

**What it contains:**
- `NodeIndex` (u32) for referencing nodes in the pool
- `Decl` union (fn_decl, var_decl, const_decl, struct_decl, enum_decl)
- `Expr` union (identifier, literal, binary, unary, call, index, field_access, etc.)
- `Stmt` union (expr_stmt, return_stmt, var_stmt, assign_stmt, if_stmt, while_stmt, for_stmt)
- `TypeExpr` for type expressions (named, pointer, optional, slice, array)
- `Ast` struct for arena-based storage with addNode/getNode/getExpr/getStmt/getDecl

**Key pattern from Go:**
Go uses interface embedding with `node` base struct. Zig uses tagged unions.

```zig
// Zig pattern:
pub const Expr = union(enum) {
    identifier: Identifier,
    literal: Literal,
    binary: Binary,
    // ...
};

pub const Ast = struct {
    nodes: std.ArrayList(Node),
    pub fn addNode(self: *Ast, node: Node) !NodeIndex { ... }
    pub fn getNode(self: *const Ast, idx: NodeIndex) Node { ... }
};
```

---

### src/parser.zig

**Purpose:** Parses tokens into AST.

**Go equivalent:** `cmd/compile/internal/syntax/parser.go`

**What it contains:**
- Parser struct with scanner, current token, AST, and error reporter
- `parseFile()` - parses complete source file into declarations
- `parseDecl()` - function, var, const, struct declarations
- `parseExpr()` / `parseBinaryExpr()` - precedence climbing for expressions
- `parseStmt()` - statements (return, if, while, for, assignment)
- Error recovery via error reporting without crashing

**Key pattern from Go:**
Go's parser uses recursive descent with precedence levels for binary expressions.

```zig
// Precedence climbing (from Go's binaryExpr)
fn parseBinaryExpr(self: *Parser, min_prec: u8) ParseError!?NodeIndex {
    var left = try self.parseUnaryExpr() orelse return null;
    while (true) {
        const prec = token.binaryPrecedence(self.tok.tok);
        if (@intFromEnum(prec) <= min_prec) break;
        // ... parse right operand with higher precedence
    }
    return left;
}
```

**Declarations supported:**
- `fn name(params) type { body }`
- `var/let name: type = value`
- `const name: type = value`
- `struct Name { fields }`

**Statements supported:**
- `return value`
- `if cond { } else { }`
- `while cond { }`
- `for item in iter { }`
- `break`, `continue`
- Expression statements and assignments

---

### src/types.zig

**Purpose:** Type representation and type registry.

**Go equivalent:** `cmd/compile/internal/types2/basic.go`, `pointer.go`, `slice.go`, `struct.go`

**What it contains:**
- `BasicKind` enum for primitive types (i8-i64, u8-u64, f32, f64, bool, string, void)
- `AlphaType` / `DecimalType` for DBL-compatible fixed types
- `PointerType`, `OptionalType`, `SliceType`, `ArrayType` for composite types
- `StructType`, `FuncType`, `NamedType` for complex types
- `Type` tagged union containing all type variants
- `TypeRegistry` for type interning with pre-registered basic types

**Key pattern from Go:**
Go uses separate struct types for each kind, we use a tagged union.

```zig
// Type indices for fast comparison
pub const TypeIndex = u32;

// Pre-registered basic types
pub const TypeRegistry = struct {
    pub const BOOL: TypeIndex = 1;
    pub const INT: TypeIndex = 5;  // i64
    pub const STRING: TypeIndex = 12;
    // ...
};

// Type aliases (cot's friendly names)
pub const INT = I64;    // int = i64
pub const FLOAT = F64;  // float = f64
pub const BYTE = U8;    // byte = u8
```

**DBL-compatible fixed types:**
- `alpha(N)` - fixed-length string (like DBL's a30)
- `decimal(N)` - fixed-point integer (like DBL's d10)
- `decimal(N,P)` - fixed-point with scale (like DBL's d8.2)

---

## Design Principles (from Go)

1. **Dense token IDs** - Token enum values are sequential, enabling array lookups.

2. **Position tracking** - Every token carries its source position for error messages.

3. **Precedence climbing** - Binary expression parsing uses precedence levels, not separate functions per level.

4. **No separate lexer pass** - Parser calls scanner on demand, not tokenizing entire file first.

5. **Simple error recovery** - On error, skip to synchronization point (`;`, `}`, etc.).

---

### src/check.zig

**Purpose:** Type checker - validates AST and resolves types.

**Go equivalent:** `cmd/compile/internal/types2/` (checker.go, resolver.go, decl.go, expr.go, stmt.go)

**What it contains:**
- `Checker` struct with type registry, current scope, error reporter
- `Scope` struct for lexical scoping (nested symbol tables)
- `Symbol` for variables, functions, types in scope
- `checkFile()` - type check all declarations
- `checkDecl()` - validate function signatures, struct fields
- `checkExpr()` - infer/check expression types, return TypeIndex
- `checkStmt()` - validate statements, check return types match

**Key responsibilities:**
1. **Name resolution** - resolve identifiers to their declarations
2. **Type inference** - infer types for `var x = expr`
3. **Type checking** - verify operand types match operators
4. **Constant folding** - evaluate compile-time constants
5. **Mode enforcement** - reject pointer syntax in `@mode safe`

**Key pattern from Go:**
```go
// Go's Checker walks the AST and builds typed info
type Checker struct {
    conf    *Config
    pkg     *Package
    info    *Info  // type information collected
    scope   *Scope
}

func (check *Checker) expr(x *operand, e ast.Expr) {
    // determine type of expression
}
```

**Zig equivalent:**
```zig
pub const Checker = struct {
    types: *TypeRegistry,
    scope: *Scope,
    err: *ErrorReporter,
    ast: *const Ast,

    pub fn checkExpr(self: *Checker, idx: NodeIndex) !TypeIndex { ... }
    pub fn checkStmt(self: *Checker, idx: NodeIndex) !void { ... }
};

pub const Scope = struct {
    parent: ?*Scope,
    symbols: std.StringHashMap(Symbol),
};
```

**Output:** Annotated AST with type information attached to each node, ready for IR generation.

---

### src/ir.zig

**Purpose:** Typed intermediate representation - bridge between AST and SSA.

**Go equivalent:** `cmd/compile/internal/ir/` (node.go, func.go, expr.go, stmt.go)

**What it contains:**
- `IR` struct holding all IR nodes
- `Func` for function bodies with typed parameters/returns
- `Node` union for IR operations (simpler than AST)
- `LocalVar` for stack-allocated variables with types
- Control flow representation (basic structure, not SSA yet)

**Key pattern from Go:**
Go's IR is a typed, lowered form of the AST. Many AST constructs desugar:
- `for item in array` → index-based loop
- `a += b` → `a = a + b`
- Method calls → function calls with receiver

```go
// Go's IR nodes are simpler than AST
type Node struct {
    op   Op
    Type *types.Type
    // ...
}
```

**Zig equivalent:**
```zig
pub const Node = struct {
    op: Op,
    type_idx: TypeIndex,
    args: []const NodeIndex,
    span: Span,
};

pub const Op = enum {
    // Constants
    const_int,
    const_float,
    const_string,

    // Operations
    add, sub, mul, div,
    eq, ne, lt, le, gt, ge,

    // Memory
    local,      // stack variable
    load,       // read from address
    store,      // write to address

    // Control
    call,
    ret,
    branch,
    phi,        // SSA phi node (added in SSA pass)
};
```

**Output:** Flat list of typed operations per function, ready for SSA construction.

---

### src/ssa.zig (next)

**Purpose:** SSA form construction and optimization passes.

**Go equivalent:** `cmd/compile/internal/ssa/` (compile.go, func.go, block.go, value.go)

**What it contains:**
- `SSA` struct for SSA representation
- `Block` for basic blocks with predecessors/successors
- `Value` for SSA values (each assigned exactly once)
- `buildSSA()` - convert IR to SSA form
- Dominator tree construction
- Phi node insertion

**Key pattern from Go:**
```go
// Go's SSA structure
type Func struct {
    Blocks []*Block
    Entry  *Block
}

type Block struct {
    ID      ID
    Preds   []*Block
    Succs   []*Block
    Values  []*Value
    Control *Value  // branch condition
}

type Value struct {
    ID   ID
    Op   Op
    Type *types.Type
    Args []*Value
}
```

**Zig equivalent:**
```zig
pub const Func = struct {
    blocks: std.ArrayList(Block),
    entry: BlockIndex,
};

pub const Block = struct {
    id: BlockIndex,
    preds: []const BlockIndex,
    succs: []const BlockIndex,
    values: []const ValueIndex,
    control: ?ValueIndex,
};

pub const Value = struct {
    id: ValueIndex,
    op: Op,
    type_idx: TypeIndex,
    args: []const ValueIndex,
    block: BlockIndex,
};
```

**SSA construction algorithm:**
1. Build control flow graph (basic blocks)
2. Compute dominance frontiers
3. Insert phi nodes at dominance frontiers
4. Rename variables to SSA form

**Output:** SSA form ready for optimization passes and code generation.

---

### src/ssa/passes.zig

**Purpose:** SSA optimization passes.

**Go equivalent:** `cmd/compile/internal/ssa/*.go` (opt.go, lower.go, deadcode.go, etc.)

**Passes to implement (in order of importance):**

1. **Dead code elimination** - remove unused values
2. **Constant propagation** - replace variables with known constants
3. **Copy propagation** - eliminate redundant copies
4. **Common subexpression elimination** - reuse computed values
5. **Strength reduction** - replace expensive ops (mul → shift)
6. **Inlining** - inline small functions (post-bootstrap)

**Key pattern from Go:**
Each pass is a function that transforms the SSA:
```go
func deadcode(f *Func) {
    // mark live values, remove dead ones
}
```

**Zig equivalent:**
```zig
pub fn deadcode(func: *ssa.Func) void { ... }
pub fn constprop(func: *ssa.Func) void { ... }
pub fn copyprop(func: *ssa.Func) void { ... }
```

---

### src/codegen/ (directory)

**Purpose:** Generate native machine code from SSA. Direct x86-64 and ARM64 emission.

**Go equivalent:** `cmd/compile/internal/ssagen/ssa.go`, `cmd/compile/internal/amd64/`, `cmd/internal/obj/`

**Roc reference:** `~/learning/roc/crates/compiler/gen_dev/src/generic64/`

**Architecture:** Trait-based polymorphism (from Roc's design)

```
           ┌──────────────────────────┐
           │    Backend (trait)        │
           │  (high-level operations)  │
           └──────────────────────────┘
                       ↑
         ┌─────────────┴─────────────┐
         ↓                           ↓
    Assembler Trait            CallConv Trait
    (instruction encoding)     (calling conventions)
         │                           │
    ├─ x86_64.zig              ├─ SystemV (Unix)
    └─ aarch64.zig             └─ Win64 (Windows)
```

**File structure:**
```
src/codegen/
  backend.zig       - Backend trait, StorageManager
  x86_64.zig        - x86-64 instruction encoding (~1500 lines)
  aarch64.zig       - ARM64 instruction encoding (~1500 lines)
  callconv.zig      - Calling convention traits
  object.zig        - ELF/Mach-O object file generation
  reloc.zig         - Relocation handling
```

**Key traits (Zig interfaces):**

```zig
// Instruction encoding - each arch implements this
pub fn Assembler(comptime Reg: type, comptime FloatReg: type) type {
    return struct {
        pub const Iface = struct {
            addRegReg: *const fn (*Self, Reg, Reg) void,
            subRegReg: *const fn (*Self, Reg, Reg) void,
            movRegImm: *const fn (*Self, Reg, i64) void,
            movRegMem: *const fn (*Self, Reg, i32) void,  // [rbp+offset]
            call: *const fn (*Self, Reg) void,
            ret: *const fn (*Self) void,
            // ... ~50 methods
        };
    };
}

// Calling convention - SystemV, Win64, etc.
pub fn CallConv(comptime Reg: type, comptime FloatReg: type) type {
    return struct {
        // Which registers hold arguments
        param_regs: []const Reg,
        // Which registers are callee-saved
        callee_saved: []const Reg,
        // Return value register(s)
        return_regs: []const Reg,
        // Stack alignment requirement
        stack_align: u8,
    };
}
```

**x86-64 register definitions:**
```zig
pub const X86Reg = enum(u4) {
    rax = 0, rcx = 1, rdx = 2, rbx = 3,
    rsp = 4, rbp = 5, rsi = 6, rdi = 7,
    r8 = 8, r9 = 9, r10 = 10, r11 = 11,
    r12 = 12, r13 = 13, r14 = 14, r15 = 15,

    pub fn encoding(self: X86Reg) u4 {
        return @intFromEnum(self);
    }
};

// SystemV ABI (Linux, macOS)
pub const SystemV = CallConv(X86Reg, X86FloatReg){
    .param_regs = &.{ .rdi, .rsi, .rdx, .rcx, .r8, .r9 },
    .callee_saved = &.{ .rbx, .r12, .r13, .r14, .r15, .rbp },
    .return_regs = &.{ .rax, .rdx },
    .stack_align = 16,
};
```

**Storage Manager (register allocation):**
```zig
pub const StorageManager = struct {
    symbol_storage: std.StringHashMap(Storage),
    stack_offset: i32,
    free_regs: RegSet,

    pub const Storage = union(enum) {
        reg: Reg,                    // Value in register
        stack: i32,                  // Value at [rbp+offset]
        spilled: struct { reg: Reg, stack: i32 },  // Both
    };

    pub fn allocate(self: *StorageManager, sym: []const u8, size: u32) Storage { ... }
    pub fn spill(self: *StorageManager, reg: Reg) void { ... }
    pub fn free(self: *StorageManager, sym: []const u8) void { ... }
};
```

**Instruction encoding example (x86-64 ADD):**
```zig
// ADD r64, r64 → REX.W + 01 /r
pub fn addRegReg(self: *X86Backend, dst: X86Reg, src: X86Reg) void {
    const rex = 0x48 | (src.needsRex() << 2) | dst.needsRex();
    self.emit(&.{ rex, 0x01, modrm(.reg, src, dst) });
}

fn modrm(mod: Mod, reg: X86Reg, rm: X86Reg) u8 {
    return (@intFromEnum(mod) << 6) | (reg.low3() << 3) | rm.low3();
}
```

**Object file generation:**
```zig
pub const ObjectFile = struct {
    sections: std.ArrayList(Section),
    symbols: std.ArrayList(Symbol),
    relocations: std.ArrayList(Relocation),

    pub fn emit(self: *ObjectFile, writer: anytype) !void {
        // Write ELF or Mach-O header
        // Write sections (.text, .data, .rodata)
        // Write symbol table
        // Write relocations
    }
};
```

**Code generation flow:**
```
SSA Func
    ↓
StorageManager.allocate() for each value
    ↓
For each SSA Block:
    For each SSA Value:
        Backend.emitValue(value)
            → Assembler.addRegReg() / movRegMem() / etc.
    ↓
ObjectFile.emit() → .o file
    ↓
System linker → executable
```

**Output:** Native object files (.o), linked with system linker to produce executable.

---

### src/arc.zig (future)

**Purpose:** Automatic Reference Counting runtime support.

**What it contains:**
- Reference count fields in heap objects
- `retain()` / `release()` intrinsics
- Weak reference support (post-bootstrap)
- Cycle detection (post-bootstrap, or use weak refs)

**Key pattern:**
```zig
pub const RcHeader = struct {
    count: u32,
};

pub fn retain(ptr: anytype) void {
    const header = @ptrCast(*RcHeader, ptr - @sizeOf(RcHeader));
    header.count += 1;
}

pub fn release(ptr: anytype) void {
    const header = @ptrCast(*RcHeader, ptr - @sizeOf(RcHeader));
    header.count -= 1;
    if (header.count == 0) {
        // call destructor, free memory
    }
}
```

The compiler inserts retain/release calls at appropriate points during IR generation.

---

## Compilation Pipeline Summary

```
Source (.cot)
    ↓
Scanner (source.zig, scanner.zig)
    ↓ tokens
Parser (parser.zig)
    ↓ AST (ast.zig)
Type Checker (check.zig)
    ↓ typed AST + type info
IR Generation (ir.zig)
    ↓ typed IR
SSA Construction (ssa.zig)
    ↓ SSA form
Optimization Passes (ssa/passes.zig)
    ↓ optimized SSA
Code Generation (codegen/)
    ↓ native machine code
Object File (codegen/object.zig)
    ↓ .o file (ELF/Mach-O)
System Linker (ld/lld)
    ↓
Executable
```

**Target architectures:**
- x86-64 (Linux, macOS, Windows)
- ARM64 (macOS, Linux)

**Design influences:**
- Go: SSA structure, compilation phases
- Roc: Trait-based backend architecture, direct object file generation
- Zig: Memory model, comptime patterns

---

## Code Quality Verification

Before any milestone is considered complete, verify:

1. **Zero TODO statements in code**
   ```bash
   grep -r "TODO" src/ --include="*.zig" | wc -l
   # Must be 0
   ```

2. **All tests pass**
   ```bash
   zig build test
   ```

3. **No compiler warnings**
   ```bash
   zig build 2>&1 | grep -i warning | wc -l
   # Must be 0
   ```

TODOs indicate unfinished work. Every TODO must be either:
- Completed and removed
- Converted to a GitHub issue and removed from code
- Explicitly deferred to a future milestone (documented in this file)
