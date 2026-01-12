# Module Reference Index

**Purpose:** Quick reference to key functions and structures in each compiler module

---

## How to Use This Reference

Each module section lists:
- **Key structs** - Main data structures
- **Key functions** - Important entry points
- **File location** - Where to find the source

For detailed explanations, see the pipeline docs in `docs/pipeline/`.

---

## Scanner (`src/scanner.zig`)

Breaks source code into tokens.

### Key Structs

| Struct | Purpose |
|--------|---------|
| `Scanner` | Holds scanning state (position, current char) |
| `TokenInfo` | Token with its span and text |

### Key Functions

| Function | Purpose | Line |
|----------|---------|------|
| `Scanner.init()` | Create new scanner | ~50 |
| `Scanner.next()` | Get next token | ~100 |
| `Scanner.scanIdentifier()` | Parse identifier/keyword | ~200 |
| `Scanner.scanNumber()` | Parse integer/float | ~250 |
| `Scanner.scanString()` | Parse string literal | ~300 |
| `Scanner.scanOperator()` | Parse operators | ~400 |

### Token Types (`src/token.zig`)

| Constant | Purpose |
|----------|---------|
| `Token.identifier` | Variable/function names |
| `Token.int_literal` | Integer constants |
| `Token.kw_fn` | `fn` keyword |
| `Token.kw_return` | `return` keyword |

---

## Parser (`src/parser.zig`)

Builds AST from tokens.

### Key Structs

| Struct | Purpose |
|--------|---------|
| `Parser` | Holds parsing state |
| `Ast` | The abstract syntax tree |

### Key Functions

| Function | Purpose | Line |
|----------|---------|------|
| `Parser.parse()` | Parse entire file | ~100 |
| `Parser.parseDecl()` | Parse declaration | ~200 |
| `Parser.parseFnDecl()` | Parse function | ~250 |
| `Parser.parseStmt()` | Parse statement | ~400 |
| `Parser.parseExpr()` | Parse expression | ~500 |
| `Parser.parseBinaryExpr()` | Handle precedence | ~550 |
| `Parser.parseType()` | Parse type annotation | ~700 |

### AST Nodes (`src/ast.zig`)

| Type | Purpose |
|------|---------|
| `ast.FnDecl` | Function declaration |
| `ast.VarStmt` | Variable declaration |
| `ast.ReturnStmt` | Return statement |
| `ast.Binary` | Binary expression |
| `ast.Literal` | Literal value |

---

## Type Checker (`src/check.zig`)

Validates types and resolves names.

### Key Structs

| Struct | Purpose |
|--------|---------|
| `Checker` | Holds type checking state |
| `Scope` | Symbol table for a scope |
| `Symbol` | Name binding (var, func, type) |

### Key Functions

| Function | Purpose | Line |
|----------|---------|------|
| `Checker.checkFile()` | Type check entire file | ~100 |
| `Checker.collectDecl()` | First pass: collect names | ~150 |
| `Checker.checkDecl()` | Second pass: check bodies | ~200 |
| `Checker.checkExpr()` | Type check expression | ~300 |
| `Checker.checkBinary()` | Check binary operation | ~400 |
| `Checker.isAssignable()` | Type compatibility check | ~600 |
| `Checker.resolveType()` | Resolve type expression | ~700 |

### Type Registry (`src/types.zig`)

| Constant | Value | Meaning |
|----------|-------|---------|
| `TypeRegistry.BOOL` | 1 | Boolean type |
| `TypeRegistry.I64` | 5 | 64-bit signed integer |
| `TypeRegistry.STRING` | 12 | String type ([]u8) |
| `TypeRegistry.VOID` | 13 | No return value |

---

## IR Lowering (`src/lower.zig`)

Transforms AST to IR.

### Key Structs

| Struct | Purpose |
|--------|---------|
| `Lowerer` | Lowering context |
| `ir.Builder` | Builds IR structures |
| `ir.FuncBuilder` | Builds a single function |

### Key Functions

| Function | Purpose | Line |
|----------|---------|------|
| `Lowerer.lower()` | Lower entire AST | ~100 |
| `Lowerer.lowerFnDecl()` | Lower function | ~130 |
| `Lowerer.lowerStmt()` | Lower statement | ~500 |
| `Lowerer.lowerExpr()` | Lower expression | ~700 |
| `Lowerer.lowerBinary()` | Lower binary op | ~800 |

### IR Structures (`src/ir.zig`)

| Type | Purpose |
|------|---------|
| `ir.Op` | IR operation enum |
| `ir.Node` | Single IR operation |
| `ir.Block` | Basic block |
| `ir.Func` | IR function |
| `ir.Local` | Local variable info |

---

## SSA Conversion (`src/ssa.zig`)

Converts IR to SSA form.

### Key Structs

| Struct | Purpose |
|--------|---------|
| `ssa.Func` | SSA function |
| `ssa.Block` | SSA basic block |
| `ssa.Value` | SSA value (assigned once) |

### Key Functions

| Function | Purpose | Line |
|----------|---------|------|
| `ssa.Func.init()` | Create SSA function | ~400 |
| `ssa.Func.newValue()` | Create new SSA value | ~450 |
| `ssa.Func.newBlock()` | Create new block | ~500 |
| `Block.addSucc()` | Add successor edge | ~350 |

### SSA Operations

| Op | Purpose |
|----|---------|
| `ssa.Op.const_int` | Integer constant |
| `ssa.Op.add` | Addition |
| `ssa.Op.phi` | Phi function (merge point) |
| `ssa.Op.ret` | Return |
| `ssa.Op.branch` | Conditional branch |

---

## Code Generation

### ARM64 (`src/codegen/arm64_codegen.zig`)

| Struct | Purpose |
|--------|---------|
| `CodeGen` | Main codegen struct |
| `MCValue` | Machine code value location |
| `RegisterManager` | Track register allocation |

| Function | Purpose | Line |
|----------|---------|------|
| `CodeGen.generate()` | Generate entire function | ~300 |
| `CodeGen.genValue()` | Generate single value | ~400 |
| `CodeGen.allocReg()` | Allocate register | ~250 |
| `CodeGen.spillReg()` | Spill register to stack | ~280 |

### ARM64 Instructions (`src/codegen/aarch64.zig`)

| Function | Instruction |
|----------|-------------|
| `movz()` | Move immediate |
| `addReg()` | Add registers |
| `addImm()` | Add immediate |
| `stpPre()` | Store pair, pre-index |
| `ldpPost()` | Load pair, post-index |
| `bl()` | Branch and link (call) |
| `ret()` | Return |

### x86_64 (`src/codegen/amd64_codegen.zig`)

Similar structure to ARM64 with x86_64-specific instructions.

---

## Object Files (`src/codegen/object.zig`)

### Key Functions

| Function | Purpose | Line |
|----------|---------|------|
| `writeMachO()` | Write Mach-O object file | ~200 |
| `writeELF()` | Write ELF object file | ~400 |
| `writeRelocation()` | Write relocation entry | ~300 |

### Structures

| Type | Purpose |
|------|---------|
| `MachHeader64` | Mach-O header |
| `Elf64Header` | ELF header |
| `Relocation` | Relocation entry |

---

## Driver (`src/driver.zig`)

Orchestrates the compilation pipeline.

### Key Functions

| Function | Purpose | Line |
|----------|---------|------|
| `Driver.compile()` | Main compilation entry | ~100 |
| `Driver.scan()` | Run scanner | ~200 |
| `Driver.parse()` | Run parser | ~250 |
| `Driver.check()` | Run type checker | ~300 |
| `Driver.lower()` | Run lowering | ~350 |
| `Driver.genCode()` | Run codegen | ~400 |
| `Driver.link()` | Run linker | ~500 |

---

## Error Handling (`src/errors.zig`)

### Key Structs

| Struct | Purpose |
|--------|---------|
| `ErrorReporter` | Collects and formats errors |
| `ErrorCode` | Error code enum (E100, E200, etc.) |

### Error Categories

| Range | Category |
|-------|----------|
| E100-E199 | Scanner errors |
| E200-E299 | Parser errors |
| E300-E399 | Type checker errors |
| E400-E499 | IR/codegen errors |

---

## Debug Utilities (`src/debug.zig`)

### Key Functions

| Function | Purpose |
|----------|---------|
| `scoped()` | Create scoped logger |
| `dumpIR()` | Print IR for debugging |
| `dumpSSA()` | Print SSA for debugging |

### Debug Flags

```bash
--debug-ir        # Show IR after lowering
--debug-ssa       # Show SSA after conversion
--debug-codegen   # Show instruction selection
--disasm          # Disassemble output
```

---

## Finding Your Way

### "I want to understand how X works"

1. Start with the pipeline doc: `docs/pipeline/1X_*.md`
2. Look at the Zig source in `src/*.zig`
3. Run with `--debug-*` flags to see it in action

### "I want to add feature Y"

1. Find which stage handles it (scanner? parser? checker?)
2. Look at similar features in that stage
3. Add tests first, then implement

### "Something is broken"

1. Run with all debug flags to see where it goes wrong
2. Check the tests in each module
3. Use `lldb` for runtime crashes

---

## Cross-Reference: Cot to Zig

Many concepts map from the `.cot` wireframes to `.zig` implementations:

| Cot Module | Zig File | Notes |
|------------|----------|-------|
| `scanner.cot` | `scanner.zig` | Nearly identical |
| `parser.cot` | `parser.zig` | Same structure |
| `checker.cot` | `check.zig` | Zig has explicit allocator |
| `types.cot` | `types.zig` | Zig uses tagged unions |
| `ir.cot` | `ir.zig` | Same IR ops |

The `.cot` files show the future self-hosted version. The `.zig` files are the current bootstrap implementation.
