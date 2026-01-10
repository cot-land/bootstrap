# Cot 0.2 Compiler Architecture

Based on Go's compiler. Implementation in Zig.

## Pluggable Frontend Design

**The AST is the stable interface.** Multiple frontends, one backend.

```
Frontend (pluggable)              Backend (shared)
────────────────────              ──────────────────────────────────
Cot syntax ────┐
               ├─→ AST ─→ Type Check ─→ IR ─→ SSA ─→ Codegen
DBL syntax ────┘
```

- Legacy DBL code keeps its syntax
- New code uses cot
- Both compile to the same AST
- All optimization/codegen is shared

## Pipeline

```
Source → Lexer → Parser → Type Check → IR → SSA → Codegen
         (syntax)         (types2)    (noder)  (ssa)
```

Type checking happens BEFORE IR construction. Errors caught early.

## Key Data Structures

### Value (SSA)
```
ID        - dense integer, enables array lookups
Op        - operation type
Type      - result type
AuxInt    - integer auxiliary data
Aux       - other auxiliary data
Args      - slice of argument Values
Block     - containing basic block
Uses      - reference count (for dead code detection)
```

Small-arg optimization: inline storage for 1-3 args.

### Block (SSA)
```
ID        - dense integer
Kind      - plain, if, exit, etc.
Succs     - successor edges
Preds     - predecessor edges
Controls  - control values (0-2)
Values    - values in this block
```

### Edge (Bidirectional)
```
b         - target block pointer
i         - index of reverse edge
```

Enables O(1) CFG modification. Both ends know about each other.

## Pass System

```zig
const passes = [_]Pass{
    .{ .name = "deadcode", .fn = deadcode, .required = true },
    .{ .name = "cse", .fn = cse },
    // ...
};

fn compile(f: *Func) void {
    for (passes) |p| {
        if (!config.optimize and !p.required) continue;
        p.fn(f);
        if (check_enabled) checkFunc(f);
    }
}
```

Run verification after EVERY pass during development.

## Fixed Types (DBL Compatibility)

Required for ISAM record layouts and DBL frontend:

```
alpha(N)          - fixed N-byte string (space padded)
decimal(N)        - fixed N-digit decimal (ASCII digits)
decimal(N, P)     - implied decimal (N digits, P after point)
```

Cot equivalents:
```cot
var name: alpha(30)          // 30-byte fixed string
var amount: decimal(10)      // 10-digit decimal
var price: decimal(8, 2)     // 8 digits, 2 decimal places
```

Maps to DBL:
```dbl
name,   a30
amount, d10
price,  d8.2
```

## Files (Target Structure)

```
src/
  frontend/
    cot/                   - Cot syntax frontend
      tokens.zig
      scanner.zig
      parser.zig
    dbl/                   - DBL syntax frontend (future)
      tokens.zig
      scanner.zig
      parser.zig
  ast/
    nodes.zig              - Shared AST (stable interface)
  types/
    types.zig              - type representation
    check.zig              - type checker
  ir/
    ir.zig                 - IR nodes
    build.zig              - AST to IR
  ssa/
    value.zig              - SSA values
    block.zig              - basic blocks
    func.zig               - SSA functions
    compile.zig            - pass orchestration
    passes/                - individual passes
  codegen/
    emit.zig               - native code emission
```

## Reference

When implementing, consult:
- `~/learning/go/src/cmd/compile/internal/syntax/` - lexer/parser
- `~/learning/go/src/cmd/compile/internal/types2/` - type checking
- `~/learning/go/src/cmd/compile/internal/ssa/` - SSA passes
