# Cot Self-Hosting Roadmap

**Last Updated:** 2026-01-12

> **Claude: Update this file when you start or complete a roadmap item.**

This document tracks features remaining for self-hosting the cot compiler.

---

## Priority 1: Critical Gaps (Block Self-Hosting)

These features are used extensively in the .cot wireframe files.

| Feature | Blocking Files | Notes |
|---------|---------------|-------|
| If capture `if x \|val\| { }` | All | Unwrap optional with binding |
| While capture `while next() \|item\| { }` | ir.cot | Iterator pattern |
| For with index `for item, i in items { }` | scanner.cot | Indexed iteration |
| Address-of `&x` | checker.cot | Get pointer to value |
| Dereference `p.*` | - | Access through pointer |
| Import system `import "module"` | All | Module imports |

---

## Priority 2: Error Handling (Required for Robust Compiler)

The .cot wireframes use error handling throughout.

| Feature | Status | Notes |
|---------|--------|-------|
| Error return type `!T` | Gap | Function can fail |
| Error return type `!` | Gap | Void + can fail |
| `error.Name` | Gap | Create error value |
| `try expr` | Gap | Propagate error |
| `catch default` | Gap | Handle error with default |
| `catch \|err\| { }` | Gap | Handle error with block |

---

## Priority 3: Function Types

Used in errors.cot for callbacks and handlers.

| Feature | Status | Notes |
|---------|--------|-------|
| Function type syntax `fn(T) R` | Gap | Type expression |
| Function as parameter | Gap | Higher-order functions |
| Type alias for fn | Gap | `type Handler = fn(Error) void` |

---

## Priority 4: Partial Features (Need Completion)

These have parsing done but codegen is incomplete.

| Feature | Current Status | What's Missing |
|---------|----------------|----------------|
| `break` | Parsing done | Codegen |
| `continue` | Parsing done | Codegen |
| Pointer type `*T` | Type exists | Full codegen support |
| Bitwise `& \| ^ ~ << >>` | Partial | Complete codegen |
| Logical `and or not` | Partial | Short-circuit evaluation |

---

## Priority 5: Nice-to-Have (Can Work Around)

These would be nice but have workarounds.

| Feature | Workaround |
|---------|------------|
| Optional chaining `?.` | Use explicit `if` checks |
| String concat `+` | Use interpolation `"{a}{b}"` |
| `@sizeof(T)` | Hardcode sizes or use type registry |
| `@intCast(T, v)` | Careful about type sizes |
| `defer` | Explicit cleanup at each exit point |
| Discard `_ = expr` | Assign to unused variable |

---

## .cot File Readiness

| File | LOC | Main Blockers | Priority |
|------|-----|---------------|----------|
| token.cot | 171 | None | Ready |
| source.cot | 120 | None | Ready |
| errors.cot | 198 | fn types | P3 |
| ast.cot | 513 | None | Ready |
| types.cot | 458 | None | Ready |
| scanner.cot | 401 | for-index | P1 |
| ir.cot | 664 | while-capture | P1 |
| parser.cot | 1289 | None | Ready |
| checker.cot | 963 | if-capture, &x, errors | P1, P2 |

---

## Suggested Implementation Order

### Phase 1: Control Flow Completion
1. `break` codegen
2. `continue` codegen
3. Logical operators with short-circuit

### Phase 2: Optional Captures
1. If capture `if x |val| { }`
2. While capture `while next() |item| { }`
3. For with index `for item, i in items { }`

### Phase 3: Pointers
1. Address-of `&x`
2. Dereference `p.*`
3. Auto-deref for field access

### Phase 4: Error Handling
1. `!T` return type
2. `error.Name` values
3. `try` propagation
4. `catch` handling

### Phase 5: Finishing
1. Import system (or file concatenation workaround)
2. Function types (if needed)
3. Remaining builtins

---

## x86_64 Test Failures (5 remaining)

| Test | Likely Issue |
|------|--------------|
| test_bool_or | Boolean/logical codegen |
| test_for_array | Loop codegen |
| test_for_slice | Loop codegen |
| test_list_methods | Collection method calls |
| test_map_methods | Collection method calls |

These should be fixed before self-hosting to ensure cross-platform support.

---

## Architecture Notes

Self-hosting will reimplement the compiler pipeline:

```
Source (.cot)
    → Scanner (token.cot)
    → Parser (parser.cot) → AST (ast.cot)
    → Checker (checker.cot) → Types (types.cot)
    → Lowerer → IR (ir.cot)
    → SSA conversion
    → Codegen (arm64/amd64)
    → Object file output
```

The Zig implementation serves as the reference. Each .cot file should produce identical results to its Zig counterpart.
