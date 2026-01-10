# Self-Hosting Feature Tracker

This document tracks language features required for self-hosting the cot compiler.
Features are extracted from the .cot wireframe files in `src/`.

**Last Updated:** 2026-01-10

## Legend

- **Implemented**: Working in Zig implementation, tested
- **Partial**: Parsing works but codegen incomplete
- **Spec'd**: Documented in spec.md but not implemented
- **Gap**: Used in .cot files but not fully spec'd

---

## Phase 1: Core Language (Critical Path)

These features are used extensively in all .cot files and must work first.

### Basic Types and Declarations

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| `i8, i16, i32, i64, u8, u16, u32, u64` | Implemented | All | Primitive integer types |
| `f32, f64` | Implemented | types.cot | Floating point |
| `bool` | Implemented | All | Boolean type |
| `string` | Implemented | All | String type with len, comparison |
| `void` | Implemented | All | Void type |
| `var` declarations | Implemented | All | Mutable variables |
| `const` declarations | Implemented | All | Immutable constants |
| `type` aliases | **Gap** | ast.cot, types.cot | `type NodeIndex = u32` |

### Struct Types

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| Struct definition | Implemented | All | `struct Name { fields }` |
| Struct initialization | Implemented | All | `Point{ .x = 1, .y = 2 }` |
| Field access | Implemented | All | `p.x` |
| Optional fields | Implemented | ast.cot | `return_type: ?NodeIndex` |
| Pointer fields | Partial | checker.cot | `parent: ?*Scope` |

### Enum Types

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| Simple enum | Implemented | All | `enum Color { red, green, blue }` |
| Enum with backing type | **Gap** | token.cot, errors.cot | `enum Token: u8 { ... }` |
| Enum with explicit values | **Gap** | errors.cot | `E100 = 100` |
| `@intFromEnum(e)` | **Gap** | errors.cot | Convert enum to int |
| `@enumFromInt(T, i)` | **Gap** | - | Convert int to enum |

### Tagged Unions

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| Union definition | **Gap** | ast.cot, types.cot, ir.cot | `union Decl { fn_decl: FnDecl, ... }` |
| Union construction | **Gap** | All | `Decl.fn_decl(FnDecl{...})` |
| Switch on union | **Gap** | All | `switch d { .fn_decl \|f\| => f.span }` |
| Payload capture | **Gap** | All | `\|f\|` captures the payload |
| Unit variants | **Gap** | ir.cot | `none,` (no payload) |

### Arrays and Slices

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| Fixed array `[N]T` | Implemented | - | Static arrays |
| Array literal | Implemented | - | `[1, 2, 3]` |
| Slice `[]T` | Implemented | ast.cot | Slice type and iteration |
| Index `arr[i]` | Implemented | All | Static and dynamic |
| `len(arr)` | Implemented | All | Built-in length for arrays/slices/strings |

### Optional Types

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| Optional `?T` | Partial | All | Type representation exists |
| Null literal | Partial | All | `null` |
| Null coalescing `??` | **Gap** | checker.cot | `val ?? default` |
| Optional unwrap `.?` | **Gap** | parser.cot | `maybe.?` |
| Optional chaining `?.` | **Gap** | - | `maybe?.method()` |
| If capture | **Gap** | All | `if maybe \|val\| { }` |
| While capture | **Gap** | ir.cot | `while iter.next() \|item\| { }` |

---

## Phase 2: Control Flow

### Basic Control Flow

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| If/else | Implemented | All | Full if/else/else-if support |
| While loop | Implemented | All | Full while loop support |
| For-in loop | Implemented | ir.cot, checker.cot | `for item in items { }` |
| For with index | **Gap** | scanner.cot | `for item, i in items { }` |
| Break | Partial | - | Parsing done, codegen TBD |
| Continue | Partial | - | Parsing done, codegen TBD |
| Return | Implemented | All | Working |

### Switch Expressions

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| Switch expression | Implemented | All | `var x = switch y { ... }` |
| Switch statement | Implemented | parser.cot | `switch x { ... }` |
| Multiple cases | **Gap** | parser.cot | `.plus, .minus => ...` |
| Else case | Implemented | All | `else => default` |
| Range patterns | **Gap** | - | Not used in wireframes |

---

## Phase 3: Functions and Methods

### Functions

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| Function definition | Implemented | All | `fn name(params) ret { }` |
| Function call | Implemented | All | `name(args)` |
| Return statement | Implemented | All | `return value` |
| Void return | Implemented | All | No return value |

### Function Types

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| Function type syntax | **Gap** | errors.cot | `fn(Error) void` |
| Function as parameter | **Gap** | errors.cot | Higher-order functions |
| Type alias for fn | **Gap** | errors.cot | `type Handler = fn(Error) void` |

### Methods (Associated Functions)

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| Methods with self | **Gap** | ir.cot, checker.cot | `fn method(self: *T) { }` |
| Method call syntax | **Gap** | All | `obj.method()` |

---

## Phase 4: Memory and Collections

### Pointers

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| Pointer type `*T` | Partial | checker.cot | Type representation |
| Address-of `&x` | **Gap** | checker.cot | Get pointer |
| Dereference `p.*` | **Gap** | - | Access through pointer |
| Auto-deref for fields | **Gap** | - | `p.x` on pointer |

### Collections (Built-in Generics)

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| `List<T>` | **Gap** | All | Dynamic array |
| `List.push(item)` | **Gap** | All | Append item |
| `List.get(index)` | **Gap** | ir.cot | Get by index |
| `Map<K, V>` | **Gap** | checker.cot, ir.cot | Hash map |
| `Map.set(k, v)` | **Gap** | checker.cot | Insert/update |
| `Map.get(key)` | **Gap** | checker.cot | Lookup (returns ?V) |
| `Map.has(key)` | **Gap** | checker.cot | Key exists |
| `new List<T>` | **Gap** | All | Heap allocation |
| `new Map<K,V>` | **Gap** | checker.cot | Heap allocation |

---

## Phase 5: Error Handling

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| Error return type `!T` | **Gap** | checker.cot | Function can fail |
| Error return type `!` | **Gap** | checker.cot | Void + can fail |
| `error.Name` | **Gap** | checker.cot | Create error value |
| `try expr` | **Gap** | checker.cot | Propagate error |
| `catch default` | **Gap** | - | Handle error |
| `catch \|err\| { }` | **Gap** | - | Handle with block |

---

## Phase 6: Miscellaneous

### Operators

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| Arithmetic `+ - * / %` | Implemented | All | All basic math ops |
| Comparison `== != < > <= >=` | Implemented | All | All comparisons |
| Logical `and or not` | Partial | All | Keywords |
| Bitwise `& \| ^ ~ << >>` | Partial | - | Bit ops |
| Compound assign `+= -= *=` | **Gap** | errors.cot, scanner.cot | `count += 1` |
| String concat `+` | **Gap** | - | `"a" + "b"` |
| String comparison | Implemented | scanner.cot | `text == keyword`, `text != keyword` |

### Built-ins

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| `len(x)` | Implemented | All | Length of array/slice/string |
| `println(x)` | Implemented | ir.cot | Print with newline (via libc write) |
| `print(x)` | Implemented | ir.cot | Print without newline (via libc write) |
| `@sizeof(T)` | **Gap** | - | Not used in wireframes |
| `@maxInt(T)` | **Gap** | ast.cot, ir.cot | Max value for int type |
| `@minInt(T)` | **Gap** | - | Min value for int type |
| `@intCast(T, v)` | **Gap** | ast.cot, types.cot | Type cast |

### Other

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| `import "module"` | **Gap** | All | Module imports |
| `defer expr` | **Gap** | checker.cot | Deferred execution |
| Discard `_ = expr` | **Gap** | parser.cot | Ignore return value |
| String interpolation | **Gap** | errors.cot | `"Value: ${x}"` |

---

## Feature Dependencies

Some features depend on others. Suggested implementation order:

### Tier 1 (Foundation) - Partially Complete
1. ~~`len()` built-in~~ - **Done**
2. Type aliases (`type X = Y`)
3. `@maxInt(T)` built-in
4. Compound assignment (`+=`, etc.)

### Tier 2 (Core Patterns)
1. Tagged unions with switch/capture
2. If/while capture syntax (`if x |val| { }`)
3. `??` null coalescing
4. `.?` optional unwrap

### Tier 3 (Collections)
1. `List<T>` built-in
2. `Map<K,V>` built-in
3. `new` heap allocation
4. ~~For-in iteration~~ - **Done**

### Tier 4 (Functions)
1. Function types (`fn(T) R`)
2. Methods with self parameter
3. Higher-order functions

### Tier 5 (Error Handling)
1. `!T` return type
2. `error.Name` values
3. `try` propagation
4. `catch` handling

### Tier 6 (Finishing) - Partially Complete
1. String interpolation
2. Import system
3. `defer`
4. ~~`print`/`println`~~ - **Done**

---

## .cot File Status

| File | LOC | Key Dependencies | Ready? |
|------|-----|------------------|--------|
| token.cot | 171 | Enum w/ backing type, @intFromEnum | Mostly |
| source.cot | 120 | @maxInt, @min, @max | Close |
| scanner.cot | 401 | String ops, for-index, switch | Closer |
| ast.cot | 513 | Tagged unions, type alias | No |
| types.cot | 458 | Tagged unions, switch | No |
| ir.cot | 664 | Tagged unions, List<T>, Map | No |
| errors.cot | 198 | Enum values, fn types, interpolation | No |
| parser.cot | 1289 | Tagged unions, ??, .?, switch | No |
| checker.cot | 963 | Everything | No |

---

## Recently Implemented (2026-01)

The following features were implemented in recent development sessions:

### Control Flow
- **Switch expressions/statements**: Full switch support with else clause
- **For-in loops**: Iteration over arrays and slices
- **If/else**: Full conditional support (was marked Partial)
- **While loops**: Full while loop support (was marked Partial)

### Built-ins
- **len()**: Works on arrays, slices, and strings
- **print/println**: Output via libc `write()` syscall

### Operators
- **String comparison**: `==` and `!=` for string equality
- **Subtraction, multiplication, division**: Full arithmetic support

### Codegen
- **ARM64 (macOS)**: Full Mach-O object file generation with relocations
- **x86_64 (Linux)**: Full ELF object file generation with relocations
- 36 tests passing on both architectures

---

## Notes

### Tagged Unions are Critical

Almost every .cot file uses tagged unions extensively:
- `ast.cot`: Decl, Expr, Stmt, TypeExpr unions
- `types.cot`: Type union
- `ir.cot`: Op enum, Aux union

Without tagged unions with payload capture, self-hosting is impossible.

### Built-in Generics Required

The wireframes use `List<T>` and `Map<K,V>` extensively:
- Parser builds lists of AST nodes
- Checker uses maps for symbol tables
- IR uses lists for values and blocks

User-defined generics are NOT needed for bootstrap (per spec.md), but the built-in collections are essential.

### Switch Expressions are Everywhere

Every .cot file uses switch expressions for pattern matching:
- Token dispatch in parser
- Type dispatch in checker
- AST node dispatch everywhere

The switch must work as an expression (returns value) with payload capture.

### Remaining Critical Gaps for Self-Hosting

1. **Tagged unions** - The single most important missing feature
2. **Enum with backing type** - `enum Token: u8 { ... }`
3. **@intFromEnum** - Convert enum to int for switch
4. **Map<K,V>** - Symbol tables and lookup
5. **Methods** - `fn method(self: *T)` pattern
