# Self-Hosting Feature Tracker

This document tracks language features required for self-hosting the cot compiler.
Features are extracted from the .cot wireframe files in `src/`.

**Last Updated:** 2026-01-11 (type aliases implemented)

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
| `type` aliases | Implemented | ast.cot, types.cot | `type NodeIndex = u32` |

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
| Enum with backing type | Implemented | token.cot, errors.cot | `enum Token: u8 { ... }` |
| Enum with explicit values | Implemented | errors.cot | `E100 = 100` |
| `@intFromEnum(e)` | Implemented | errors.cot | Convert enum to int |
| `@enumFromInt(T, i)` | Implemented | - | Convert int to enum |

### Tagged Unions

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| Union definition | Implemented | ast.cot, types.cot, ir.cot | Parsing and type checking done |
| Union construction | Implemented | All | `Result.ok(42)` |
| Switch on union | Implemented | All | `switch r { .ok \|val\| => val }` |
| Payload capture | Implemented | All | `\|val\|` captures the payload |
| Unit variants | Partial | ir.cot | Parsing done, no payload = `none,` |

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
| Multiple cases | Implemented | parser.cot | `.plus, .minus => ...` |
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
| Methods with self | Implemented | ir.cot, checker.cot | `fn method(self: *T) { }` |
| Method call syntax (UFCS) | Implemented | All | `obj.method()` transforms to `method(&obj)` |

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
| `List<T>` | Implemented | All | Full runtime support |
| `List.push(item)` | Implemented | All | Append item via FFI |
| `List.get(index)` | Implemented | ir.cot | Get by index via FFI |
| `Map<K, V>` | Implemented | checker.cot, ir.cot | Full runtime support |
| `Map.set(k, v)` | Implemented | checker.cot | Native layout + FFI |
| `Map.get(key)` | Implemented | checker.cot | Native layout + FFI |
| `Map.has(key)` | Implemented | checker.cot | Native layout + FFI |
| `new List<T>` | Implemented | All | Native calloc + 24-byte header |
| `new Map<K,V>` | Implemented | checker.cot | Native calloc + init |

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
| `@maxInt(T)` | Implemented | ast.cot, ir.cot | Max value for int type |
| `@minInt(T)` | Implemented | - | Min value for int type |
| `@intCast(T, v)` | **Gap** | ast.cot, types.cot | Type cast |

### Other

| Feature | Status | Used In | Notes |
|---------|--------|---------|-------|
| `import "module"` | **Gap** | All | Module imports |
| `defer expr` | **Gap** | checker.cot | Deferred execution |
| Discard `_ = expr` | **Gap** | parser.cot | Ignore return value |
| String interpolation | Implemented | errors.cot | `"Value: {x}"` |

---

## Feature Dependencies

Some features depend on others. Suggested implementation order:

### Tier 1 (Foundation) - Complete
1. ~~`len()` built-in~~ - **Done**
2. ~~Type aliases (`type X = Y`)~~ - **Done**
3. ~~`@maxInt(T)` built-in~~ - **Done**
4. Compound assignment (`+=`, etc.)

### Tier 2 (Core Patterns)
1. ~~Tagged unions with switch/capture~~ - **Done**
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

### Tier 6 (Finishing) - Mostly Complete
1. ~~String interpolation~~ - **Done**
2. Import system
3. `defer`
4. ~~`print`/`println`~~ - **Done**

---

## .cot File Status

| File | LOC | Key Dependencies | Ready? |
|------|-----|------------------|--------|
| token.cot | 171 | ~~Enum w/ backing type~~, ~~@intFromEnum~~ | **Yes** |
| source.cot | 120 | @maxInt, @min, @max | Close |
| scanner.cot | 401 | String ops, for-index, ~~switch~~ | Closer |
| ast.cot | 513 | ~~Tagged unions~~, type alias | Closer |
| types.cot | 458 | ~~Tagged unions~~, ~~switch~~ | Closer |
| ir.cot | 664 | ~~Tagged unions~~, List<T>, Map | Closer |
| errors.cot | 198 | ~~Enum values~~, fn types, interpolation | Close |
| parser.cot | 1289 | ~~Tagged unions~~, ??, .?, ~~switch~~ | Closer |
| checker.cot | 963 | Everything | No |

---

## Recently Implemented (2026-01)

The following features were implemented in recent development sessions:

### Control Flow
- **Switch expressions/statements**: Full switch support with else clause
- **Multiple switch case patterns**: `.a, .b, .c => value` - multiple values per arm
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
- 51 tests passing on both architectures

### Tagged Unions - **Complete**
- **Union definition**: Parsing `union Name { variant: Type, ... }` syntax
- **Union construction**: `Result.ok(42)` creates a union value with payload
- **Switch on union**: `switch r { .ok |val| => val, .err |e| => e }`
- **Payload capture**: `|val|` captures the union payload in switch cases
- **Type system**: `union_type` in registry with variants and 8-byte aligned layout (tag + payload)

### Map Types - **Implemented**
- **Type syntax**: `Map<K, V>` parsing works
- **Type checking**: Map types are registered and type-checked
- **new expression**: `new Map<string, i64>()` parsing and codegen works
- **Native layout** (allocated via `calloc` in codegen):
  - Header (32 bytes): capacity, size, seed (FNV offset basis), unused
  - Slots (64 × 32 bytes): meta byte, padding, key_ptr, key_len, value
  - Total: 2080 bytes per map
- **Runtime library**: `runtime/map.zig` with C ABI functions for native layout:
  - `cot_native_map_set(map, key_ptr, key_len, value)` - FNV-1a hash + linear probe
  - `cot_native_map_get(map, key_ptr, key_len)` - Hash lookup with probing
  - `cot_native_map_has(map, key_ptr, key_len)` - Check if key exists
  - `cot_native_map_size(map)` - Read size from header
  - `cot_native_map_free(map)` - Free keys and map memory
- **Method syntax**: `.set()`, `.get()`, `.has()` all work via IR ops

### List Types - **Implemented**
- **Type syntax**: `List<T>` parsing works
- **Type checking**: List types are registered and type-checked
- **new expression**: `new List<i64>()` allocates 24-byte header via calloc
- **Native layout** (24-byte header):
  - `ptr` (8 bytes): pointer to element array
  - `len` (8 bytes): current number of elements
  - `cap` (8 bytes): allocated capacity
- **Runtime library**: `runtime/list.zig` with C ABI functions:
  - `cot_native_list_push(list, value)` - Append with automatic reallocation
  - `cot_native_list_get(list, index)` - Get element by index
  - `cot_native_list_len(list)` - Get current length
  - `cot_native_list_free(list)` - Free elements and header
- **Method syntax**: `.push()`, `.get()` work via IR ops
- **Scratch slot codegen**: Intermediate results saved to stack for multi-operation expressions (e.g., `list.get(0) + list.get(1) + list.get(2)`)

### String Interpolation - **Implemented**
- **Syntax**: `"Hello {name}!"` embeds variable values in strings
- **Implementation**: Parser rewrites to `str_concat` operations
- **Codegen**: Uses `cot_str_concat` runtime function for concatenation
- **Tests**: `test_interpolation.cot` and `test_interp_var.cot` pass on both platforms

### @maxInt Builtin - **Implemented**
- **Syntax**: `@maxInt(i8)` returns maximum value for integer type
- **Compile-time**: Evaluated at compile time to constant
- **Tests**: `test_maxint.cot` passes on both platforms

### Register Allocator - **Implemented**
- **Go-style farthest-next-use eviction policy**
- **Complements StorageManager**: StorageManager provides spill slots, RegAllocator tracks register state
- **Caller-saved register invalidation**: Properly invalidates registers after runtime function calls (x0-x17 on ARM64, rax/rcx/rdx/rsi/rdi/r8-r11 on x86_64)
- **Fixes value lifetime bugs**: Values across function calls are correctly reloaded from storage

### Type Aliases - **Implemented**
- **Syntax**: `type MyInt = i64` creates a transparent alias
- **Parsing**: Added `kw_type` token and `parseTypeAlias()` in parser
- **Type checking**: Alias resolved to target type at definition time
- **Codegen**: No codegen needed - purely a type-system feature
- **Tests**: `test_type_alias.cot` passes on both platforms

---

## Notes

### Tagged Unions are Critical - **NOW IMPLEMENTED**

Almost every .cot file uses tagged unions extensively:
- `ast.cot`: Decl, Expr, Stmt, TypeExpr unions
- `types.cot`: Type union
- `ir.cot`: Op enum, Aux union

Tagged unions with payload capture are now working on both ARM64 and x86_64.

### Built-in Generics Required - **Map DONE, List IN PROGRESS**

The wireframes use `List<T>` and `Map<K,V>` extensively:
- Parser builds lists of AST nodes
- Checker uses maps for symbol tables
- IR uses lists for values and blocks

**Map Progress**: Complete. Native layout with heap allocation via `calloc`. FNV-1a hashing with linear probing. Method syntax (`.set()`, `.get()`, `.has()`) works.

**List Progress**: Complete. Native 24-byte header layout with heap allocation via `calloc`. Automatic capacity growth in push. Method syntax (`.push()`, `.get()`) works. Scratch slot mechanism for intermediate results in multi-operation expressions.

**Both Map and List**: 51 tests pass on ARM64 and x86_64. User-defined generics are NOT needed for bootstrap (per spec.md).

### Switch Expressions are Everywhere

Every .cot file uses switch expressions for pattern matching:
- Token dispatch in parser
- Type dispatch in checker
- AST node dispatch everywhere

The switch must work as an expression (returns value) with payload capture.

### Remaining Critical Gaps for Self-Hosting

1. ~~**Tagged unions**~~ - **DONE** (construction + switch with payload capture)
2. ~~**Map<K,V> types**~~ - **DONE** (native layout + FFI, method syntax works)
3. ~~**Map methods**~~ - **DONE** (`.set()`, `.get()`, `.has()` all work)
4. ~~**List<T> runtime**~~ - **DONE** (runtime library with push/get/len/free)
5. ~~**List methods**~~ - **DONE** (`.push()`, `.get()` method call syntax works)
6. ~~**Methods**~~ - **DONE** (`fn method(self: *T)` + UFCS `obj.method()`)
7. ~~**String interpolation**~~ - **DONE** (`"Error: {msg}"` syntax)
8. ~~**@maxInt**~~ - **DONE** (Integer bounds for type checks)
9. ~~**@minInt**~~ - **DONE** (Integer minimum bounds)
10. ~~**Type aliases**~~ - **DONE** (`type NodeIndex = u32` syntax)
11. **Compound assignment** - `+=`, `-=`, etc.
12. **Optional unwrap** - `.?` and `??` operators

### Post-Bootstrap Features

These features are deferred until after self-hosting is complete:

13. **Import system** - `import "module"` syntax (use file concatenation for bootstrap)
