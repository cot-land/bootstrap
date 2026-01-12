# Cot Language Improvements for 1.0

**Created:** 2026-01-12
**Purpose:** Analysis of current .cot files and roadmap to production-ready language

---

## Vision Recap

Cot aims to be a **Go-like language with Zig syntax** for business software developers. Key principles:
- Systems-level performance without C#/Java ceremony
- Clean, readable syntax inspired by Zig
- Simple is better - learn from Go's success
- Fresh start in 2026, free from legacy baggage

---

## Current State Analysis

### What Works Well

| Feature | Assessment |
|---------|------------|
| **Primitives** | Complete: i8-i64, u8-u64, f32/f64, bool, string |
| **Structs** | Solid: named init, field access, methods via receiver |
| **Enums** | Solid: backing types, explicit values, methods |
| **Tagged Unions** | Excellent: payload capture, exhaustive switching |
| **Arrays/Slices** | Good: indexing, slicing, for-in iteration |
| **Control Flow** | Complete: if/else, while, for-in, switch, return |
| **Optional Types** | Good foundation: `?T`, `??`, capture syntax |
| **Type Aliases** | Works: `type NodeIndex = u32` |

### Critical Gaps

| Gap | Impact | Current Workaround |
|-----|--------|-------------------|
| **Error Handling** | Cannot write robust code | Return error codes, ignore errors |
| **String Operations** | Cannot build/manipulate strings | Only interpolation works |
| **Module System** | Code duplication, no encapsulation | Inline everything |
| **User Generics** | Cannot abstract over types | Duplicate code per type |
| **Break/Continue Codegen** | Cannot exit loops early | Restructure with flags |

---

## Language Improvement Proposals

### 1. Error Handling (CRITICAL)

**Current state:** `!void` placeholder syntax exists but does nothing.

**Proposal:** Go-style error handling with optional sugar

```cot
// Error type definition (like Go's error interface)
type Error = union {
    none,
    message: string,
    code: ErrorCode,
}

// Functions that can fail return Result
fn readFile(path: string) Result<string, Error> {
    // ...
}

// Result type (built-in generic)
type Result<T, E> = union {
    ok: T,
    err: E,
}

// Usage pattern 1: Explicit handling (Go-style)
var result = readFile("config.json");
switch result {
    .ok |content| => processContent(content),
    .err |e| => println("Error: ${e}"),
}

// Usage pattern 2: Propagation with ? operator (Rust-style sugar)
fn loadConfig() Result<Config, Error> {
    var content = readFile("config.json")?;  // Returns early on error
    return parseConfig(content);
}

// Usage pattern 3: Default on error
var content = readFile("config.json") ?? "{}";
```

**Why this design:**
- Go's explicit error handling prevents hidden control flow
- `?` propagation operator reduces boilerplate for the common case
- `??` reuses existing null-coalescing for errors
- No exceptions - control flow is always visible

---

### 2. String Operations (CRITICAL)

**Current state:** Only interpolation (`"${x}"`) and basic indexing/slicing.

**Proposal:** String methods and concatenation

```cot
// Concatenation operator
var full = first ++ " " ++ last;

// Or via method (UFCS)
var full = first.concat(" ").concat(last);

// Essential string methods
var s = "  Hello, World!  ";

s.len()           // 17 (already works via len(s))
s.trim()          // "Hello, World!"
s.lower()         // "  hello, world!  "
s.upper()         // "  HELLO, WORLD!  "
s.contains("World")  // true
s.startsWith("  H")  // true
s.endsWith("!  ")    // true
s.indexOf("World")   // 9 (returns ?u64, null if not found)
s.split(",")         // ["  Hello", " World!  "]
s.replace("World", "Cot")  // "  Hello, Cot!  "

// String building for performance
var builder = StringBuilder.init();
builder.append("Hello");
builder.append(", ");
builder.append("World");
var result = builder.toString();  // "Hello, World"
```

**Implementation approach:**
- Add `++` as string concat operator (distinct from `+` to avoid ambiguity)
- String methods implemented in runtime library (like Map/List)
- StringBuilder for efficient multi-part construction

---

### 3. Module System (HIGH PRIORITY)

**Current state:** No imports, code duplication across files.

**Proposal:** Simple Go-style imports

```cot
// Declare module at top of file
module scanner;

// Import other modules
import token;       // imports token module
import errors;      // imports errors module

// Use qualified names
var tok = token.Token.identifier;
var err = errors.ErrorCode.E001;

// Or import specific items
import { Token, Keyword } from token;
var tok = Token.identifier;

// Public/private visibility (default private)
pub struct Scanner {   // accessible from other modules
    src: Source,       // private field (only accessible within module)
    pub pos: Pos,      // public field
}

pub fn scan() Token { }  // public function
fn helper() void { }     // private function
```

**File organization:**
```
src/
  scanner.cot      // module scanner
  token.cot        // module token
  parser.cot       // module parser
  main.cot         // module main (entry point)
```

**Why this design:**
- Go's simplicity: one file = one module (or one directory = one module)
- No complex visibility rules like Rust's pub(crate)
- Default private encourages encapsulation
- Explicit imports make dependencies visible

---

### 4. User-Defined Generics (MEDIUM PRIORITY)

**Current state:** Only built-in `Map<K,V>` and `List<T>`.

**Proposal:** Simple generics without complex constraints

```cot
// Generic struct
struct Pair<A, B> {
    first: A,
    second: B,
}

// Generic function
fn swap<T>(a: T, b: T) Pair<T, T> {
    return Pair<T, T>{ .first = b, .second = a };
}

// Usage with inference
var p = swap(1, 2);  // Pair<i64, i64>{ .first = 2, .second = 1 }

// Generic with constraint (post-1.0)
fn print<T: Display>(value: T) void {
    println(value.toString());
}
```

**Initial scope (for 1.0):**
- Generic structs with type parameters
- Generic functions with type parameters
- Basic type inference for generic parameters
- NO constraint system initially (add post-1.0)

---

### 5. Range Iteration (MEDIUM PRIORITY)

**Current state:** Only `for x in array` works.

**Proposal:** Range expressions

```cot
// Exclusive range (0 to 9)
for i in 0..10 {
    println(i);
}

// Inclusive range (0 to 10)
for i in 0..=10 {
    println(i);
}

// Indexed iteration over collections
for item, index in array {
    println("${index}: ${item}");
}

// Map iteration
for key, value in map {
    println("${key} = ${value}");
}

// Reverse iteration
for item in array.reversed() {
    println(item);
}
```

---

### 6. Optional Chaining (MEDIUM PRIORITY)

**Current state:** `.?` token defined but not implemented.

**Proposal:** Safe navigation for optionals

```cot
struct User {
    name: string,
    address: ?Address,
}

struct Address {
    city: string,
    zip: ?string,
}

var user: ?User = getUser();

// Optional chaining - returns ?string
var city = user?.address?.city;

// Combined with null coalescing
var city = user?.address?.city ?? "Unknown";

// Method call chaining
var upper = user?.name.upper();  // ?string
```

---

### 7. Default Parameters (LOW PRIORITY)

**Current state:** All parameters required.

**Proposal:** Optional parameters with defaults

```cot
// Default parameter values
fn connect(host: string, port: i64 = 8080, timeout: i64 = 30) Connection {
    // ...
}

// Called with defaults
var conn1 = connect("localhost");           // port=8080, timeout=30
var conn2 = connect("localhost", 3000);     // port=3000, timeout=30
var conn3 = connect("localhost", 3000, 60); // explicit values

// Named arguments (optional, consider for post-1.0)
var conn = connect("localhost", timeout = 60);  // port=8080, timeout=60
```

---

### 8. Impl Blocks (LOW PRIORITY)

**Current state:** Methods are functions with receiver as first param.

**Proposal:** Explicit impl blocks for organization

```cot
struct Point {
    x: i64,
    y: i64,
}

impl Point {
    // Constructor
    fn new(x: i64, y: i64) Point {
        return Point{ .x = x, .y = y };
    }

    // Method with self receiver
    fn distance(self: Point, other: Point) f64 {
        var dx = self.x - other.x;
        var dy = self.y - other.y;
        return sqrt(dx * dx + dy * dy);
    }

    // Mutating method
    fn translate(self: *Point, dx: i64, dy: i64) void {
        self.x += dx;
        self.y += dy;
    }
}

// Usage
var p1 = Point.new(0, 0);
var p2 = Point.new(3, 4);
var d = p1.distance(p2);  // 5.0
```

**Note:** Current method syntax already works via UFCS. Impl blocks add organization but are not strictly necessary.

---

## Execution Plan

### Phase 1: Foundation (Pre-Bootstrap Completion)

**Goal:** Complete features needed for self-hosting compiler

| Step | Feature | Scope | Dependencies |
|------|---------|-------|--------------|
| 1.1 | Break/continue codegen | Implement IR→SSA→codegen | None |
| 1.2 | Module imports | Basic `import "file"` | None |
| 1.3 | String concat operator | `++` for strings | Runtime support |

**Exit criteria:** All 22 bootstrap .cot files compile and run correctly.

---

### Phase 2: Error Handling

**Goal:** Make Cot safe for production error handling

| Step | Feature | Scope |
|------|---------|-------|
| 2.1 | Result<T, E> union | Built-in generic type |
| 2.2 | Error type | Standard error union |
| 2.3 | `?` propagation | Sugar for early return on error |
| 2.4 | `??` for Result | Extend null-coalescing to errors |

**Exit criteria:** Can write code like `var x = riskyOp()?;` that propagates errors.

---

### Phase 3: String Enhancement

**Goal:** Make string manipulation practical

| Step | Feature | Scope |
|------|---------|-------|
| 3.1 | String concat | `++` operator in codegen |
| 3.2 | Core methods | `.trim()`, `.lower()`, `.upper()` |
| 3.3 | Search methods | `.contains()`, `.indexOf()`, `.startsWith()` |
| 3.4 | StringBuilder | Efficient string building |
| 3.5 | Split/join | `.split()`, `.join()` |

**Exit criteria:** Can parse and manipulate strings without byte-level gymnastics.

---

### Phase 4: Iteration Enhancement

**Goal:** Make loops expressive

| Step | Feature | Scope |
|------|---------|-------|
| 4.1 | Range syntax | `for i in 0..n` |
| 4.2 | Indexed iteration | `for item, i in arr` |
| 4.3 | Map iteration | `for k, v in map` |
| 4.4 | Inclusive range | `0..=n` syntax |

**Exit criteria:** Can iterate over any collection with index access if needed.

---

### Phase 5: Optional Enhancement

**Goal:** Eliminate null-related boilerplate

| Step | Feature | Scope |
|------|---------|-------|
| 5.1 | Optional chaining | `x?.y?.z` syntax |
| 5.2 | Optional map | `x?.map(fn)` |
| 5.3 | Propagation | `x?` in optional context |

**Exit criteria:** Can chain optional accesses without nested if-captures.

---

### Phase 6: Module System

**Goal:** Enable multi-file projects with encapsulation

| Step | Feature | Scope |
|------|---------|-------|
| 6.1 | Module declaration | `module name;` at file top |
| 6.2 | Basic imports | `import name;` |
| 6.3 | Qualified access | `module.Type` syntax |
| 6.4 | Selective imports | `import { A, B } from module;` |
| 6.5 | Visibility | `pub` keyword for exports |
| 6.6 | Circular deps | Handle mutual references |

**Exit criteria:** Compiler source split into proper modules with clean dependencies.

---

### Phase 7: User Generics

**Goal:** Enable generic abstractions

| Step | Feature | Scope |
|------|---------|-------|
| 7.1 | Generic structs | `struct Foo<T> { x: T }` |
| 7.2 | Generic functions | `fn bar<T>(x: T) T` |
| 7.3 | Type inference | Infer generic params from args |
| 7.4 | Monomorphization | Generate specialized code |

**Exit criteria:** Can define custom generic containers like `Stack<T>`.

---

### Phase 8: Polish (1.0 Release)

**Goal:** Production-ready language

| Step | Feature | Scope |
|------|---------|-------|
| 8.1 | Default parameters | `fn f(x: i64 = 0)` |
| 8.2 | Impl blocks | `impl Type { methods }` |
| 8.3 | Standard library | Core types and functions |
| 8.4 | Documentation | Language spec, tutorials |
| 8.5 | Tooling | Formatter, LSP basics |

**Exit criteria:** Business developers can build real applications.

---

## Refactoring Plan for Existing .cot Files

Once features are implemented, refactor existing code:

### Round 1: After Phase 2 (Error Handling)

**scanner_boot.cot:**
```cot
// Before
fn scan(self: *Scanner) Token {
    // returns invalid token on error
}

// After
fn scan(self: *Scanner) Result<Token, ScanError> {
    if isEOF() { return .ok(Token.eof); }
    if invalid { return .err(ScanError.invalidChar(ch)); }
}
```

### Round 2: After Phase 3 (Strings)

**token_boot.cot:**
```cot
// Before (if-chain for keywords)
fn lookupKeyword(name: string) Token {
    if name == "fn" { return Token.kw_fn; }
    if name == "var" { return Token.kw_var; }
    // ... 30 more cases
}

// After (with Map support and string methods)
const keywords = Map<string, Token>{
    "fn" => Token.kw_fn,
    "var" => Token.kw_var,
    // ...
};

fn lookupKeyword(name: string) Token {
    return keywords.get(name) ?? Token.identifier;
}
```

### Round 3: After Phase 6 (Modules)

**All bootstrap files:**
```cot
// Before: single concatenated file or duplicated types

// After: clean module structure
// token.cot
module token;
pub enum Token: u8 { ... }

// scanner.cot
module scanner;
import token;
pub struct Scanner { ... }

// parser.cot
module parser;
import token;
import scanner;
import ast;
pub struct Parser { ... }
```

### Round 4: After Phase 7 (Generics)

**types_boot.cot:**
```cot
// Before: specific container types
struct TypeList {
    items: []TypeInfo,
    // ...
}

// After: use generic List
var types = new List<TypeInfo>();
```

---

## Success Metrics for 1.0

| Metric | Target |
|--------|--------|
| Bootstrap test pass rate | 100% on ARM64 and x86_64 |
| Self-hosting | Cot compiler compiles itself |
| Error handling coverage | All fallible ops return Result |
| Module system | No code duplication in compiler |
| String operations | Can parse/manipulate without byte ops |
| Documentation | Language spec + getting started guide |

---

## Non-Goals for 1.0

Features explicitly deferred:

- **Concurrency** - No goroutines/async yet (add in 1.1+)
- **Traits/Interfaces** - Generic constraints deferred
- **Macros** - No metaprogramming initially
- **Package manager** - Manual dependency management
- **Debugger integration** - DWARF/debugging info later
- **Optimizations** - Focus on correctness, not speed

---

## Notes

This plan prioritizes:
1. **Self-hosting first** - Complete bootstrap before adding features
2. **Practical features** - Error handling and strings over advanced type system
3. **Incremental progress** - Each phase delivers usable improvements
4. **Business developer focus** - Features that reduce day-to-day friction

The goal is a language that business developers can actually use, not an academic exercise in type theory.
