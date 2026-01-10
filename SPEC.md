# Cot 0.2 Minimal Language Spec

Memory-managed Zig with business-friendly syntax. 95% Zig alignment.

## Design Principles

1. **No manual memory management** - ARC handles allocation/deallocation
2. **Zig semantics, friendly names** - aliases for business devs
3. **Explicit over implicit** - but not painful
4. **defer over finally** - cleaner resource management

## Type Aliases

```cot
string  = []u8           // UTF-8 bytes
int     = i64            // default integer
float   = f64            // default float
decimal                  // fixed-point (financial math)
byte    = u8
bool                     // true, false
```

Full Zig types also available: `i8, i16, i32, i64, u8, u16, u32, u64, f32, f64`

## Fixed Types (DBL/ISAM Compatibility)

Required for fixed-size record layouts:

```cot
alpha(N)                 // fixed N-byte string, space-padded
decimal(N)               // fixed N-digit decimal (stored as ASCII)
decimal(N, P)            // implied decimal (N digits, P after point)

var name: alpha(30)      // 30-byte fixed string  (DBL: a30)
var amount: decimal(10)  // 10-digit decimal      (DBL: d10)
var price: decimal(8, 2) // 8 digits, 2 decimal   (DBL: d8.2)
```

## Variables

```cot
var x: int = 42          // mutable, explicit type
var y = 42               // mutable, inferred
let z = 42               // alias for var
const PI = 3.14159       // immutable
_ = someFunction()       // discard return value
```

The discard operator `_` explicitly ignores a value. Use it when calling a function for its side effects when you don't need the return value.

## Type Aliases

```cot
type UserId = int
type Handler = fn(Error) void
type StringList = List<string>

var id: UserId = 42
var callback: Handler = myHandler
```

## Pointers and Optionals

```cot
*T                       // pointer to T
?T                       // optional T (may be null)

var p: *Point = &point   // address-of
p.* = value              // dereference (Zig-style)
p.x                      // field access (auto-deref)

var maybe: ?int = null
maybe ?? 0               // null coalescing (default value)
maybe ?? return 0        // null coalescing with early return
maybe ?? return error.NotFound  // early return with error
maybe?.method()          // optional chaining
maybe.?                  // unwrap (panic if null)
maybe == 42              // compare optional to value (null != anything)
maybe == null            // check if null

// Capture syntax - unwrap and bind in one step
if maybe |value| {
    // value is int, not ?int
    println(value)
}

// Works with else
if maybe |value| {
    println(value)
} else {
    println("was null")
}

// Works with while - loop until null
while iterator.next() |item| {
    process(item)
}
```

## Mode Directive (Pointer Visibility)

Cot supports two modes for pointer visibility, configurable per-file or per-project:

### Default Mode (Go-like)

```cot
// No directive needed - this is the default

var point: Point = Point{ .x = 10, .y = 20 }
var p: *Point = &point   // explicit pointer type
p.x = 30                 // auto-deref for field access
p.method()               // auto-deref for method calls
p.* = other              // explicit deref when needed
```

Pointers are visible but ergonomic. You see `*` and `&` in type signatures and address-of operations, but field/method access auto-derefs like Go.

### Safe Mode (Business-Friendly)

```cot
@mode safe

// Java/C# style reference semantics
var p = new Point{ .x = 10, .y = 20 }   // heap allocated object
var q = p                                // q references same object
q.x = 30                                 // p.x is also 30 now

// Primitives are still value types
var x = 42
var y = x                                // y is a copy
y = 100                                  // x is still 42

// No *, &, or .* syntax allowed in safe mode
```

Safe mode uses familiar Java/C# semantics: `new` creates heap objects, assignment shares references, ARC handles cleanup. Designed for business developers coming from managed languages.

### File-Level Directive

```cot
@mode safe              // at top of file, hides pointers
@mode default           // explicit default (optional)
```

### Project-Level Configuration

In `cot.toml`:
```toml
[compiler]
default_mode = "safe"   # all files default to safe mode
```

Individual files can still override with `@mode default` when needed.

### Mode Interaction

- Default mode files can import safe mode modules (and vice versa)
- At module boundaries, the compiler handles any necessary conversions
- Safe mode code cannot use pointer syntax even when calling default mode code

### Why Two Modes?

1. **Gradual adoption** - Teams can start with safe mode and opt into pointers where needed
2. **DBL migration** - Business logic from DBL doesn't need pointer concepts
3. **Mixed teams** - Systems code in default mode, business logic in safe mode
4. **Learning curve** - New developers start in safe mode, learn pointers later

## Strings

```cot
var name: string = "John"
var greeting = "Hello ${name}!"    // interpolation
var combined = first + " " + last  // concatenation
len(name)                          // byte length
name[0..4]                         // slice

// Interpolation supports any expression
var msg = "Count: ${count + 1}"
var info = "Code: E${@intFromEnum(code)}"
var debug = "Value: ${obj.field.method()}"
```

## Functions

```cot
fn add(a: int, b: int) int {
    return a + b
}

fn greet(name: string) {           // no return = void
    println("Hello " + name)
}
```

## Function Types

Functions are first-class values. Use `fn` to declare function types.

```cot
// Function type syntax
fn(int, int) int                   // takes two ints, returns int
fn(string)                         // takes string, returns void
fn() bool                          // takes nothing, returns bool

// Type alias for readability
type Comparator = fn(int, int) int
type ErrorHandler = fn(Error) void

// Function as parameter
fn forEach(items: []int, callback: fn(int)) {
    for item in items {
        callback(item)
    }
}

// Function as variable
var handler: ?fn(Error) void = null
handler = myErrorHandler
if handler |h| {
    h(err)
}
```

## Structs

```cot
struct Point {
    x: int,
    y: int,
}

var p = Point{ .x = 10, .y = 20 }  // Zig-style init
p.x = 30
```

## Enums

```cot
// Simple enum
enum Color {
    red,
    green,
    blue,
}

// Enum with backing type
enum Token: u8 {
    eof,
    identifier,
    plus,
}

// Enum with explicit values
enum Precedence: u8 {
    none = 0,
    add = 4,
    mul = 5,
}

var c = Color.red
var t: Token = Token.eof
```

## Tagged Unions

Tagged unions combine an enum tag with associated data. Essential for AST nodes,
result types, and any situation where a value can be one of several variants.

```cot
// Define a tagged union
union Result {
    ok: int,
    err: string,
}

union Expr {
    literal: Literal,
    binary: Binary,
    unary: Unary,
    identifier: string,
}

// Construction - use variant name as constructor
var r: Result = Result.ok(42)
var e: Expr = Expr.literal(my_literal)

// Pattern matching with switch (captures payload)
var msg = switch r {
    .ok |value| => "got ${value}",
    .err |msg| => "error: ${msg}",
}

// Check active variant
if r == .ok {
    // r is the ok variant
}

// Access payload directly (panics if wrong variant)
var value = r.ok    // panics if r is .err
```

### Union Methods

Unions can have methods defined as functions taking self:

```cot
union Option {
    some: int,
    none,              // variant with no payload
}

fn isNone(self: Option) bool {
    return self == .none
}

fn unwrapOr(self: Option, default: int) int {
    return switch self {
        .some |v| => v,
        .none => default,
    }
}
```

## Switch Expressions

Switch is an expression that returns a value. Essential for pattern matching.

```cot
// Switch expression (returns value)
var name = switch token {
    Token.eof => "end of file",
    Token.plus => "+",
    Token.minus => "-",
    else => "unknown",
}

// Shorthand: infer enum type from subject
var name = switch token {
    .eof => "end of file",
    .plus, .minus => "operator",   // multiple values
    else => "unknown",
}

// Switch statement (no return value)
switch token {
    .plus => handlePlus(),
    .minus => handleMinus(),
    else => {},
}
```

## Arrays and Slices

```cot
var arr: [5]int = [1, 2, 3, 4, 5]  // fixed array
var slice: []int = arr[1..3]       // slice
arr[0]                             // index
len(arr)                           // length
```

## Control Flow

```cot
if (condition) {
    // ...
} else if (other) {
    // ...
} else {
    // ...
}

while (condition) {
    break
    continue
}

for i in 0..10 {
    // 0, 1, 2, ..., 9
}

for item in array {
    // iterate
}
```

## Operators

```cot
+ - * / %                // arithmetic
== != < <= > >=          // comparison (works on strings too)
and or not               // logical (keywords)
& | ^ ~ << >>            // bitwise
+ on strings             // concatenation

// Compound assignment
x += 1                   // x = x + 1
x -= 1                   // x = x - 1
x *= 2                   // x = x * 2
x /= 2                   // x = x / 2
x %= 2                   // x = x % 2
x &= mask                // x = x & mask
x |= flag                // x = x | flag
x ^= bits                // x = x ^ bits
x <<= n                  // x = x << n
x >>= n                  // x = x >> n
```

String comparison uses `==` and `!=` for equality, and `<`, `>`, etc. for lexicographic ordering.

## Defer

```cot
fn process() {
    var file = openFile("data.txt")
    defer closeFile(file)          // runs on scope exit

    // work with file...
    // closeFile called automatically
}
```

## Error Handling

Cot uses Zig-style explicit error handling. Functions that can fail return `!T` (T or error).

```cot
// Function that can fail - returns !int (int or error)
fn parseInt(s: string) !int {
    if s == "" {
        return error.EmptyString
    }
    if not isNumeric(s) {
        return error.InvalidFormat
    }
    return parseInternal(s)
}

// Void function that can fail - returns !
fn writeFile(path: string, data: string) ! {
    var file = try openFile(path)
    defer closeFile(file)
    try file.write(data)
}
```

### Propagating Errors with try

The `try` keyword propagates errors to the caller:

```cot
fn processData() !Result {
    var input = try readFile("input.txt")   // propagate if error
    var parsed = try parseData(input)        // propagate if error
    return transform(parsed)
}
```

### Handling Errors with catch

The `catch` keyword handles errors inline:

```cot
// Default value on error
var count = parseInt(s) catch 0

// Handle with block
var value = parseInt(s) catch |err| {
    println("parse failed: ${err}")
    return error.InvalidInput
}

// Convert error to different error
var data = readFile(path) catch |_| {
    return error.ConfigMissing
}
```

### Error Values

Errors are created with the `error.Name` syntax:

```cot
return error.NotFound
return error.PermissionDenied
return error.OutOfMemory
```

Error names are global - any error name can be used without prior declaration.

## Imports

```cot
import "scanner"                   // local module
```

## Heap Allocation

```cot
var list = new List<int>              // dynamic list
var map = new Map<string, int>        // hash map
var point = new Point{ .x = 10 }      // heap-allocated struct
```

`new` allocates on the heap, ARC handles cleanup. No manual free.

## Built-in Generic Collections

```cot
List<T>                    // dynamic array
  .push(item)
  .pop() T
  .get(index) T
  .len() int

Map<K, V>                  // hash map
  .set(key, value)
  .get(key) ?V
  .has(key) bool
  .delete(key)
  .len() int
```

## Memory Model

- Heap allocation via `new`, cleanup via ARC
- Structs are value types (stack by default)
- `new Struct{}` promotes to heap
- No manual memory management required

## Minimal Builtins

```cot
len(x)                   // length of array/slice/string
println(x)               // print with newline
print(x)                 // print without newline
@sizeof(T)               // compile-time size of type
@intFromEnum(e)          // convert enum to backing integer
@enumFromInt(T, i)       // convert integer to enum of type T
@intCast(T, v)           // cast integer v to type T (runtime checked)
@maxInt(T)               // maximum value for integer type T
@minInt(T)               // minimum value for integer type T
@min(a, b)               // minimum of two values
@max(a, b)               // maximum of two values
```

## NOT in 0.2 Bootstrap

These come after self-hosting:
- User-defined generics (built-in List/Map only)
- Traits
- impl blocks (methods)
- Closures/lambdas
- Typed error sets (E!T syntax)
- Weak references
- Comptime

## Future (Post-Bootstrap)

See SYNTAX.md for full planned feature set.
