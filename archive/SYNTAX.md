# Cot Language Syntax Reference

Quick reference for Claude. Example-first, minimal prose. Cot syntax is Zig-inspired with some Rust influences.

> **Implementation Status Legend:**
> - ✅ = Fully implemented and tested
> - ⚠️ = Partially implemented or has known bugs
> - ❌ = Not yet implemented

## Comments ✅

```cot
// Line comment
/* Block comment */
```

## Variables ✅

```cot
var x: i64 = 42          // Mutable, explicit type
var y = 42               // Mutable, inferred type
let z = 42               // 'let' is an alias for 'var'
const w: i64 = 42        // Immutable
const v = "hello"        // Immutable, inferred
```

### Module-Level Constants ✅

```cot
// Constants at module level are visible in all functions
const MAX_SIZE: i64 = 100
const GREETING: string = "Hello"
const PI: f64 = 3.14159

fn main() {
    println(GREETING)           // Prints "Hello"
    var arr: [MAX_SIZE]i64      // Use constant in type
    var circumference = 2.0 * PI * radius
}
```

Module-level constants are evaluated at compile-time and their values are inlined at each use site.

## Numeric Literals ✅

```cot
// Decimal integers
var x = 42
var big = 1000000

// Hexadecimal integers (0x or 0X prefix)
var hex = 0xFF          // 255
var mask = 0xFFFF       // 65535
var color = 0x1A2B3C    // 1715004

// Binary integers (0b or 0B prefix)
var bits = 0b1010       // 10
var byte = 0b11111111   // 255

// Floating-point decimals
var pi = 3.14159
var small = 0.001
```

Hex and binary literals are useful for bitwise operations:

```cot
var value = 0x1234
var mask = 0xFF00
var result = value & mask   // Bitwise AND: 0x1200 (4608)
```

## Primitive Types ✅

```cot
i8, i16, i32, i64, isize  // Signed integers (i64 is default)
u8, u16, u32, u64, usize  // Unsigned integers
f32, f64                  // Floats
bool                      // true, false
string                    // String type
decimal                   // Fixed-point decimal (financial math)
void                      // No value
```

## Optional Types ✅

```cot
var x: ?i64 = 42         // Optional with value ✅
var y: ?i64 = null       // Optional null ✅
if (x != null) { }       // Null check ✅
if (x == null) { }       // Is null check ✅
x?.field                 // Null-safe field access ✅
x ?? default             // Null coalescing ✅

// Pointer to optional pointer coercion ✅
var ptr: *Node = &node
var opt: ?*Node = ptr    // *T implicitly converts to ?*T
```

## Pointers ✅

```cot
var p: *i64              // Mutable pointer ✅
var cp: *const i64       // Const pointer ✅
p.*                      // Dereference ✅
&value                   // Address-of ✅
```

## Heap Allocation (PLANNED)

Cot has full ARC (automatic reference counting) support in the runtime. Heap-allocated
objects are automatically freed when their reference count reaches zero.

The `new` keyword allocates on the heap and returns a pointer:

```cot
// Heap-allocated struct, returns *Point (ARC-managed)
var p = new Point{ .x = 10, .y = 20 }
p.x = 30                 // Modify through pointer
println(p.x)             // Auto-dereference for field access

// Compare to stack-allocated:
var s = Point{ .x = 10, .y = 20 }  // Stack, type is Point (not pointer)
```

### Unified `new` Syntax

The `new` keyword works consistently for all heap-allocated types:

```cot
// Structs
var point = new Point{ .x = 10, .y = 20 }

// List - empty or with initial values
var list = new List<i64>
var list = new List<i64>{ 1, 2, 3 }

// Map - empty or with initial values
var map = new Map<string, i64>
var map = new Map<string, i64>{ "a": 1, "b": 2 }
```


### Memory Management

```cot
// ARC handles cleanup automatically
fn createPoint() *Point {
    return new Point{ .x = 1, .y = 2 }  // Refcount = 1
}

var p1 = createPoint()    // p1 owns the reference
var p2 = p1               // p2 shares reference, refcount = 2
p1 = null                 // refcount = 1
p2 = null                 // refcount = 0, memory freed

// Weak references don't prevent cleanup
var strong = new Node{ .value = 42 }
var weak_ref: weak *Node = strong
strong = null             // Node freed, weak_ref becomes null
```

### Self-Referential Structures

```cot
struct Node {
    value: i64,
    next: ?*Node,         // Optional pointer to another Node
}

// Create linked list with heap allocation
var head = new Node{ .value = 1, .next = null }
head.next = new Node{ .value = 2, .next = null }
head.next.next = new Node{ .value = 3, .next = null }

// ARC + cycle collector handles circular references
```

## Arrays and Slices ✅

```cot
var arr: [5]i64 = [1, 2, 3, 4, 5]   // Fixed-size array ✅
var arr = [1, 2, 3]                  // Inferred array ✅
arr[0]                               // Index access (0-based) ✅
arr?[10]                             // Optional index (returns null if OOB) ✅
arr[1..3]                            // Array slice (returns list) ✅
arr[1..=3]                           // Inclusive array slice ✅

var slice: []i64                     // Slice type ✅
len(arr)                             // Array/slice length ✅
```


## Ranges ✅

```cot
0..5                     // Exclusive range: 0, 1, 2, 3, 4
0..=5                    // Inclusive range: 0, 1, 2, 3, 4, 5

for i in 0..5 { }        // Iterate 0-4 ✅
for i in 0..=5 { }       // Iterate 0-5 ✅
```

## Strings ✅

```cot
var s = "hello"
len(s)                     // String length ✅
s[0..3]                    // Substring: "hel" (0-based, end exclusive) ✅
s + " world"               // Concatenation ✅
"Count: " + 42             // Auto-converts i64 to string (no cast needed!) ✅
"Value: " + x              // Auto-converts any type to string ✅
"Hello ${name}!"           // String interpolation ✅
"Sum: ${a + b}"            // Expression interpolation ✅

// Character access (byte-level)
s[0]                       // Get byte value (i64) at index ✅
s[i]                       // Index with variable ✅
                           // Returns ASCII/UTF-8 byte at position (0-255)
                           // Out of bounds returns 0
s.char_at(0)               // Legacy method, same as s[0] ✅
                           // Alternative: s[0..1] for single-char substring

// Built-in string functions
upcase(s)                  // "HELLO" ✅
locase(s)                  // "hello" ✅
trim(s)                    // Remove whitespace ✅
instr(haystack, needle)    // Find position (-1 if not found) ✅
char(65)                   // "A" (ASCII code to char) ✅
```

## Functions ✅

```cot
fn add(a: i64, b: i64) i64 {
    return a + b
}

fn greet(name: string) {            // No return type = void
    println("Hello " + name)
}

fn nothing() void { }               // Explicit void

fn process(data: *MyStruct) {       // Pointer parameter (mutable)
    data.field = 42
}
```

## Generics ✅ FULLY IMPLEMENTED

Built-in generic types (`List<T>`, `Map<K,V>`) are fully working. User-defined generics work including generic structs, generic functions, generic traits with nested bounds, and trait-constrained generic functions.

Type arguments support any type, including pointer types and optional types.

```cot
// Built-in generic types - FULLY WORKING ✅
var numbers = new List<i64>
numbers.push(42)

var lookup = new Map<string, i64>
lookup.set("key", 100)

// Pointer types as generic arguments ✅
var ptrs: List<*Node> = new List<*Node>
var opt_map: Map<string, ?i64> = new Map<string, ?i64>

// User-defined generic struct ✅
struct Box<T> {
    value: T,
}
var box = Box<i64>{ .value = 42 }

// User-defined generic function ✅
fn identity<T>(x: T) T {
    return x
}

// Multiple type parameters ✅
struct Pair<K, V> {
    key: K,
    value: V,
}

// Type bounds ✅
fn compare<T: Comparable>(a: T, b: T) bool {
    return a == b
}
```

**Implementation details:**
- Generic instantiation uses name mangling (e.g., `Box__i64`)
- Instantiated functions/structs are cached to avoid duplication
- See `src/ir/lower.zig:1049` for `instantiateGenericFn()`
- See `src/ir/lower.zig:941` for `instantiateGenericStruct()`

## Visibility ✅

```cot
pub fn public_function() { }        // Public function
pub struct PublicStruct { }         // Public struct
pub const PUBLIC_CONST: i64 = 42    // Public constant

// No keyword = private (module-scoped)
fn private_function() { }
```

## Structs ✅

```cot
struct Point {
    x: i64,
    y: i64,
}

// Initialization (MUST use .field = value syntax)
var p: Point = Point{ .x = 10, .y = 20 }
var p = Point{ .x = 10, .y = 20 }

// Field access
p.x                      // Read field
p.x = 30                 // Write field

// Nested struct
struct Rect {
    origin: Point,
    size: Point,
}
var r = Rect{ .origin = Point{ .x = 0, .y = 0 }, .size = Point{ .x = 100, .y = 50 } }
r.origin.x               // Nested access
```

## Self-Referential Structs ✅

```cot
struct Node {
    value: i64,
    next: ?*Node,        // Optional pointer to same type
}
```

## Impl Blocks (Methods) ✅

```cot
struct Counter {
    value: i64,
}

impl Counter {
    // Constructor (Zig-style: use init() for struct initialization)
    fn init(initial: i64) Counter {
        return Counter{ .value = initial }
    }

    // Method with self (reads struct)
    fn get(self: Counter) i64 {
        return self.value
    }

    // Method with pointer self (modifies struct)
    fn increment(self: *Counter) {
        self.value = self.value + 1
    }
}

// Calling methods
var c = Counter.init(0)  // Constructor via static method (Zig-style)
c = new Counter{ .value = 0 }  // Or heap-allocate directly
c.get()                  // Instance method call
c.increment()            // Mutating method call
```

### Constructor Convention (Zig-Style) ✅

Cot follows Zig's convention of using `.init()` for struct constructors:

```cot
struct Point {
    x: i64,
    y: i64,
}

impl Point {
    // Constructor - returns value type
    fn init(x: i64, y: i64) Point {
        return Point{ .x = x, .y = y }
    }

    // Named constructor for common cases
    fn zero() Point {
        return Point{ .x = 0, .y = 0 }
    }

    // Conversion constructor
    fn fromPolar(r: f64, theta: f64) Point {
        return Point{
            .x = @intCast(r * cos(theta)),
            .y = @intCast(r * sin(theta)),
        }
    }
}

// Usage
var p1 = Point.init(10, 20)      // Construct via init()
var p2 = Point.zero()            // Named constructor
var p3 = Point{ .x = 5, .y = 5 } // Direct struct literal (also valid)
```

- `init()` is the standard constructor name (like Zig)
- `new Type{...}` is for heap allocation, returns `*Type`
- `Type{...}` is for stack allocation / struct literals

## Enums ✅

```cot
enum Color {
    Red,
    Green,
    Blue,
}

var c: Color = Color.Red

// Enum equality
if (c == Color.Red) { }

// Enum comparison by declaration order (ordinal)
if (Color.Red < Color.Blue) { }      // true (0 < 2)
if (Color.Green <= Color.Green) { }  // true (1 <= 1)

// Enum to integer conversion
var x: i64 = Color.Green as i64      // x = 1 (ordinal)

// Integer to enum conversion
var c2: Color = 2 as Color           // c2 = Color.Blue

// Switch on enum
switch (c) {
    Color.Red => { println("red") }
    Color.Green => { println("green") }
    Color.Blue => { println("blue") }
}
```

## Traits ✅

Traits, trait objects, trait bounds, default implementations, generic traits, and associated types are all fully implemented.

```cot
// Trait definition ✅
trait Printable {
    fn print(self);
}

// Implement trait for type ✅
impl Printable for Point {
    fn print(self) {
        println("Point(" + self.x + ", " + self.y + ")")
    }
}

// Dynamic trait object (runtime dispatch) ✅
var obj: dyn Printable = point
obj.print()

// Generic traits ✅
trait Iterator<T> {
    fn next(self) ?T;
}

// Trait bounds in generics ✅
fn print_all<T: Printable>(items: List<T>) { }

// Default trait implementations ✅
trait Display {
    fn show(self: Display) string     // Required method

    // Default implementation that calls required method
    fn debug(self: Display) string {
        return "[DEBUG] " + self.show()
    }
}

impl Display for Point {
    fn show(self: Point) string {
        return "Point(" + string(self.x) + ", " + string(self.y) + ")"
    }
    // debug() uses the default implementation automatically
}

// Associated types in traits ✅
trait Container {
    type Item;                           // Associated type declaration
    fn get(self: Container) Self.Item    // Method returning associated type
}

impl Container for IntBox {
    type Item = i64;                     // Bind associated type to concrete type
    fn get(self: IntBox) Self.Item {
        return self.value
    }
}
```

**Implementation details:**
- Vtable-based dispatch for `dyn Trait` objects
- `make_trait_object` and `call_trait_method` VM opcodes exist
- See `src/ir/lower.zig:1239` for `lowerTraitDef()`
- See `tests/trait_object_basic.cot` for working examples

## Unions (Overlaid Memory) ✅

```cot
// Union - all fields share same memory (DBL compatibility)
union Number {
    as_int: i64,
    as_float: f64,
}

// Only one field valid at a time
var n: Number = Number{ .as_int = 42 }
```

## Views (Field Aliases) ✅

```cot
// View - alias into a field (DBL record compatibility)
struct Record {
    data: [100]u8,
    view name: string = @data,            // Alias to start of data
    view id: i64 = @data + 50,            // Alias with offset
}
```

## Weak References ✅

```cot
// Weak reference - doesn't prevent the target from being freed
// When the target is freed, the weak reference becomes null
var data: string = "hello"
var weak_data: weak string = data

// Access weak reference (may be null if target was freed)
println(weak_data)

// Weak references are automatically nulled when target is freed
data = "new value"  // Old "hello" may be freed
// weak_data is now null if ARC freed the original

// Multiple weak refs to the same target
var weak1: weak string = data
var weak2: weak string = data

// Reassigning weak references
var other: string = "world"
weak_data = other
```

## Control Flow

### If/Else ✅

```cot
if (condition) {
    // body
}

if (condition) {
    // then
} else {
    // else
}

if (a) {
    // ...
} else if (b) {
    // ...
} else {
    // ...
}
```

### If Expressions ✅

If expressions return a value based on a condition. Unlike if statements, the else branch is required:

```cot
// Basic if expression
var result = if (condition) value1 else value2

// In function return
fn max(a: i64, b: i64) i64 {
    return if (a > b) a else b
}

// Chained if-else-if
var sign = if (x > 0) 1 else if (x < 0) -1 else 0

// Used inline
println("Status: " + if (success) "OK" else "FAILED")
```

Both branches must have the same type.

### While Loop ✅

```cot
while (condition) {
    // body
    if (done) { break }
    if (skip) { continue }
}
```

### For-In Loop (Iteration) ✅

```cot
// Range iteration (end exclusive)
for i in 0..5 {
    println(i)           // 0, 1, 2, 3, 4
}

// Array iteration
var arr = [10, 20, 30]
for item in arr {
    println(item)
}
```

### Loop (Infinite) ✅

```cot
loop {
    // infinite loop
    if (done) { break }
}
```

### Switch ✅

```cot
switch (value) {
    1 => { println("one") }
    2 => { println("two") }
    3 => { println("three") }
}

// Switch on strings
switch (name) {
    "alice" => { }
    "bob" => { }
}

// Multi-statement arms use braces
switch (x) {
    1 => {
        var y = x + 1
        println(y)
    }
    2 => { println("two") }
}

// Default case
switch (x) {
    1 => println("one"),
    else => println("other")
}
```

## Error Handling ✅

```cot
// Throwing errors ✅
fn divide(a: i64, b: i64) i64 {
    if (b == 0) {
        throw "division by zero"
    }
    return a / b
}

// Catching errors ✅
try {
    var result = divide(10, 0)
} catch {
    println("caught error")
}

// Catch with error binding ✅
try {
    throw "something went wrong"
} catch (err) {
    println("Error: " + err)
}

// Use defer for cleanup that must always run
defer cleanup()         // Runs when scope exits (success or error)
try {
    riskyOperation()
} catch {
    println("error")
}

// Nested try/catch ✅
try {
    try {
        throw "inner"
    } catch {
        throw "rethrow"
    }
} catch {
    println("outer caught")
}
```

## Defer ✅

```cot
// Defer - executes at end of scope
fn process() {
    var file = openFile("data.txt")
    defer closeFile(file)           // Will run when function returns

    // ... use file ...
    // file automatically closed on return
}
```

## Lambdas and Closures ✅

```cot
// Lambda syntax: |params| { body }
var add = |a: i64, b: i64| {
    return a + b
}
var result = add(3, 4)

// Closure (captures outer variable)
var multiplier: i64 = 10
var scale = |x: i64| {
    return x * multiplier     // captures multiplier
}
scale(5)                      // returns 50
```

## Map<K, V> ✅

```cot
var m = new Map<string, i64>

m.set("key", 42)
m.get("key")              // 42
m.has("key")              // true
m.delete("key")
m.len()                   // 0
m.clear()

// Pattern: check before get
if (m.has("key")) {
    var val = m.get("key")
}
```

## List<T> ✅

```cot
var list = new List<i64>

list.push(10)
list.push(20)
list.get(0)               // 10
list.set(0, 99)           // change first element
list.pop()                // remove and return last
list.len()                // length
list.clear()              // remove all

// Lists can hold any type, including pointers ✅
var nodes: List<*Node> = new List<*Node>
nodes.push(&node1)
nodes.push(&node2)
const ptr = nodes.get(0)  // Returns *Node
println(ptr.value)        // Access through pointer
```

## Imports ✅

```cot
import "token"            // Import local module
import "std/io"           // Import with path
import utils              // Import package (from cot.json dependencies)

// Package functions use qualified names
var result = utils.add(5, 3)
utils.multiply(4, 7)
```

### Cross-Package Imports

In a workspace, packages declare dependencies in `cot.json`:
```json
{
  "dependencies": {
    "utils": "workspace:../../packages/utils"
  }
}
```

The imported package's `pub` functions are automatically exported:
```cot
// packages/utils/lib.cot
pub fn add(a: i64, b: i64) i64 { return a + b }
```

No explicit `exports` field needed in `cot.json` - `pub` keyword is sufficient.

## Tests ✅

```cot
test "description of test" {
    var x = 2 + 2
    assert(x == 4, "math should work")
}

test "another test" {
    assert(true, "should pass")
}
```

## Function Types ✅

```cot
// Function type signature
fn(i64, i64) -> i64              // Takes two i64, returns i64
fn(string) -> void               // Takes string, returns nothing

// Function as parameter
fn apply(f: fn(i64) -> i64, x: i64) i64 {
    return f(x)
}

// Assigning function to variable
var callback: fn(i64) -> i64 = add
```

## Type Aliases ✅

```cot
type Handler = fn(string) -> void
type IntPair = Pair<i64, i64>

var h: Handler = myHandler
```

## Type Operators ✅

```cot
// Type testing with 'is' - runtime type checking ✅
// Works for primitive types (i64, f64, string, bool)
if (value is i64) {
    println("it's an integer")
}
if (value is string) {
    println("it's a string")
}
if (value is bool) {
    println("it's a boolean")
}
if (value is f64) {
    println("it's a float")
}

// Type casting with 'as' (for enums and primitives) ✅
var x: i64 = Color.Green as i64      // Enum to int
var c: Color = 2 as Color            // Int to enum
var s: string = 42 as string         // Int to string (same as string(42))
```

**Note:** The `is` operator currently only supports primitive types. Struct/enum type checking returns an error.

## Compile-Time Features ✅ IMPLEMENTED

Comptime blocks, conditional compilation, and builtin functions are fully implemented.

```cot
// Comptime block ✅
comptime {
    // Code evaluated at compile time
}

// Comptime if - conditional compilation ✅
comptime if (@os() == "windows") {
    // Windows-specific code
} else {
    // Other platforms
}

// Type introspection builtins ✅
@sizeof(T)          // Size of type in bytes
@alignof(T)         // Alignment of type
@typeName(T)        // Get type name as string: @typeName(Point) -> "Point"
@hasField(T, "x")   // Check if struct has field: @hasField(Point, "x") -> true
@fieldNames(T)      // Get comma-separated field names: @fieldNames(Point) -> "x,y"

// Environment queries ✅
@os()               // "macos", "linux", "windows", etc.
@arch()             // "x86_64", "arm64", etc.

// Build info ✅
@file()             // Current source file path
@line()             // Current line number
@version()          // Compiler version ("0.1.0")

// Symbol checking ✅ (always returns false currently)
@defined(name)      // Check if name is defined
```

**Implementation status:**
- `comptime` blocks: Parsing ✅, AST ✅, IR lowering ✅
- `comptime if`: Works for conditional compilation ✅
- `@builtin()` functions: Fully implemented ✅
- See `src/parser/parser.zig` for comptime parsing
- See `src/ir/lower_expr.zig:lowerComptimeBuiltin` for builtin evaluation

## Operators

### Arithmetic ✅
```cot
a + b      // Add
a - b      // Subtract
a * b      // Multiply
a / b      // Divide
a % b      // Modulo
-a         // Negate
```

### Comparison ✅
```cot
a == b     // Equal
a != b     // Not equal
a < b      // Less than
a <= b     // Less or equal
a > b      // Greater than
a >= b     // Greater or equal
```

### Logical ✅
```cot
a and b    // Logical AND (keyword, not &&)
a or b     // Logical OR (keyword, not ||)
not a      // Logical NOT (keyword, not !)
!a         // Also logical NOT
```

### Bitwise ✅
```cot
a & b      // Bitwise AND ✅
a | b      // Bitwise OR ✅
a ^ b      // Bitwise XOR ✅
~a         // Bitwise NOT ✅
```

### Assignment ✅
```cot
a = b      // Assign
a += b     // Add-assign
a -= b     // Subtract-assign
a *= b     // Multiply-assign
a /= b     // Divide-assign
a |= b     // Bitwise OR-assign
a &= b     // Bitwise AND-assign
```

### Shift Operators ✅
```cot
a << b     // Left shift
a >> b     // Right shift
```

### Special Operators ✅
```cot
s ++ t     // String concatenation (alternative to +)
a # b      // Truncating rounding / string hash
a ## b     // True rounding
```

## Common Mistakes to Avoid

```cot
// WRONG: C-style struct init
var p = Point{ x: 10, y: 20 }        // NO!
// CORRECT: Zig-style with .field =
var p = Point{ .x = 10, .y = 20 }    // YES!

// WRONG: C-style pointer deref (compile error)
var x = *ptr                          // NO! This is a compile error
// CORRECT: Zig-style postfix deref
var x = ptr.*                         // YES!

// WRONG: && and || for logic (but these DO work)
if (a && b) { }                       // Works, but prefer 'and'
// PREFERRED: Use keywords
if (a and b) { }                      // Preferred style

// WRONG: No parentheses on if
if condition { }                       // NO!
// CORRECT: Parentheses required
if (condition) { }                     // YES!

// WRONG: match keyword (Rust)
match (x) { }                          // NO!
// CORRECT: switch keyword (Zig-style)
switch (x) { }                         // YES!

// WRONG: Rust-style Result type
fn foo() Result<i64, Error> { }        // NO!
// CORRECT: Use try/catch/throw
fn foo() i64 { throw "error" }         // YES!

// WRONG: let keyword (Rust)
let x = 42                             // NO!
// CORRECT: var or const
var x = 42                             // YES! (mutable)
const x = 42                           // YES! (immutable)

// WRONG: func keyword (Go)
func foo() { }                         // NO!
// CORRECT: fn keyword
fn foo() { }                           // YES!

// WRONG: : for function return (TypeScript)
fn foo(): i64 { }                      // NO!
// CORRECT: Space before return type
fn foo() i64 { }                       // YES!

// WRONG: Rust-style generic syntax
Vec<T>                                 // Works but prefer...
// PREFERRED: Built-in List<T>
List<T>                                // Built-in generic list

// WRONG: :: for static method (Rust)
Type::method()                         // NO!
// CORRECT: Dot notation
Type.method()                          // YES!
```

## Standard Library Functions

### I/O ✅
```cot
println("text")           // Print with newline
print("text")             // Print without newline
readln()                  // Read line from stdin
readkey()                 // Read single key
```

### Math ✅
```cot
abs(x)                    // Absolute value
sqrt(x)                   // Square root
sin(x), cos(x), tan(x)    // Trig functions
log(x), log10(x)          // Logarithms
exp(x)                    // e^x
pow(x, y)                 // x^y
round(x), trunc(x)        // Rounding
```

### Type Conversion ✅
```cot
string(42)                // "42" - int to string
str(42)                   // "42" - alias for string()
int("42")                 // 42 - string to int (may throw)
bool(x)                   // Convert to bool
```

---

## Reserved Keywords

The following words are reserved and cannot be used as identifiers (variable names, function names, etc.):

### Declaration Keywords
`fn`, `struct`, `union`, `enum`, `trait`, `impl`, `const`, `var`, `type`, `pub`, `static`, `view`, `dyn`

### Control Flow Keywords
`if`, `else`, `switch`, `for`, `in`, `while`, `loop`, `break`, `continue`, `return`

### Error Handling Keywords
`try`, `catch`, `throw`, `defer`

### Operators and Literals
`and`, `or`, `not`, `as`, `is`, `true`, `false`, `null`, `self`, `new`

### Async Keywords
`async`, `await`

### Other Keywords
`import`, `weak`, `comptime`, `test`

**Note:** `new` is a keyword used for heap allocation (`new Type{...}`, `new List<T>`). It cannot be used as a function or variable name.

### Quoted Identifiers

To use a reserved keyword as an identifier, use the `@"..."` syntax (Zig-style):

```cot
// Use a keyword as a struct field name
struct MyData {
    @"type": string,      // "type" is a reserved keyword
    @"struct": i64,       // "struct" is a reserved keyword
    name: string,
}

// Access with quoted identifier
var data = MyData{ .@"type" = "example", .@"struct" = 42, .name = "test" }
println(data.@"type")    // prints: example

// Also allows identifiers with spaces (useful for FFI)
var @"my field" = 123
```

---

## Implementation Status

### Recently Fixed ✅
- `x != null` comparison
- `len(arr)` for arrays
- `impl` blocks (methods on structs)
- Bitwise operators (`&`, `|`, `^`, `~`)
- Shift operators (`<<`, `>>`)
- Switch default case (`else =>`)
- Optional chaining (`?.`)
- Pointer dereference (`.*`)
- Enum comparison (`<`, `<=`, `>`, `>=`)
- `as` casting (enum↔int, primitives)
- Module-level `const` declarations visible in functions

### Mostly Implemented ⚠️
1. **Generic functions and structs** - Works for user-defined generics (`Box<T>`, `Pair<K,V>`),
   name mangling (`Box__i64`), constraint validation. Known issues:
   - Generic functions returning `string` type return corrupted/empty values
   - Generic functions with trait constraints don't dispatch trait methods correctly
   - See `tests/generics_comprehensive_test.cot` for test cases

### Fully Implemented ✅
- **Traits** - Trait definitions, `impl Trait for Type`, vtable dispatch, default implementations, trait bounds
- **Generic traits** - `trait Iterator<T>`, nested generic bounds like `<T: Container<i64>>`, `>>` token splitting
- **Associated types** - `type Item;` in traits, `type Item = i64;` in impls, `Self.Item` type resolution
- **Comptime** - `comptime` blocks, `comptime if`, and all builtins (`@os`, `@arch`, `@sizeof`, `@typeName`, `@hasField`, `@fieldNames`, etc.)
- **Type operator `is`** - Runtime type checking: `if value is SomeType { ... }`
- **Weak references** - `weak T` type, `op_weak_ref` opcode, GC integration

### Removed from Language
- **`finally` blocks** - Use `defer` instead. Defer is fully implemented with proper
  scope tracking (works with return, break, continue through nested scopes).
