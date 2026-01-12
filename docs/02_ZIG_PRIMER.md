# Zig Primer for the Cot Compiler

**Purpose:** This document explains Zig language features used throughout the Cot compiler codebase. You don't need to become a Zig expert - just understand these concepts to read the implementation.

---

## Why Zig?

Zig is the "bootstrap language" for Cot. We use it because:
1. **No hidden allocations** - You always see when memory is allocated
2. **No hidden control flow** - No exceptions, no operator overloading
3. **Compiles to efficient machine code** - Good for a compiler
4. **Easy C interop** - We can use system libraries easily

Once Cot is complete enough, we'll rewrite the compiler in Cot itself (self-hosting).

---

## Table of Contents

1. [Variables and Types](#1-variables-and-types)
2. [Functions](#2-functions)
3. [Optionals](#3-optionals)
4. [Error Handling](#4-error-handling)
5. [Allocators](#5-allocators)
6. [Slices and Arrays](#6-slices-and-arrays)
7. [Structs](#7-structs)
8. [Enums and Unions](#8-enums-and-unions)
9. [Pointers](#9-pointers)
10. [Control Flow](#10-control-flow)
11. [Comptime](#11-comptime)
12. [Common Patterns in Our Code](#12-common-patterns-in-our-code)

---

## 1. Variables and Types

### Declaring Variables

```zig
// Immutable (cannot be changed)
const x: i32 = 42;

// Mutable (can be changed)
var y: i32 = 10;
y = 20;  // OK

// Type inference (Zig figures out the type)
const z = 42;  // Zig infers i32 (or comptime_int)
```

### Basic Types

| Type | Description | Size |
|------|-------------|------|
| `i8`, `i16`, `i32`, `i64` | Signed integers | 1, 2, 4, 8 bytes |
| `u8`, `u16`, `u32`, `u64` | Unsigned integers | 1, 2, 4, 8 bytes |
| `f32`, `f64` | Floating point | 4, 8 bytes |
| `bool` | Boolean | 1 byte |
| `void` | No value | 0 bytes |
| `usize` | Pointer-sized unsigned int | 4 or 8 bytes |

### Cot Comparison

```zig
// Zig
const x: i64 = 42;
var y: i64 = 10;
```

```cot
// Cot (similar but slightly different syntax)
const x: i64 = 42
var y: i64 = 10
```

---

## 2. Functions

### Basic Functions

```zig
fn add(a: i32, b: i32) i32 {
    return a + b;
}

// Calling
const result = add(2, 3);  // result = 5
```

### Functions That Can Fail

```zig
// Returns either a u32 OR an error
fn divide(a: u32, b: u32) !u32 {
    if (b == 0) return error.DivisionByZero;
    return a / b;
}
```

The `!` before the return type means "this function can fail."

### Methods (Functions on Structs)

```zig
const Point = struct {
    x: i32,
    y: i32,

    // Method - first parameter is self
    fn distanceFromOrigin(self: Point) f64 {
        const x_f: f64 = @floatFromInt(self.x);
        const y_f: f64 = @floatFromInt(self.y);
        return @sqrt(x_f * x_f + y_f * y_f);
    }
};

const p = Point{ .x = 3, .y = 4 };
const dist = p.distanceFromOrigin();  // 5.0
```

---

## 3. Optionals

Optionals represent "a value that might not exist." They're safer than null pointers.

### The `?` Type

```zig
// This can hold either a u32 or "null"
var maybe_number: ?u32 = 42;

maybe_number = null;  // Now it's empty
```

### Unwrapping Optionals

```zig
fn process(maybe_value: ?u32) void {
    // Method 1: if statement (safe)
    if (maybe_value) |value| {
        // value is guaranteed to be a real u32 here
        std.debug.print("Got: {}\n", .{value});
    } else {
        std.debug.print("Nothing!\n", .{});
    }

    // Method 2: orelse (provide default)
    const val = maybe_value orelse 0;  // Use 0 if null

    // Method 3: .? (crash if null - use carefully!)
    const must_exist = maybe_value.?;  // PANIC if null
}
```

### Cot Comparison

```cot
// Cot uses similar syntax
var maybe_number: ?u32 = 42
maybe_number = null

// Capture syntax
if maybe_number |value| {
    println(value)
}

// Null coalescing
var val = maybe_number ?? 0
```

---

## 4. Error Handling

Zig doesn't have exceptions. Instead, functions that can fail return an **error union**.

### Error Union Type: `!T`

```zig
// This function returns either a u32 OR an error
fn readNumber() !u32 {
    // ... something that might fail
    return error.InvalidInput;  // Return an error
    // OR
    return 42;  // Return success
}
```

### Handling Errors with `try`

```zig
fn doWork() !void {
    // If readNumber fails, doWork immediately returns that error
    const num = try readNumber();

    // Only reaches here if readNumber succeeded
    std.debug.print("Got: {}\n", .{num});
}
```

`try x` is shorthand for:
```zig
const num = readNumber() catch |err| return err;
```

### Handling Errors with `catch`

```zig
// Provide a default value on error
const num = readNumber() catch 0;

// Handle the error explicitly
const num = readNumber() catch |err| {
    std.debug.print("Error: {}\n", .{err});
    return;
};
```

### Defining Error Sets

```zig
const ParseError = error{
    InvalidCharacter,
    UnexpectedEnd,
    Overflow,
};

fn parse(input: []const u8) ParseError!u32 {
    if (input.len == 0) return error.UnexpectedEnd;
    // ...
}
```

### Cot Comparison

```cot
// Cot uses Result<T, E> instead of error unions
fn readNumber() Result<u32, Error> {
    if failed {
        return .err(Error.InvalidInput)
    }
    return .ok(42)
}

// Using the result
var result = readNumber()
switch result {
    .ok |value| => println(value)
    .err |e| => println("Error!")
}

// Propagation with ?
fn doWork() Result<void, Error> {
    var num = readNumber()?  // Returns early on error
    println(num)
    return .ok(void{})
}
```

---

## 5. Allocators

This is Zig's most distinctive feature. **Memory allocation is always explicit.**

### The Problem Allocators Solve

In many languages, you write:
```javascript
let items = [];
items.push(1);  // Where does memory come from? 🤷
```

In Zig, you must specify:
```zig
var items = std.ArrayList(u32).init(allocator);  // You choose the allocator
try items.append(1);  // Might fail if out of memory
defer items.deinit();  // Don't forget to free!
```

### Common Allocators

```zig
// 1. Page allocator - gets memory directly from OS
const page_allocator = std.heap.page_allocator;

// 2. Arena allocator - fast, bulk-free all at once
var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
defer arena.deinit();  // Frees everything at once
const allocator = arena.allocator();

// 3. General purpose allocator - good default choice
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
defer _ = gpa.deinit();
const allocator = gpa.allocator();
```

### Using an Allocator

```zig
// Allocate a single item
const ptr = try allocator.create(MyStruct);
defer allocator.destroy(ptr);

// Allocate an array
const buffer = try allocator.alloc(u8, 1024);
defer allocator.free(buffer);
```

### In Our Codebase

We typically use `ArenaAllocator` because:
1. Compiling is a single operation - we can free everything at the end
2. It's fast (no tracking individual allocations)
3. Less code (one `defer arena.deinit()` instead of many)

```zig
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // All allocations use this arena
    var scanner = Scanner.init(allocator, source);
    var parser = Parser.init(allocator, &scanner);
    // ... etc
}
```

### Cot Comparison

Cot will use **automatic reference counting (ARC)**, so you won't need allocators:

```cot
// Cot - no allocator needed
var items = new List<u32>()
items.push(1)
// Memory automatically freed when items goes out of scope
```

---

## 6. Slices and Arrays

### Arrays (Fixed Size)

```zig
// Array of 5 u32s - size is part of the type
const arr: [5]u32 = .{ 1, 2, 3, 4, 5 };

// Access
const first = arr[0];  // 1
const length = arr.len;  // 5 (known at compile time)
```

### Slices (Dynamic Size)

```zig
// Slice - pointer + length, size not part of type
const slice: []const u32 = &arr;  // Create slice from array

// Same access syntax
const first = slice[0];
const length = slice.len;  // Runtime value
```

### The Difference

| | Array `[N]T` | Slice `[]T` |
|-|--------------|-------------|
| Size known at | Compile time | Runtime |
| Can resize | No | Depends on backing storage |
| Stored as | Inline values | Pointer + length |

```zig
fn printAll(items: []const u32) void {  // Takes any size
    for (items) |item| {
        std.debug.print("{}\n", .{item});
    }
}

const a: [3]u32 = .{ 1, 2, 3 };
const b: [5]u32 = .{ 1, 2, 3, 4, 5 };

printAll(&a);  // Works!
printAll(&b);  // Also works!
```

### String Slices

Strings in Zig are just `[]const u8`:

```zig
const greeting: []const u8 = "Hello, world!";
// OR
const greeting = "Hello, world!";  // Same type
```

### Cot Comparison

```cot
// Cot arrays
const arr: [5]u32 = [1, 2, 3, 4, 5]

// Cot slices
var slice: []u32 = arr[0..3]  // Elements 0, 1, 2

// Cot strings are a distinct type (not just []u8)
var greeting: string = "Hello, world!"
```

---

## 7. Structs

### Defining Structs

```zig
const Token = struct {
    kind: TokenKind,
    text: []const u8,
    line: u32,
    column: u32,

    // Method
    fn isKeyword(self: Token) bool {
        return switch (self.kind) {
            .kw_fn, .kw_return, .kw_if => true,
            else => false,
        };
    }

    // "Static" method (no self)
    fn eof() Token {
        return Token{
            .kind = .eof,
            .text = "",
            .line = 0,
            .column = 0,
        };
    }
};
```

### Creating Instances

```zig
// All fields specified
const tok = Token{
    .kind = .identifier,
    .text = "foo",
    .line = 1,
    .column = 5,
};

// Using a "constructor" function
const eof_tok = Token.eof();
```

### Default Values

```zig
const Config = struct {
    debug: bool = false,      // Default value
    max_errors: u32 = 10,     // Default value
    source: []const u8,       // Required (no default)
};

// Can omit fields with defaults
const cfg = Config{
    .source = "hello.cot",
    // debug defaults to false
    // max_errors defaults to 10
};
```

### Cot Comparison

```cot
// Very similar syntax
struct Token {
    kind: TokenKind
    text: string
    line: u32
    column: u32
}

// Struct literal
var tok = Token{
    .kind = .identifier
    .text = "foo"
    .line = 1
    .column = 5
}
```

---

## 8. Enums and Unions

### Enums

```zig
const TokenKind = enum(u8) {
    // Variants
    eof,
    identifier,
    int_literal,
    kw_fn,
    kw_return,
    plus,
    minus,

    // Method on enum
    fn isOperator(self: TokenKind) bool {
        return switch (self) {
            .plus, .minus => true,
            else => false,
        };
    }
};

const kind = TokenKind.identifier;
```

### Tagged Unions

```zig
const Value = union(enum) {
    integer: i64,
    float: f64,
    string: []const u8,
    boolean: bool,
    none,  // No payload

    // Method
    fn asInt(self: Value) ?i64 {
        return switch (self) {
            .integer => |i| i,
            else => null,
        };
    }
};

// Creating
const v1 = Value{ .integer = 42 };
const v2 = Value{ .string = "hello" };
const v3 = Value.none;

// Pattern matching with switch
fn printValue(v: Value) void {
    switch (v) {
        .integer => |i| std.debug.print("int: {}\n", .{i}),
        .float => |f| std.debug.print("float: {}\n", .{f}),
        .string => |s| std.debug.print("string: {s}\n", .{s}),
        .boolean => |b| std.debug.print("bool: {}\n", .{b}),
        .none => std.debug.print("none\n", .{}),
    }
}
```

### Cot Comparison

```cot
// Cot enums
enum TokenKind: u8 {
    eof
    identifier
    int_literal
    kw_fn
    kw_return
}

// Cot unions
union Value {
    integer: i64
    float: f64
    string: string
    boolean: bool
    none
}

// Switch with capture
switch value {
    .integer |i| => println(i)
    .float |f| => println(f)
    .none => println("none")
}
```

---

## 9. Pointers

### Basic Pointers

```zig
var x: u32 = 42;
const ptr: *u32 = &x;  // Pointer to x

// Dereference
const value = ptr.*;  // 42

// Modify through pointer
ptr.* = 100;  // x is now 100
```

### Const vs Mutable Pointers

```zig
const x: u32 = 42;
const ptr: *const u32 = &x;  // Can't modify through this pointer

var y: u32 = 42;
const mut_ptr: *u32 = &y;  // Can modify through this
mut_ptr.* = 100;
```

### Pointer to Many (`[*]T`)

```zig
// Pointer to single item
var single: *u32 = &value;

// Pointer to unknown number of items (like C pointer)
var many: [*]u32 = array.ptr;
```

### Optional Pointers

```zig
var ptr: ?*u32 = null;  // Can be null

ptr = &some_value;  // Now points to something

if (ptr) |p| {
    // p is guaranteed non-null here
    std.debug.print("{}\n", .{p.*});
}
```

### Cot Comparison

```cot
// Cot pointers work similarly
var x: u32 = 42
var ptr: *u32 = &x

// Dereference
var value = ptr.*

// Optional pointer
var maybe_ptr: ?*u32 = null
```

---

## 10. Control Flow

### If Statements

```zig
if (condition) {
    // ...
} else if (other_condition) {
    // ...
} else {
    // ...
}

// If with optional capture
if (optional_value) |value| {
    // value is unwrapped here
}

// If with error capture
if (fallible_call()) |result| {
    // success
} else |err| {
    // handle error
}
```

### While Loops

```zig
while (condition) {
    // ...
}

// With else (runs if never entered or condition false)
while (condition) {
    // ...
} else {
    // runs after loop (if no break)
}

// With capture (like iterators)
while (iter.next()) |item| {
    // process item
}
```

### For Loops

```zig
// Iterate over slice/array
for (items) |item| {
    std.debug.print("{}\n", .{item});
}

// With index
for (items, 0..) |item, i| {
    std.debug.print("{}: {}\n", .{i, item});
}
```

### Switch

```zig
const result = switch (value) {
    1 => "one",
    2, 3 => "two or three",
    4...10 => "four to ten",
    else => "other",
};
```

### Cot Comparison

```cot
// Cot for loops
for item in items {
    println(item)
}

// With index
for item, i in items {
    println("${i}: ${item}")
}

// Range
for i in 0..10 {
    println(i)
}
```

---

## 11. Comptime

`comptime` is Zig's compile-time execution. Code runs during compilation, not at runtime.

### Comptime Values

```zig
// This calculation happens at compile time
const x = comptime blk: {
    var sum: u32 = 0;
    for (0..10) |i| {
        sum += i;
    }
    break :blk sum;  // 45
};
// x is just 45 in the compiled program, no loop at runtime
```

### Generic Types

```zig
// ArrayList is generic - T is a comptime type parameter
fn ArrayList(comptime T: type) type {
    return struct {
        items: []T,
        capacity: usize,

        fn append(self: *@This(), item: T) !void {
            // ...
        }
    };
}

// Usage
var list = ArrayList(u32).init(allocator);
try list.append(42);
```

### @-Builtins

Zig has many `@` builtins for compile-time operations:

```zig
@intCast(i32, some_u64)      // Safe integer cast
@ptrCast(*T, some_ptr)       // Pointer cast
@sizeOf(MyStruct)            // Size in bytes
@alignOf(MyStruct)           // Alignment
@typeInfo(MyType)            // Type introspection
@typeName(MyType)            // "MyType" as string
@This()                      // Current struct type
```

### In Our Codebase

We use comptime for:
1. Generic containers (`ArrayList`, `HashMap`)
2. Compile-time lookups (keyword tables)
3. Conditional compilation (ARM64 vs x86_64)

```zig
// Example from scanner.zig
const keywords = std.ComptimeStringMap(Token.Kind, .{
    .{ "fn", .kw_fn },
    .{ "return", .kw_return },
    .{ "if", .kw_if },
    // ...
});

// Lookup is O(1) at runtime
const kind = keywords.get(text) orelse .identifier;
```

---

## 12. Common Patterns in Our Code

### The Init/Deinit Pattern

```zig
const Scanner = struct {
    allocator: Allocator,
    source: []const u8,
    pos: usize,

    pub fn init(allocator: Allocator, source: []const u8) Scanner {
        return Scanner{
            .allocator = allocator,
            .source = source,
            .pos = 0,
        };
    }

    pub fn deinit(self: *Scanner) void {
        // Free any allocated resources
    }
};

// Usage
var scanner = Scanner.init(allocator, source);
defer scanner.deinit();
```

### ArrayList Pattern (Zig 0.15)

```zig
// Zig 0.15 uses unmanaged ArrayList
var list: std.ArrayList(Token) = .{ .items = &.{}, .capacity = 0 };
defer list.deinit(allocator);

// Must pass allocator to each operation
try list.append(allocator, token);
```

### Writer Pattern

```zig
// Many functions accept a writer for output
fn emit(self: *Codegen, writer: anytype) !void {
    try writer.writeAll("Hello\n");
    try writer.print("Value: {}\n", .{42});
}

// Can write to file, buffer, stdout, etc.
var buffer = std.ArrayList(u8).init(allocator);
try emit(&codegen, buffer.writer());
```

### Error Union Chaining

```zig
fn compile(source: []const u8) ![]const u8 {
    const tokens = try scan(source);      // Fail early if scan fails
    const ast = try parse(tokens);        // Fail early if parse fails
    const ir = try lower(ast);            // Fail early if lower fails
    const code = try generate(ir);        // Fail early if codegen fails
    return code;
}
```

---

## Quick Reference Card

| Concept | Zig Syntax | Cot Equivalent |
|---------|------------|----------------|
| Optional type | `?T` | `?T` |
| Optional unwrap | `x orelse default` | `x ?? default` |
| Optional capture | `if (x) \|v\| {}` | `if x \|v\| {}` |
| Error return | `!T` | `Result<T, E>` |
| Try (propagate) | `try expr` | `expr?` |
| Slice | `[]T` | `[]T` |
| Pointer | `*T` | `*T` |
| String | `[]const u8` | `string` |
| Struct init | `.{ .x = 1 }` | `{ .x = 1 }` |
| Method call | `obj.method()` | `obj.method()` |
| Enum variant | `.variant` | `.variant` |
| Switch capture | `.foo => \|v\| {}` | `.foo \|v\| => {}` |

---

## Further Reading

- [Zig Language Reference](https://ziglang.org/documentation/master/)
- [Zig Learn](https://ziglearn.org/)
- Our code: Start with `src/scanner.zig` - it's the simplest module
