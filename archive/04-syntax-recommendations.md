# Syntax Recommendations: Making Cot More Zig-Like

Based on comprehensive analysis of Go and Zig repositories, here are specific syntax recommendations to make Cot closer to Zig's elegance while maintaining Go's simplicity.

## Priority 1: Adopt Immediately

### 1.1 Struct Field Initialization Shorthand

**Current Cot:**
```cot
var p = Point{ .x = 10, .y = 20 }
```

**Already Zig-like!** Cot already uses `.field = value` syntax. No change needed.

### 1.2 Switch as Expression (Returns Value)

**Current Cot:** Switch is statement-only (based on SYNTAX.md)
```cot
switch (value) {
    1 => { result = "one" }
    2 => { result = "two" }
}
```

**Recommended (Zig-style):**
```cot
var result = switch (value) {
    1 => "one",
    2 => "two",
    else => "other",
}
```

**Benefits:**
- Eliminates temp variables
- More functional style
- Matches if-expression pattern already in Cot

**Implementation:** Parser already handles switch; add expression-return semantics in IR lowering.

### 1.3 For Loop with Multiple Iterables

**Current Cot:**
```cot
for i in 0..len(arr) {
    var item = arr[i]
    // use i and item
}
```

**Recommended (Zig-style):**
```cot
for arr, 0.. |item, i| {
    // both available directly
}
```

**Or simpler syntax:**
```cot
for item, i in arr {
    // item and index together
}
```

**Benefits:**
- No manual indexing
- Clearer intent
- Matches destructuring philosophy

### 1.4 Payload Capture in If/Switch

**Current Cot (SYNTAX.md shows):**
```cot
if (x != null) {
    // x is still optional, must access x.value or similar
}
```

**Recommended (Zig-style):**
```cot
if (x) |value| {
    // value is unwrapped, non-optional
} else {
    // x was null
}
```

**For optionals:**
```cot
if (maybeUser) |user| {
    println(user.name)
} else {
    println("No user")
}
```

**Benefits:**
- Eliminates null checks inside blocks
- Pattern matches on success/failure
- Cleaner than `x?.field ?? default`

**Implementation:** Add payload capture syntax to parser, propagate to IR lowering.

---

## Priority 2: Strong Recommendations

### 2.1 Error Union Type Syntax

**Current Cot:** Uses try/catch/throw (exception-style)
```cot
fn divide(a: i64, b: i64) i64 {
    if (b == 0) { throw "division by zero" }
    return a / b
}
```

**Recommended (Zig-style error unions):**
```cot
fn divide(a: i64, b: i64) MathError!i64 {
    if (b == 0) { return error.DivisionByZero }
    return a / b
}

// Caller:
const result = divide(10, 2) catch |err| {
    log("Failed: " + err)
    return 0
}
```

**Define error sets:**
```cot
const MathError = error {
    DivisionByZero,
    Overflow,
    Underflow,
}
```

**Benefits:**
- Errors are values, not control flow
- Type system tracks which errors can occur
- `try` keyword for propagation (already have this!)
- Can still support `throw` for truly exceptional cases

**Implementation:**
- Add `error` type constructor
- Add `!T` error union syntax
- Modify `catch` to work with error unions
- Keep `throw` for panic-like behavior

### 2.2 Explicit `errdefer` Keyword

**Current Cot:** Only has `defer`
```cot
fn process() {
    var file = openFile("data.txt")
    defer closeFile(file)
    // if error, file still closed
}
```

**Recommended (add errdefer):**
```cot
fn allocateAndProcess() !Result {
    var buffer = try allocate(1024)
    errdefer free(buffer)  // Only runs on error return

    try processData(buffer)  // If this fails, buffer freed

    return Result{ .data = buffer }  // Success: buffer NOT freed
}
```

**Benefits:**
- Cleanup only on error paths
- Prevents double-free bugs
- Clearer resource management intent

### 2.3 `comptime` Keyword Enhancement

**Current Cot (SYNTAX.md):**
```cot
comptime {
    // compile-time code
}

comptime if (@os() == "windows") {
    // conditional compilation
}
```

**Recommended additions:**

**Comptime parameters:**
```cot
fn makeArray(comptime T: type, comptime size: i64) [size]T {
    var arr: [size]T = undefined
    return arr
}
```

**Inline for (loop unrolling):**
```cot
inline for fields |field| {
    // Unrolled at compile time
    println(field.name)
}
```

**Benefits:**
- Generic programming without runtime cost
- Explicit performance expectations
- Type-level computation

### 2.4 Sentinel Values in Types

**Current Cot:** No sentinel syntax

**Recommended (Zig-style):**
```cot
// Null-terminated string
var s: [:0]u8 = "hello"

// Array with sentinel
var arr: [5:0]i64 = [1, 2, 3, 4, 5]
```

**Benefits:**
- C interop (null-terminated strings)
- Compiler-checked bounds
- Type encodes termination semantics

---

## Priority 3: Consider Adopting

### 3.1 Many-Pointer Syntax

**Zig has:** `*T` (single pointer), `[*]T` (many-pointer), `[*:0]T` (sentinel-terminated)

**Current Cot:** Only `*T`

**Recommended:**
```cot
var single: *i64 = &value        // Pointer to one item
var many: [*]i64 = buffer.ptr    // Pointer to unknown count
var cstr: [*:0]u8 = c_string     // C string
```

**Benefits:**
- Clearer intent for C interop
- Type system prevents single/many confusion
- Enables safer slice-from-pointer operations

### 3.2 Anonymous Struct Literals

**Current Cot:** Must name type
```cot
var p = Point{ .x = 10, .y = 20 }
```

**Recommended (Zig-style inference):**
```cot
fn getOrigin() Point {
    return .{ .x = 0, .y = 0 }  // Type inferred from return type
}
```

**Benefits:**
- Less repetition
- Cleaner function returns
- Matches existing Cot `.{}` initialization

### 3.3 Labeled Blocks with Break Values

**Zig pattern:**
```zig
const result = blk: {
    if (condition) break :blk value1;
    break :blk value2;
};
```

**Recommended for Cot:**
```cot
var result = calc: {
    if (x > 10) { break :calc "big" }
    break :calc "small"
}
```

**Benefits:**
- Complex expressions without temp variables
- Named break targets
- More flexible than ternary operator

### 3.4 `undefined` Value

**Zig:** `undefined` marks uninitialized memory explicitly
```zig
var x: i64 = undefined  // Explicitly garbage
```

**Recommended for Cot:**
```cot
var buffer: [1024]u8 = undefined  // Don't zero-initialize
```

**Benefits:**
- Performance (avoid unnecessary zeroing)
- Clear intent
- Debug checks can detect use of undefined

---

## Syntax to KEEP from Cot (Don't Change)

### Keep: `fn` keyword
Already matches Zig. Don't use Go's `func`.

### Keep: `.field = value` initialization
Already matches Zig. Perfect.

### Keep: `if (condition)` parentheses
More familiar than Zig's `if condition`. Keep for readability.

### Keep: `and`, `or`, `not` keywords
More readable than `&&`, `||`, `!`. This is a strength.

### Keep: `var` and `const`
Matches Zig. Clear mutability distinction.

### Keep: `impl Trait for Type`
Clear trait implementation syntax. Keep it.

### Keep: String concatenation with `+`
More intuitive than Zig's `++`. Keep for business developers.

---

## Syntax Comparison Table

| Feature | Go | Zig | Cot Now | Cot Recommended |
|---------|-----|-----|---------|-----------------|
| Function keyword | `func` | `fn` | `fn` | `fn` (keep) |
| Type after name | `x int` | `x: i64` | `x: i64` | `x: i64` (keep) |
| Struct init | `{field: v}` | `.{.field = v}` | `.{.field = v}` | `.{.field = v}` (keep) |
| If expression | No | Yes | Yes | Yes (keep) |
| Switch expression | No | Yes | No | **Yes (add)** |
| Payload capture | No | `\|value\|` | No | **Yes (add)** |
| Error unions | No | `!T` | No | **Yes (add)** |
| errdefer | No | Yes | No | **Yes (add)** |
| comptime params | No | Yes | Partial | **Enhance** |
| Sentinel types | No | `[:0]T` | No | **Consider** |
| Labeled blocks | No | Yes | No | Consider |
| undefined | No | Yes | No | Consider |

---

## Implementation Roadmap

### Phase 1: Low-Hanging Fruit (1-2 weeks)
1. Switch as expression
2. Payload capture in if (`if (x) |v| {}`)
3. Anonymous struct literals (`.{}` inference)

### Phase 2: Error Handling Revolution (2-4 weeks)
1. Error set definitions
2. Error union syntax (`!T`)
3. `errdefer` keyword
4. Modify `catch` for error unions

### Phase 3: Advanced Features (4-8 weeks)
1. Comptime parameters
2. Inline for
3. Sentinel types
4. Labeled blocks with values

### Phase 4: Polish (2-4 weeks)
1. Many-pointer syntax (for C interop)
2. `undefined` value
3. Documentation updates
4. Migration guides
