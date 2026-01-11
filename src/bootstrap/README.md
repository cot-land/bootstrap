# Bootstrap Files

This directory contains simplified versions of the compiler source files (`*_boot.cot`) that use only currently-supported language features.

## Process: Wireframe to Simplified

For each compiler component, follow this two-step process:

### Step 1: Verify Wireframe Matches Zig Implementation

Before simplifying, ensure the `.cot` wireframe file matches its `.zig` implementation:

```
src/token.cot  <-> src/token.zig
src/source.cot <-> src/source.zig
src/scanner.cot <-> src/scanner.zig
```

**Check for:**
- Missing tokens, keywords, operators
- Missing struct fields
- Missing methods/functions
- Logic differences

**Example differences found and fixed:**
- token.cot was missing: `string_interp_*`, `dot_question`, `fat_arrow`, `kw_enum`, `kw_union`, `kw_type`, `kw_switch`, `coalesce` precedence
- scanner.cot was missing: `in_interp_string`, `interp_brace_depth` fields, `scanStringContinuation` method, interpolation handling

### Step 2: Create Simplified Boot Version

Create `*_boot.cot` that:
1. Has the same logic as the wireframe
2. Uses only currently-supported features
3. Can actually compile with the cot compiler

## Currently Supported Features

Features that work in `*_boot.cot` files:

- Basic types: `int`, `bool`, `string`
- Enums with values: `enum Token: u8 { ... }`
- Structs with fields: `struct Pos { offset: int }`
- Functions with parameters and return types
- Variables: `var x: int = 0`
- If/else statements
- While loops
- Switch statements (basic)
- Boolean operators: `and`, `or`
- Comparisons: `==`, `!=`, `<`, `<=`, `>`, `>=`
- Arithmetic: `+`, `-`, `*`, `/`
- String indexing: `str[i]`
- String slicing: `str[start..end]`
- `len()` builtin
- `return` statements

## NOT Yet Supported

Features that require workarounds in `*_boot.cot`:

| Feature | Wireframe | Bootstrap Workaround |
|---------|-----------|---------------------|
| `import` statements | `import "token"` | Inline all definitions |
| Pointer types | `*Source` | Pass by value or use indices |
| Optional types | `?byte` | Use sentinel values (0) |
| Optional unwrap | `x.?` | Check and access directly |
| If/while with capture | `if x \|v\| {}` | Check then access |
| Methods in structs | `fn (self: T)` | Standalone functions |
| Map types | `Map<K,V>` | Chain of if statements |
| `@intFromEnum` | `@intFromEnum(x)` | Direct comparison |

## File Status

| Wireframe | Zig Match | Boot Version | Compiles |
|-----------|-----------|--------------|----------|
| token.cot | ✓ | token_boot.cot | Pending |
| source.cot | ✓ | source_boot.cot | Pending |
| scanner.cot | ✓ | scanner_boot.cot | Pending |

## Testing Boot Files

To test if a boot file compiles:

```bash
zig build && ./zig-out/bin/cot src/bootstrap/token_boot.cot -o /tmp/test
```

## Next Steps

1. Test each `*_boot.cot` file compiles
2. Add more compiler phases (parser, checker, etc.)
3. Implement missing language features to reduce workarounds
