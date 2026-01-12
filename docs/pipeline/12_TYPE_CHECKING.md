# Stage 3: Type Checking (Semantic Analysis)

**Files:** `src/check.zig`, `src/types.zig`

**Purpose:** Verify that the code makes sense

---

## What is Type Checking?

The parser built a tree showing structure, but it didn't check if the code makes logical sense. Consider:

```cot
fn broken() i64 {
    return "hello"  // Error: returning string from int function!
}
```

The parser happily builds an AST - the syntax is valid. But it's nonsense: you can't return a string when the function promises to return an integer.

Type checking catches these logical errors by:
1. **Resolving names** - When you write `x`, find what `x` refers to
2. **Computing types** - Figure out what type each expression has
3. **Checking compatibility** - Verify types are used correctly

---

## Symbols and Scopes

A **symbol** represents something that has a name: a variable, function, type, etc.

```zig
pub const Symbol = struct {
    name: []const u8,      // The name: "x", "main", "Point"
    kind: SymbolKind,      // What kind: variable, function, type, etc.
    type_idx: TypeIndex,   // The type: i64, fn(i64, i64) -> i64, etc.
    node: NodeIndex,       // Where in the AST it was declared
    mutable: bool,         // Can it be assigned to? (var vs const)
};

pub const SymbolKind = enum {
    variable,    // var x: i64
    constant,    // const y: i64
    function,    // fn foo() {}
    type_name,   // struct Point, enum Color
    parameter,   // function parameter
};
```

A **scope** is a container for symbols. Scopes nest:

```cot
fn outer() {              // <- outer function scope
    var x: i64 = 1

    if condition {        // <- nested block scope
        var y: i64 = 2
        x = x + y        // Can see x from outer scope
    }
    // y is not visible here
}
```

```zig
pub const Scope = struct {
    parent: ?*Scope,                    // Enclosing scope
    symbols: std.StringHashMap(Symbol), // Name -> Symbol
    allocator: std.mem.Allocator,

    /// Look up a symbol in this scope or any parent scope.
    pub fn lookup(self: *const Scope, name: []const u8) ?Symbol {
        if (self.symbols.get(name)) |sym| {
            return sym;  // Found in this scope
        }
        if (self.parent) |p| {
            return p.lookup(name);  // Try parent scope
        }
        return null;  // Not found anywhere
    }
};
```

The lookup walks up the scope chain:

```
lookup("x"):
  inner scope: not found
  └── outer scope: not found
      └── global scope: found! Return x
```

---

## The Type Registry

Types are stored in a **registry** that assigns each unique type an index:

```zig
pub const TypeRegistry = struct {
    types: ArrayList(Type),  // Array of all types
};

// Pre-allocated indices for basic types
pub const BOOL: TypeIndex = 1;
pub const I8: TypeIndex = 2;
pub const I16: TypeIndex = 3;
pub const I32: TypeIndex = 4;
pub const I64: TypeIndex = 5;
pub const U8: TypeIndex = 6;
// ... more basic types

// Aliases
pub const INT: TypeIndex = I64;   // int = i64
pub const FLOAT: TypeIndex = F64; // float = f64
```

This allows comparing types by index (fast integer comparison) rather than comparing entire type structures.

---

## The Type Union

Types can be basic (like `i64`) or compound (like `[]i64`, `*Point`):

```zig
pub union Type {
    basic: BasicKind,         // i64, bool, string, etc.
    pointer: PointerType,     // *T
    optional: OptionalType,   // ?T
    slice: SliceType,         // []T
    array: ArrayType,         // [N]T
    struct_type: StructType,  // struct { fields }
    enum_type: EnumType,      // enum { variants }
    union_type: UnionType,    // union { variants }
    func: FuncType,           // fn(params) -> return_type
    named: NamedType,         // type alias
}
```

Each compound type stores its component types as indices:

```zig
pub struct SliceType {
    elem: TypeIndex,  // The element type (e.g., u8 for []u8)
}

pub struct FuncType {
    params: []FuncParam,      // Parameter types
    return_type: TypeIndex,   // Return type
}
```

---

## The Checker

The checker holds state during type checking:

```zig
pub const Checker = struct {
    types: *TypeRegistry,        // Type registry
    scope: *Scope,               // Current scope
    err: *ErrorReporter,         // Error reporter
    tree: *const Ast,            // AST being checked
    allocator: std.mem.Allocator,

    // Cache: expression node -> type
    expr_types: std.AutoHashMap(NodeIndex, TypeIndex),

    // Current function's return type (for checking return statements)
    current_return_type: TypeIndex,

    // Are we inside a loop? (for validating break/continue)
    in_loop: bool,

    // Method registry: type name -> methods
    method_registry: std.StringHashMap(std.ArrayList(MethodInfo)),
};
```

---

## Two-Pass Checking

Type checking happens in two passes:

### Pass 1: Collect Declarations

First, we register all top-level names without checking bodies:

```zig
pub fn checkFile(self: *Checker) CheckError!void {
    const file = self.tree.file orelse return;

    // First pass: collect all top-level declarations
    for (file.decls) |decl_idx| {
        try self.collectDecl(decl_idx);
    }

    // Second pass: check all declarations
    for (file.decls) |decl_idx| {
        try self.checkDecl(decl_idx);
    }
}
```

Why two passes? Consider:

```cot
fn foo() {
    bar()  // bar isn't defined yet!
}

fn bar() {
    // ...
}
```

If we checked `foo` before seeing `bar`, we'd report an error. The first pass collects all function names, so the second pass can resolve them.

### Pass 2: Check Bodies

Now we check function bodies, verifying types are correct:

```zig
fn checkFnDecl(self: *Checker, f: ast.FnDecl, idx: NodeIndex) CheckError!void {
    // Get the function's type
    const sym = self.scope.lookup(f.name) orelse return;
    const func_type = self.types.get(sym.type_idx);
    const return_type = switch (func_type) {
        .func => |ft| ft.return_type,
        else => TypeRegistry.VOID,
    };

    // Create new scope for function body
    var func_scope = Scope.init(self.allocator, self.scope);
    defer func_scope.deinit();

    // Add parameters to function scope
    for (f.params) |param| {
        const param_type = try self.resolveTypeExpr(param.type_expr);
        try func_scope.define(Symbol.init(
            param.name,
            .parameter,
            param_type,
            idx,
            false,  // parameters are immutable
        ));
    }

    // Save and set state
    const old_scope = self.scope;
    const old_return = self.current_return_type;
    self.scope = &func_scope;
    self.current_return_type = return_type;

    // Check function body
    if (f.body) |body_idx| {
        try self.checkBlockExpr(body_idx);
    }

    // Restore state
    self.scope = old_scope;
    self.current_return_type = old_return;
}
```

---

## Checking Expressions

Each expression type has a type. The checker computes it:

```zig
pub fn checkExpr(self: *Checker, idx: NodeIndex) CheckError!TypeIndex {
    // Check cache first
    if (self.expr_types.get(idx)) |t| {
        return t;
    }

    const result = try self.checkExprInner(idx);
    try self.expr_types.put(idx, result);
    return result;
}

fn checkExprInner(self: *Checker, idx: NodeIndex) CheckError!TypeIndex {
    const expr = self.tree.getExpr(idx) orelse return invalid_type;

    return switch (expr) {
        .identifier => |id| self.checkIdentifier(id),
        .literal => |lit| try self.checkLiteral(lit),
        .binary => |bin| try self.checkBinary(bin),
        .unary => |un| try self.checkUnary(un),
        .call => |c| try self.checkCall(c),
        .index => |i| try self.checkIndex(i),
        .field_access => |f| try self.checkFieldAccess(f),
        .array_literal => |al| try self.checkArrayLiteral(al),
        .if_expr => |ie| try self.checkIfExpr(ie),
        .switch_expr => |se| try self.checkSwitchExpr(se),
        .struct_init => |si| try self.checkStructInit(si),
        // ... more cases
    };
}
```

### Literals

```zig
fn checkLiteral(self: *Checker, lit: ast.Literal) CheckError!TypeIndex {
    return switch (lit.kind) {
        .int => TypeRegistry.UNTYPED_INT,    // Can be any integer type
        .float => TypeRegistry.UNTYPED_FLOAT, // Can be any float type
        .string => TypeRegistry.STRING,       // []u8
        .char => TypeRegistry.U8,             // char is u8
        .true_lit, .false_lit => TypeRegistry.UNTYPED_BOOL,
        .null_lit => invalid_type,            // null needs context
    };
}
```

**Untyped literals** can be assigned to any compatible type:

```cot
var a: i8 = 42   // 42 becomes i8
var b: i64 = 42  // 42 becomes i64
var c: f64 = 42  // 42 becomes f64 (42.0)
```

### Identifiers

```zig
fn checkIdentifier(self: *Checker, id: ast.Identifier) TypeIndex {
    if (self.scope.lookup(id.name)) |sym| {
        return sym.type_idx;
    }
    self.errUndefined(id.span.start, id.name);
    return invalid_type;
}
```

### Binary Operators

```zig
fn checkBinary(self: *Checker, bin: ast.Binary) CheckError!TypeIndex {
    const left_type = try self.checkExpr(bin.left);
    const right_type = try self.checkExpr(bin.right);

    const left = self.types.get(left_type);
    const right = self.types.get(right_type);

    switch (bin.op) {
        // Arithmetic: both must be numeric
        .plus, .minus, .star, .slash, .percent => {
            if (!isNumeric(left) or !isNumeric(right)) {
                self.errInvalidOp(bin.span.start, "arithmetic", left_type, right_type);
                return invalid_type;
            }
            return left_type;  // Result has same type as operands
        },

        // Comparison: result is always bool
        .equal_equal, .bang_equal, .less, .greater, ... => {
            if (!self.isComparable(left_type, right_type)) {
                self.errInvalidOp(bin.span.start, "comparison", left_type, right_type);
                return invalid_type;
            }
            return TypeRegistry.BOOL;
        },

        // Logical: both must be bool
        .kw_and, .kw_or => {
            if (!isBool(left) or !isBool(right)) {
                self.errInvalidOp(bin.span.start, "logical", left_type, right_type);
                return invalid_type;
            }
            return TypeRegistry.BOOL;
        },

        // Null coalescing: a ?? b
        .question_question => {
            // If a is optional ?T, return T
            if (left == .optional) {
                return left.optional.elem;
            }
            return left_type;
        },

        else => return invalid_type,
    }
}
```

### Function Calls

```zig
fn checkCall(self: *Checker, c: ast.Call) CheckError!TypeIndex {
    // Check for builtins first
    if (self.tree.getExpr(c.callee)) |callee_expr| {
        if (callee_expr == .identifier) {
            const name = callee_expr.identifier.name;
            if (std.mem.eql(u8, name, "len")) {
                return self.checkBuiltinLen(c);
            }
            if (std.mem.eql(u8, name, "print")) {
                return self.checkBuiltinPrint(c);
            }
        }
    }

    const callee_type = try self.checkExpr(c.callee);
    const callee = self.types.get(callee_type);

    switch (callee) {
        .func => |ft| {
            // Check argument count
            if (c.args.len != ft.params.len) {
                self.err.errorWithCode(c.span.start, .E300, "wrong number of arguments");
                return invalid_type;
            }

            // Check argument types
            for (c.args, 0..) |arg_idx, i| {
                const arg_type = try self.checkExpr(arg_idx);
                const param_type = ft.params[i].type_idx;
                if (!self.isAssignable(arg_type, param_type)) {
                    self.errTypeMismatch(c.span.start, param_type, arg_type);
                }
            }

            return ft.return_type;
        },
        else => {
            self.err.errorWithCode(c.span.start, .E303, "cannot call non-function");
            return invalid_type;
        },
    }
}
```

### Field Access

```zig
fn checkFieldAccess(self: *Checker, f: ast.FieldAccess) CheckError!TypeIndex {
    const base_type = try self.checkExpr(f.base);
    const base = self.types.get(base_type);

    switch (base) {
        .struct_type => |st| {
            // Look for field with this name
            for (st.fields) |field| {
                if (std.mem.eql(u8, field.name, f.field)) {
                    return field.type_idx;
                }
            }
            // Not a field - check for methods
            if (self.lookupMethod(st.name, f.field)) |method| {
                return method.func_type;
            }
            self.errUndefined(f.span.start, f.field);
            return invalid_type;
        },
        .enum_type => |et| {
            // Enum variant access: Color.red
            for (et.variants) |variant| {
                if (std.mem.eql(u8, variant.name, f.field)) {
                    return base_type;  // Variant has enum type
                }
            }
            self.errUndefined(f.span.start, f.field);
            return invalid_type;
        },
        .pointer => |ptr| {
            // Auto-deref for field access: p.x on *Point
            const elem = self.types.get(ptr.elem);
            // ... check elem is struct ...
        },
        else => {
            self.err.errorWithCode(f.span.start, .E303, "cannot access field on this type");
            return invalid_type;
        },
    }
}
```

---

## Checking Statements

Statements don't have types but must be checked:

```zig
fn checkStmt(self: *Checker, idx: NodeIndex) CheckError!void {
    const stmt = self.tree.getStmt(idx) orelse return;

    switch (stmt) {
        .return_stmt => |rs| try self.checkReturn(rs),
        .var_stmt => |vs| try self.checkVarStmt(vs, idx),
        .assign_stmt => |as| try self.checkAssign(as),
        .if_stmt => |is| try self.checkIfStmt(is),
        .while_stmt => |ws| try self.checkWhileStmt(ws),
        .for_stmt => |fs| try self.checkForStmt(fs),
        .break_stmt => |bs| {
            if (!self.in_loop) {
                self.err.errorWithCode(bs.span.start, .E303, "break outside of loop");
            }
        },
        .continue_stmt => |cs| {
            if (!self.in_loop) {
                self.err.errorWithCode(cs.span.start, .E303, "continue outside of loop");
            }
        },
        // ... more cases
    }
}
```

### Return Statement

```zig
fn checkReturn(self: *Checker, rs: ast.ReturnStmt) CheckError!void {
    if (rs.value) |val_idx| {
        const val_type = try self.checkExpr(val_idx);

        // Void function shouldn't return a value
        if (self.current_return_type == TypeRegistry.VOID) {
            self.err.errorWithCode(rs.span.start, .E300, "void function should not return a value");
        } else if (!self.isAssignable(val_type, self.current_return_type)) {
            self.errTypeMismatch(rs.span.start, self.current_return_type, val_type);
        }
    } else {
        // No return value - must be void function
        if (self.current_return_type != TypeRegistry.VOID) {
            self.err.errorWithCode(rs.span.start, .E300, "non-void function must return a value");
        }
    }
}
```

### Variable Declaration

```zig
fn checkVarStmt(self: *Checker, vs: ast.VarStmt, idx: NodeIndex) CheckError!void {
    // Check for redefinition
    if (self.scope.isDefined(vs.name)) {
        self.errRedefined(vs.span.start, vs.name);
        return;
    }

    var var_type: TypeIndex = invalid_type;

    // Explicit type annotation?
    if (vs.type_expr) |type_idx| {
        var_type = try self.resolveTypeExpr(type_idx);
    }

    // Initializer?
    if (vs.value) |val_idx| {
        const val_type = try self.checkExpr(val_idx);

        if (var_type == invalid_type) {
            // Infer type from initializer
            var_type = self.materializeType(val_type);
        } else if (!self.isAssignable(val_type, var_type)) {
            // Check initializer matches declared type
            self.errTypeMismatch(vs.span.start, var_type, val_type);
        }
    }

    // Add to current scope
    try self.scope.define(Symbol.init(
        vs.name,
        if (vs.is_const) .constant else .variable,
        var_type,
        idx,
        !vs.is_const,
    ));
}
```

### Assignment

```zig
fn checkAssign(self: *Checker, as: ast.AssignStmt) CheckError!void {
    const target_type = try self.checkExpr(as.target);
    const value_type = try self.checkExpr(as.value);

    // Check target is assignable (lvalue)
    const target = self.tree.getExpr(as.target) orelse return;
    switch (target) {
        .identifier => |id| {
            if (self.scope.lookup(id.name)) |sym| {
                if (!sym.mutable) {
                    self.err.errorWithCode(as.span.start, .E303, "cannot assign to constant");
                    return;
                }
            }
        },
        .index, .field_access => {},  // Valid lvalues
        else => {
            self.err.errorWithCode(as.span.start, .E303, "invalid assignment target");
            return;
        },
    }

    // Check type compatibility
    if (!self.isAssignable(value_type, target_type)) {
        self.errTypeMismatch(as.span.start, target_type, value_type);
    }
}
```

---

## Type Resolution

When you write `var x: []i64`, the parser creates type expression nodes. The checker resolves them to actual types:

```zig
fn resolveType(self: *Checker, te: TypeExpr) CheckError!TypeIndex {
    return switch (te.kind) {
        .named => |name| {
            // Built-in types first
            if (self.types.lookupBasic(name)) |idx| {
                return idx;
            }
            // User-defined types
            if (self.scope.lookup(name)) |sym| {
                if (sym.kind == .type_name) {
                    return sym.type_idx;
                }
            }
            self.errUndefined(te.span.start, name);
            return invalid_type;
        },
        .pointer => |elem_idx| {
            const elem = try self.resolveTypeExpr(elem_idx);
            return try self.types.makePointer(elem);
        },
        .optional => |elem_idx| {
            const elem = try self.resolveTypeExpr(elem_idx);
            return try self.types.makeOptional(elem);
        },
        .slice => |elem_idx| {
            const elem = try self.resolveTypeExpr(elem_idx);
            return try self.types.makeSlice(elem);
        },
        .array => |a| {
            const elem = try self.resolveTypeExpr(a.elem);
            // Note: size evaluation would need constant folding
            return try self.types.makeArray(elem, 0);
        },
        .map => |m| {
            const key = try self.resolveTypeExpr(m.key);
            const value = try self.resolveTypeExpr(m.value);
            return try self.types.makeMap(key, value);
        },
        .list => |elem_idx| {
            const elem = try self.resolveTypeExpr(elem_idx);
            return try self.types.makeList(elem);
        },
    };
}
```

---

## Type Compatibility

### isAssignable

Can a value of type `from` be assigned to type `to`?

```zig
fn isAssignable(self: *Checker, from: TypeIndex, to: TypeIndex) bool {
    // Same type - always OK
    if (self.types.equal(from, to)) return true;

    var tf = self.types.get(from);
    var tt = self.types.get(to);

    // Handle untyped -> typed conversions
    return switch (tf) {
        .basic => |kf| switch (tt) {
            .basic => |kt| {
                // Untyped int can become any integer
                if (kf == .untyped_int and kt.isInteger()) return true;
                // Untyped float can become any float
                if (kf == .untyped_float and kt.isFloat()) return true;
                // Untyped bool can become bool
                if (kf == .untyped_bool and kt == .bool_type) return true;
                return false;
            },
            .optional => true,  // null assignable to any optional
            else => false,
        },
        else => false,
    };
}
```

### isComparable

Can two values be compared with `==` or `<`?

```zig
fn isComparable(self: *Checker, a: TypeIndex, b: TypeIndex) bool {
    // Same types are comparable
    if (self.types.equal(a, b)) return true;

    // Numeric types are comparable to each other
    const ta = self.types.get(a);
    const tb = self.types.get(b);
    if (isNumeric(ta) and isNumeric(tb)) return true;

    // Byte slices (strings) are comparable
    if (isByteSlice(ta) and isByteSlice(tb)) return true;

    return false;
}
```

### materializeType

Convert untyped to a concrete type:

```zig
fn materializeType(self: *Checker, idx: TypeIndex) TypeIndex {
    const t = self.types.get(idx);
    return switch (t) {
        .basic => |k| switch (k) {
            .untyped_int => TypeRegistry.INT,    // becomes i64
            .untyped_float => TypeRegistry.FLOAT, // becomes f64
            .untyped_bool => TypeRegistry.BOOL,
            else => idx,
        },
        else => idx,
    };
}
```

---

## Building Complex Types

When we see a struct declaration, we build its type:

```zig
fn buildStructType(self: *Checker, name: []const u8, fields: []const ast.Field) CheckError!TypeIndex {
    var struct_fields = ArrayList(types.StructField){ ... };

    var offset: u32 = 0;
    for (fields) |field| {
        const field_type = try self.resolveTypeExpr(field.type_expr);
        const field_size = self.typeSize(field_type);

        try struct_fields.append(.{
            .name = field.name,
            .type_idx = field_type,
            .offset = offset,   // For codegen: where in memory
        });
        offset += field_size;
    }

    return try self.types.add(.{ .struct_type = .{
        .name = name,
        .fields = struct_fields.items,
        .size = offset,
        .alignment = 8,
    } });
}
```

---

## Error Messages

The checker reports errors with location information:

```zig
fn errUndefined(self: *Checker, pos: Pos, name: []const u8) void {
    self.err.errorWithCode(pos, .E301, "undefined variable");
}

fn errRedefined(self: *Checker, pos: Pos, name: []const u8) void {
    self.err.errorWithCode(pos, .E302, "redefined identifier");
}

fn errTypeMismatch(self: *Checker, pos: Pos, expected: TypeIndex, got: TypeIndex) void {
    self.err.errorWithCode(pos, .E300, "type mismatch");
}
```

Error output:
```
test.cot:5:12: error E301: undefined variable
    return x
           ^
```

---

## Complete Example

Let's trace type checking for:

```cot
fn add(a: i64, b: i64) i64 {
    return a + b
}
```

### Pass 1: Collect

```
1. collectDecl(fn_decl "add")
2. Build function type:
   - param "a": resolve "i64" -> TypeIndex 5 (I64)
   - param "b": resolve "i64" -> TypeIndex 5 (I64)
   - return: resolve "i64" -> TypeIndex 5 (I64)
   - Create: fn(i64, i64) -> i64 at TypeIndex 14
3. Define symbol: add -> function, type 14
```

### Pass 2: Check Body

```
1. checkFnDecl:
   - Lookup "add" -> Symbol { type: 14 }
   - Get function type -> FuncType { params: [a:5, b:5], return: 5 }

2. Create function scope, add parameters:
   - a -> variable, type 5 (i64)
   - b -> variable, type 5 (i64)

3. Set current_return_type = 5 (i64)

4. Check body (block):
   - Check statement: return a + b

5. checkReturn:
   - Check expr: a + b

6. checkBinary(+):
   - Check left: identifier "a"
   - checkIdentifier: lookup("a") -> type 5 (i64)
   - Check right: identifier "b"
   - checkIdentifier: lookup("b") -> type 5 (i64)
   - Both numeric? Yes (i64 is numeric)
   - Result type: 5 (i64)

7. Return value type: 5 (i64)
   - current_return_type: 5 (i64)
   - isAssignable(5, 5)? Yes!
   - No error
```

Result: Type checking passes, no errors.

---

## Key Takeaways

1. **Scopes track what names are visible** and walk up the parent chain.

2. **Types are interned** with indices for efficient comparison.

3. **Two-pass checking** allows forward references (call a function defined later).

4. **Untyped literals** get concrete types based on context.

5. **Every expression has a type** - the checker computes it.

6. **Statements are checked** for correctness but don't have types.

---

## Next Steps

Now that we've verified the code is correct, we need to transform it into a simpler form for code generation. The next stage, **IR lowering**, converts the AST into basic operations.

See: [13_IR_LOWERING.md](13_IR_LOWERING.md)
