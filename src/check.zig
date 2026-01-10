///! Type checker for cot.
///!
///! Maps to Go's cmd/compile/internal/types2/
///! - checker.go (Checker struct, main entry points)
///! - resolver.go (name resolution)
///! - decl.go (declaration checking)
///! - expr.go (expression type checking)
///! - stmt.go (statement checking)

const std = @import("std");
const ast = @import("ast.zig");
const types = @import("types.zig");
const errors = @import("errors.zig");
const source = @import("source.zig");

const Ast = ast.Ast;
const NodeIndex = ast.NodeIndex;
const null_node = ast.null_node;
const Expr = ast.Expr;
const Stmt = ast.Stmt;
const Decl = ast.Decl;
const TypeExpr = ast.TypeExpr;
const LiteralKind = ast.LiteralKind;

const Type = types.Type;
const TypeIndex = types.TypeIndex;
const TypeRegistry = types.TypeRegistry;
const BasicKind = types.BasicKind;
const invalid_type = types.invalid_type;

const ErrorReporter = errors.ErrorReporter;
const ErrorCode = errors.ErrorCode;
const Pos = source.Pos;
const Span = source.Span;

// ============================================================================
// Check Error
// ============================================================================

pub const CheckError = error{OutOfMemory};

// ============================================================================
// Symbol
// ============================================================================

/// What kind of symbol this is.
pub const SymbolKind = enum {
    variable,
    constant,
    function,
    type_name,
    parameter,
};

/// A symbol in a scope (variable, function, type, etc.)
pub const Symbol = struct {
    name: []const u8,
    kind: SymbolKind,
    type_idx: TypeIndex,
    /// AST node index (for functions, structs, etc.)
    node: NodeIndex,
    /// Is this symbol mutable? (var vs const)
    mutable: bool,

    pub fn init(name: []const u8, kind: SymbolKind, type_idx: TypeIndex, node: NodeIndex, mutable: bool) Symbol {
        return .{
            .name = name,
            .kind = kind,
            .type_idx = type_idx,
            .node = node,
            .mutable = mutable,
        };
    }
};

// ============================================================================
// Scope
// ============================================================================

/// Lexical scope for name resolution.
/// Scopes form a tree with parent pointers.
pub const Scope = struct {
    parent: ?*Scope,
    symbols: std.StringHashMap(Symbol),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, parent: ?*Scope) Scope {
        return .{
            .parent = parent,
            .symbols = std.StringHashMap(Symbol).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Scope) void {
        self.symbols.deinit();
    }

    /// Define a symbol in this scope.
    pub fn define(self: *Scope, sym: Symbol) !void {
        try self.symbols.put(sym.name, sym);
    }

    /// Look up a symbol in this scope only.
    pub fn lookupLocal(self: *const Scope, name: []const u8) ?Symbol {
        return self.symbols.get(name);
    }

    /// Look up a symbol in this scope or any parent scope.
    pub fn lookup(self: *const Scope, name: []const u8) ?Symbol {
        if (self.symbols.get(name)) |sym| {
            return sym;
        }
        if (self.parent) |p| {
            return p.lookup(name);
        }
        return null;
    }

    /// Check if a name is already defined in this scope (not parent).
    pub fn isDefined(self: *const Scope, name: []const u8) bool {
        return self.symbols.contains(name);
    }
};

// ============================================================================
// Checker
// ============================================================================

/// Type checker state.
pub const Checker = struct {
    /// Type registry for type interning and lookup.
    types: *TypeRegistry,
    /// Current scope.
    scope: *Scope,
    /// Error reporter.
    err: *ErrorReporter,
    /// AST being checked.
    tree: *const Ast,
    /// Memory allocator.
    allocator: std.mem.Allocator,
    /// Expression type cache: NodeIndex -> TypeIndex
    expr_types: std.AutoHashMap(NodeIndex, TypeIndex),
    /// Current function return type (for checking return statements).
    current_return_type: TypeIndex,
    /// Are we inside a loop? (for break/continue)
    in_loop: bool,

    pub fn init(
        allocator: std.mem.Allocator,
        tree: *const Ast,
        type_reg: *TypeRegistry,
        reporter: *ErrorReporter,
        global_scope: *Scope,
    ) Checker {
        return .{
            .types = type_reg,
            .scope = global_scope,
            .err = reporter,
            .tree = tree,
            .allocator = allocator,
            .expr_types = std.AutoHashMap(NodeIndex, TypeIndex).init(allocator),
            .current_return_type = TypeRegistry.VOID,
            .in_loop = false,
        };
    }

    pub fn deinit(self: *Checker) void {
        self.expr_types.deinit();
    }

    // ========================================================================
    // File checking
    // ========================================================================

    /// Type check an entire file.
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

    /// Collect a declaration (add to scope without checking body).
    fn collectDecl(self: *Checker, idx: NodeIndex) CheckError!void {
        const decl = self.tree.getDecl(idx) orelse return;

        switch (decl) {
            .fn_decl => |f| {
                if (self.scope.isDefined(f.name)) {
                    self.errRedefined(f.span.start, f.name);
                    return;
                }
                // Build function type
                const func_type = try self.buildFuncType(f.params, f.return_type);
                try self.scope.define(Symbol.init(
                    f.name,
                    .function,
                    func_type,
                    idx,
                    false,
                ));
            },
            .var_decl => |v| {
                if (self.scope.isDefined(v.name)) {
                    self.errRedefined(v.span.start, v.name);
                    return;
                }
                // Type will be determined in checkDecl
                try self.scope.define(Symbol.init(
                    v.name,
                    .variable,
                    invalid_type,
                    idx,
                    true,
                ));
            },
            .const_decl => |c| {
                if (self.scope.isDefined(c.name)) {
                    self.errRedefined(c.span.start, c.name);
                    return;
                }
                try self.scope.define(Symbol.init(
                    c.name,
                    .constant,
                    invalid_type,
                    idx,
                    false,
                ));
            },
            .struct_decl => |s| {
                if (self.scope.isDefined(s.name)) {
                    self.errRedefined(s.span.start, s.name);
                    return;
                }
                // Build struct type
                const struct_type = try self.buildStructType(s.name, s.fields);
                try self.scope.define(Symbol.init(
                    s.name,
                    .type_name,
                    struct_type,
                    idx,
                    false,
                ));
            },
            .enum_decl => |e| {
                if (self.scope.isDefined(e.name)) {
                    self.errRedefined(e.span.start, e.name);
                    return;
                }
                // Build enum type
                const enum_type = try self.buildEnumType(e);
                try self.scope.define(Symbol.init(
                    e.name,
                    .type_name,
                    enum_type,
                    idx,
                    false,
                ));
            },
            .union_decl => |u| {
                if (self.scope.isDefined(u.name)) {
                    self.errRedefined(u.span.start, u.name);
                    return;
                }
                // Build union type
                const union_type = try self.buildUnionType(u);
                try self.scope.define(Symbol.init(
                    u.name,
                    .type_name,
                    union_type,
                    idx,
                    false,
                ));
            },
            .bad_decl => {},
        }
    }

    // ========================================================================
    // Declaration checking
    // ========================================================================

    /// Check a declaration.
    fn checkDecl(self: *Checker, idx: NodeIndex) CheckError!void {
        const decl = self.tree.getDecl(idx) orelse return;

        switch (decl) {
            .fn_decl => |f| try self.checkFnDecl(f, idx),
            .var_decl => |v| try self.checkVarDecl(v, idx),
            .const_decl => |c| try self.checkConstDecl(c, idx),
            .struct_decl => {}, // Already processed in collectDecl
            .enum_decl => {}, // Already processed in collectDecl
            .union_decl => {}, // Already processed in collectDecl
            .bad_decl => {},
        }
    }

    /// Check function declaration.
    fn checkFnDecl(self: *Checker, f: ast.FnDecl, idx: NodeIndex) CheckError!void {
        // Get the function type we built earlier
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
                false, // parameters are immutable by default
            ));
        }

        // Save state
        const old_scope = self.scope;
        const old_return = self.current_return_type;

        // Set up for function body
        self.scope = &func_scope;
        self.current_return_type = return_type;

        // Check body if present
        if (f.body) |body_idx| {
            try self.checkBlockExpr(body_idx);
        }

        // Restore state
        self.scope = old_scope;
        self.current_return_type = old_return;
    }

    /// Check variable declaration.
    fn checkVarDecl(self: *Checker, v: ast.VarDecl, idx: NodeIndex) CheckError!void {
        var var_type: TypeIndex = invalid_type;

        // Get explicit type if present
        if (v.type_expr) |type_idx| {
            var_type = try self.resolveTypeExpr(type_idx);
        }

        // Check initializer if present
        if (v.value) |val_idx| {
            const val_type = try self.checkExpr(val_idx);

            if (var_type == invalid_type) {
                // Infer type from initializer
                var_type = self.materializeType(val_type);
            } else {
                // Check that value is assignable to declared type
                if (!self.isAssignable(val_type, var_type)) {
                    self.errTypeMismatch(v.span.start, var_type, val_type);
                }
            }
        }

        // Update symbol with resolved type
        if (self.scope.lookupLocal(v.name)) |_| {
            try self.scope.define(Symbol.init(
                v.name,
                .variable,
                var_type,
                idx,
                true,
            ));
        }
    }

    /// Check const declaration.
    fn checkConstDecl(self: *Checker, c: ast.ConstDecl, idx: NodeIndex) CheckError!void {
        var const_type: TypeIndex = invalid_type;

        // Get explicit type if present
        if (c.type_expr) |type_idx| {
            const_type = try self.resolveTypeExpr(type_idx);
        }

        // Check initializer (required for const)
        const val_type = try self.checkExpr(c.value);

        if (const_type == invalid_type) {
            const_type = self.materializeType(val_type);
        } else {
            if (!self.isAssignable(val_type, const_type)) {
                self.errTypeMismatch(c.span.start, const_type, val_type);
            }
        }

        // Update symbol with resolved type
        if (self.scope.lookupLocal(c.name)) |_| {
            try self.scope.define(Symbol.init(
                c.name,
                .constant,
                const_type,
                idx,
                false,
            ));
        }
    }

    // ========================================================================
    // Expression checking
    // ========================================================================

    /// Check an expression and return its type.
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
            .literal => |lit| self.checkLiteral(lit),
            .binary => |bin| try self.checkBinary(bin),
            .unary => |un| try self.checkUnary(un),
            .call => |c| try self.checkCall(c),
            .index => |i| try self.checkIndex(i),
            .slice_expr => |se| try self.checkSliceExpr(se),
            .field_access => |f| try self.checkFieldAccess(f),
            .array_literal => |al| try self.checkArrayLiteral(al),
            .paren => |p| try self.checkExpr(p.inner),
            .if_expr => |ie| try self.checkIfExpr(ie),
            .switch_expr => |se| try self.checkSwitchExpr(se),
            .block => |b| try self.checkBlock(b),
            .struct_init => |si| try self.checkStructInit(si),
            .new_expr => |ne| try self.checkNewExpr(ne),
            .type_expr => invalid_type, // Types are not values
            .bad_expr => invalid_type,
        };
    }

    /// Check new expression: new Map<K, V>() or new List<T>()
    fn checkNewExpr(self: *Checker, ne: ast.NewExpr) CheckError!TypeIndex {
        // Resolve the type being allocated
        return try self.resolveTypeExpr(ne.type_expr);
    }

    /// Check identifier expression.
    fn checkIdentifier(self: *Checker, id: ast.Identifier) TypeIndex {
        if (self.scope.lookup(id.name)) |sym| {
            return sym.type_idx;
        }
        self.errUndefined(id.span.start, id.name);
        return invalid_type;
    }

    /// Check literal expression.
    fn checkLiteral(self: *Checker, lit: ast.Literal) TypeIndex {
        _ = self;
        return switch (lit.kind) {
            .int => TypeRegistry.INT, // Could use untyped_int for more flexibility
            .float => TypeRegistry.FLOAT,
            .string => TypeRegistry.STRING,
            .char => TypeRegistry.U8, // char is u8
            .true_lit, .false_lit => TypeRegistry.BOOL,
            .null_lit => invalid_type, // null needs context
        };
    }

    /// Check binary expression.
    fn checkBinary(self: *Checker, bin: ast.Binary) CheckError!TypeIndex {
        const left_type = try self.checkExpr(bin.left);
        const right_type = try self.checkExpr(bin.right);

        const left = self.types.get(left_type);
        const right = self.types.get(right_type);

        // Arithmetic operators: +, -, *, /, %
        switch (bin.op) {
            .plus, .minus, .star, .slash, .percent => {
                // Both operands must be numeric
                if (!isNumeric(left) or !isNumeric(right)) {
                    self.errInvalidOp(bin.span.start, "arithmetic", left_type, right_type);
                    return invalid_type;
                }
                // Result is the common type (simplified: use left type)
                return left_type;
            },
            // Comparison operators: ==, !=, <, <=, >, >=
            .equal_equal, .bang_equal, .less, .less_equal, .greater, .greater_equal => {
                // Both operands must be comparable
                if (!self.isComparable(left_type, right_type)) {
                    self.errInvalidOp(bin.span.start, "comparison", left_type, right_type);
                    return invalid_type;
                }
                return TypeRegistry.BOOL;
            },
            // Logical operators: and, or
            .kw_and, .kw_or => {
                // Both operands must be bool
                if (!isBool(left) or !isBool(right)) {
                    self.errInvalidOp(bin.span.start, "logical", left_type, right_type);
                    return invalid_type;
                }
                return TypeRegistry.BOOL;
            },
            // Bitwise operators: &, |, ^
            .ampersand, .pipe, .caret => {
                // Both operands must be integer
                if (!isInteger(left) or !isInteger(right)) {
                    self.errInvalidOp(bin.span.start, "bitwise", left_type, right_type);
                    return invalid_type;
                }
                return left_type;
            },
            else => return invalid_type,
        }
    }

    /// Check unary expression.
    fn checkUnary(self: *Checker, un: ast.Unary) CheckError!TypeIndex {
        const operand_type = try self.checkExpr(un.operand);
        const operand = self.types.get(operand_type);

        switch (un.op) {
            .minus => {
                if (!isNumeric(operand)) {
                    self.err.errorWithCode(un.span.start, .E303, "unary '-' requires numeric operand");
                    return invalid_type;
                }
                return operand_type;
            },
            .bang, .kw_not => {
                if (!isBool(operand)) {
                    self.err.errorWithCode(un.span.start, .E303, "unary '!' requires bool operand");
                    return invalid_type;
                }
                return TypeRegistry.BOOL;
            },
            else => return invalid_type,
        }
    }

    /// Check function call.
    fn checkCall(self: *Checker, c: ast.Call) CheckError!TypeIndex {
        // Check for builtin functions first
        if (self.tree.getExpr(c.callee)) |callee_expr| {
            if (callee_expr == .identifier) {
                const name = callee_expr.identifier.name;
                if (std.mem.eql(u8, name, "len")) {
                    return self.checkBuiltinLen(c);
                }
                if (std.mem.eql(u8, name, "print") or std.mem.eql(u8, name, "println")) {
                    return self.checkBuiltinPrint(c);
                }
                if (std.mem.eql(u8, name, "@intFromEnum")) {
                    return self.checkBuiltinIntFromEnum(c);
                }
                if (std.mem.eql(u8, name, "@enumFromInt")) {
                    return self.checkBuiltinEnumFromInt(c);
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

    /// Check builtin len() function.
    fn checkBuiltinLen(self: *Checker, c: ast.Call) CheckError!TypeIndex {
        // len() takes exactly one argument
        if (c.args.len != 1) {
            self.err.errorWithCode(c.span.start, .E300, "len() expects exactly one argument");
            return invalid_type;
        }

        const arg_type = try self.checkExpr(c.args[0]);
        const arg = self.types.get(arg_type);

        // len() works on strings, arrays, and slices
        switch (arg) {
            .basic => |k| {
                if (k == .string_type) {
                    return TypeRegistry.INT;
                }
            },
            .array, .slice => {
                return TypeRegistry.INT;
            },
            else => {},
        }

        self.err.errorWithCode(c.span.start, .E300, "len() argument must be string, array, or slice");
        return invalid_type;
    }

    /// Check builtin print()/println() functions.
    fn checkBuiltinPrint(self: *Checker, c: ast.Call) CheckError!TypeIndex {
        // print()/println() takes exactly one argument
        if (c.args.len != 1) {
            self.err.errorWithCode(c.span.start, .E300, "print() expects exactly one argument");
            return TypeRegistry.VOID;
        }

        const arg_type = try self.checkExpr(c.args[0]);
        const arg = self.types.get(arg_type);

        // print() works on strings and integers
        switch (arg) {
            .basic => |k| {
                if (k == .string_type or k == .i64_type or k == .i32_type or
                    k == .i16_type or k == .i8_type or k == .u64_type or
                    k == .u32_type or k == .u16_type or k == .u8_type or k == .bool_type)
                {
                    return TypeRegistry.VOID;
                }
            },
            else => {},
        }

        self.err.errorWithCode(c.span.start, .E300, "print() argument must be string or integer");
        return TypeRegistry.VOID;
    }

    /// Check builtin @intFromEnum() function.
    fn checkBuiltinIntFromEnum(self: *Checker, c: ast.Call) CheckError!TypeIndex {
        // @intFromEnum() takes exactly one argument
        if (c.args.len != 1) {
            self.err.errorWithCode(c.span.start, .E300, "@intFromEnum() expects exactly one argument");
            return invalid_type;
        }

        const arg_type = try self.checkExpr(c.args[0]);
        const arg = self.types.get(arg_type);

        // Argument must be an enum type
        switch (arg) {
            .enum_type => |e| {
                // Return the backing type of the enum
                return e.backing_type;
            },
            else => {
                self.err.errorWithCode(c.span.start, .E300, "@intFromEnum() argument must be an enum value");
                return invalid_type;
            },
        }
    }

    /// Check builtin @enumFromInt() function.
    /// Syntax: @enumFromInt(EnumType, int_value)
    fn checkBuiltinEnumFromInt(self: *Checker, c: ast.Call) CheckError!TypeIndex {
        // @enumFromInt() takes exactly two arguments: type and value
        if (c.args.len != 2) {
            self.err.errorWithCode(c.span.start, .E300, "@enumFromInt() expects two arguments: (EnumType, value)");
            return invalid_type;
        }

        // First argument should be an enum type name (identifier)
        const type_arg = self.tree.getExpr(c.args[0]);
        if (type_arg == null or type_arg.? != .identifier) {
            self.err.errorWithCode(c.span.start, .E300, "@enumFromInt() first argument must be an enum type name");
            return invalid_type;
        }

        const type_name = type_arg.?.identifier.name;
        const enum_type_idx = self.types.lookupByName(type_name) orelse {
            self.errUndefined(c.span.start, type_name);
            return invalid_type;
        };

        const enum_type = self.types.get(enum_type_idx);
        if (enum_type != .enum_type) {
            self.err.errorWithCode(c.span.start, .E300, "@enumFromInt() first argument must be an enum type");
            return invalid_type;
        }

        // Second argument should be an integer
        const value_type = try self.checkExpr(c.args[1]);
        const value = self.types.get(value_type);
        if (!isInteger(value)) {
            self.err.errorWithCode(c.span.start, .E300, "@enumFromInt() second argument must be an integer");
            return invalid_type;
        }

        // Return the enum type
        return enum_type_idx;
    }

    /// Check index expression.
    fn checkIndex(self: *Checker, i: ast.Index) CheckError!TypeIndex {
        const base_type = try self.checkExpr(i.base);
        const index_type = try self.checkExpr(i.index);
        const base = self.types.get(base_type);

        // Index must be integer
        const index = self.types.get(index_type);
        if (!isInteger(index)) {
            self.err.errorWithCode(i.span.start, .E300, "index must be integer");
            return invalid_type;
        }

        // Check indexable types
        return switch (base) {
            .array => |a| a.elem,
            .slice => |s| s.elem,
            .basic => |k| if (k == .string_type) TypeRegistry.U8 else invalid_type,
            else => blk: {
                self.err.errorWithCode(i.span.start, .E303, "cannot index this type");
                break :blk invalid_type;
            },
        };
    }

    /// Check slice expression (base[start:end]).
    fn checkSliceExpr(self: *Checker, se: ast.SliceExpr) CheckError!TypeIndex {
        const base_type = try self.checkExpr(se.base);
        const base = self.types.get(base_type);

        // Check start index if present
        if (se.start != ast.null_node) {
            const start_type = try self.checkExpr(se.start);
            const start = self.types.get(start_type);
            if (!isInteger(start)) {
                self.err.errorWithCode(se.span.start, .E300, "slice start must be integer");
                return invalid_type;
            }
        }

        // Check end index if present
        if (se.end != ast.null_node) {
            const end_type = try self.checkExpr(se.end);
            const end_t = self.types.get(end_type);
            if (!isInteger(end_t)) {
                self.err.errorWithCode(se.span.start, .E300, "slice end must be integer");
                return invalid_type;
            }
        }

        // Check sliceable types and return slice type
        return switch (base) {
            .array => |a| try self.types.makeSlice(a.elem),
            .slice => base_type, // Slicing a slice returns same slice type
            .basic => |k| if (k == .string_type) try self.types.makeSlice(TypeRegistry.U8) else blk: {
                self.err.errorWithCode(se.span.start, .E303, "cannot slice this type");
                break :blk invalid_type;
            },
            else => blk: {
                self.err.errorWithCode(se.span.start, .E303, "cannot slice this type");
                break :blk invalid_type;
            },
        };
    }

    /// Check field access.
    fn checkFieldAccess(self: *Checker, f: ast.FieldAccess) CheckError!TypeIndex {
        const base_type = try self.checkExpr(f.base);
        const base = self.types.get(base_type);

        // Handle struct field access
        switch (base) {
            .struct_type => |st| {
                for (st.fields) |field| {
                    if (std.mem.eql(u8, field.name, f.field)) {
                        return field.type_idx;
                    }
                }
                self.errUndefined(f.span.start, f.field);
                return invalid_type;
            },
            .enum_type => |et| {
                // Enum variant access: Color.red
                for (et.variants) |variant| {
                    if (std.mem.eql(u8, variant.name, f.field)) {
                        // Return the enum type itself (not the backing type)
                        return base_type;
                    }
                }
                self.errUndefined(f.span.start, f.field);
                return invalid_type;
            },
            .union_type => |ut| {
                // Union variant access: Result.ok
                // This returns a "constructor" - handled specially in checkCall
                for (ut.variants) |variant| {
                    if (std.mem.eql(u8, variant.name, f.field)) {
                        // For unit variants (no payload), return the union type directly
                        if (variant.type_idx == types.invalid_type) {
                            return base_type;
                        }
                        // For variants with payload, create a synthetic function type: fn(PayloadType) UnionType
                        // Must heap-allocate params to avoid dangling pointer
                        const params = try self.allocator.alloc(types.FuncParam, 1);
                        params[0] = .{
                            .name = "payload",
                            .type_idx = variant.type_idx,
                        };
                        return try self.types.add(.{ .func = .{
                            .params = params,
                            .return_type = base_type,
                        } });
                    }
                }
                self.errUndefined(f.span.start, f.field);
                return invalid_type;
            },
            .pointer => |ptr| {
                // Auto-deref for field access
                const elem = self.types.get(ptr.elem);
                switch (elem) {
                    .struct_type => |st| {
                        for (st.fields) |field| {
                            if (std.mem.eql(u8, field.name, f.field)) {
                                return field.type_idx;
                            }
                        }
                        self.errUndefined(f.span.start, f.field);
                        return invalid_type;
                    },
                    else => {},
                }
                self.err.errorWithCode(f.span.start, .E303, "cannot access field on this type");
                return invalid_type;
            },
            .map_type => |mt| {
                // Map method access: map.set, map.get, map.has, map.size
                if (std.mem.eql(u8, f.field, "set")) {
                    // set(key, value) returns void
                    const params = try self.allocator.alloc(types.FuncParam, 2);
                    params[0] = .{ .name = "key", .type_idx = mt.key };
                    params[1] = .{ .name = "value", .type_idx = mt.value };
                    return try self.types.add(.{ .func = .{
                        .params = params,
                        .return_type = TypeRegistry.VOID,
                    } });
                } else if (std.mem.eql(u8, f.field, "get")) {
                    // get(key) returns value type
                    const params = try self.allocator.alloc(types.FuncParam, 1);
                    params[0] = .{ .name = "key", .type_idx = mt.key };
                    return try self.types.add(.{ .func = .{
                        .params = params,
                        .return_type = mt.value,
                    } });
                } else if (std.mem.eql(u8, f.field, "has")) {
                    // has(key) returns bool
                    const params = try self.allocator.alloc(types.FuncParam, 1);
                    params[0] = .{ .name = "key", .type_idx = mt.key };
                    return try self.types.add(.{ .func = .{
                        .params = params,
                        .return_type = TypeRegistry.BOOL,
                    } });
                } else if (std.mem.eql(u8, f.field, "size")) {
                    // size() returns int
                    return try self.types.add(.{ .func = .{
                        .params = &.{},
                        .return_type = TypeRegistry.INT,
                    } });
                }
                self.errUndefined(f.span.start, f.field);
                return invalid_type;
            },
            else => {
                self.err.errorWithCode(f.span.start, .E303, "cannot access field on this type");
                return invalid_type;
            },
        }
    }

    /// Check struct initialization: Point{ .x = 10, .y = 20 }
    fn checkStructInit(self: *Checker, si: ast.StructInit) CheckError!TypeIndex {
        // Look up the struct type
        const sym = self.scope.lookup(si.type_name) orelse {
            self.errUndefined(si.span.start, si.type_name);
            return invalid_type;
        };

        const struct_type = self.types.get(sym.type_idx);
        switch (struct_type) {
            .struct_type => |st| {
                // Check each field initializer
                for (si.fields) |field_init| {
                    // Find the field in the struct type
                    var found = false;
                    for (st.fields) |struct_field| {
                        if (std.mem.eql(u8, struct_field.name, field_init.name)) {
                            found = true;
                            // Check the value type matches the field type
                            const value_type = try self.checkExpr(field_init.value);
                            if (!self.types.equal(value_type, struct_field.type_idx)) {
                                self.err.errorWithCode(field_init.span.start, .E300, "type mismatch in field initializer");
                            }
                            break;
                        }
                    }
                    if (!found) {
                        self.err.errorWithCode(field_init.span.start, .E301, "unknown field in struct initializer");
                    }
                }
                return sym.type_idx;
            },
            else => {
                self.err.errorWithCode(si.span.start, .E300, "not a struct type");
                return invalid_type;
            },
        }
    }

    /// Check array literal: [1, 2, 3]
    fn checkArrayLiteral(self: *Checker, al: ast.ArrayLiteral) CheckError!TypeIndex {
        if (al.elements.len == 0) {
            self.err.errorWithCode(al.span.start, .E300, "cannot infer type of empty array literal");
            return invalid_type;
        }

        // Get type of first element
        const first_type = try self.checkExpr(al.elements[0]);
        if (first_type == invalid_type) {
            return invalid_type;
        }

        // Check all other elements have the same type
        for (al.elements[1..]) |elem_idx| {
            const elem_type = try self.checkExpr(elem_idx);
            if (!self.types.equal(first_type, elem_type)) {
                self.err.errorWithCode(al.span.start, .E300, "array elements must have same type");
                return invalid_type;
            }
        }

        // Create array type with inferred element type and length
        const array_type = self.types.makeArray(first_type, al.elements.len) catch {
            return invalid_type;
        };
        return array_type;
    }

    /// Check if expression.
    fn checkIfExpr(self: *Checker, ie: ast.IfExpr) CheckError!TypeIndex {
        const cond_type = try self.checkExpr(ie.condition);
        const cond = self.types.get(cond_type);

        if (!isBool(cond)) {
            self.err.errorWithCode(ie.span.start, .E300, "condition must be bool");
        }

        const then_type = try self.checkExpr(ie.then_branch);

        if (ie.else_branch) |else_idx| {
            const else_type = try self.checkExpr(else_idx);
            // Both branches must have same type
            if (!self.types.equal(then_type, else_type)) {
                self.err.errorWithCode(ie.span.start, .E300, "if branches have different types");
                return invalid_type;
            }
            return then_type;
        }

        // If without else has void type
        return TypeRegistry.VOID;
    }

    /// Check switch expression.
    fn checkSwitchExpr(self: *Checker, se: ast.SwitchExpr) CheckError!TypeIndex {
        const subject_type = try self.checkExpr(se.subject);
        const subject_t = self.types.get(subject_type);

        // Track result type (from first case body)
        var result_type: TypeIndex = TypeRegistry.VOID;
        var first_case = true;

        // Check each case
        for (se.cases) |case| {
            // Check each value in this case
            for (case.values) |val_idx| {
                const val_node = self.tree.getNode(val_idx);
                // Handle inferred variant literals (.variant) for union switches
                if (val_node == .expr and val_node.expr == .field_access) {
                    const fa = val_node.expr.field_access;
                    if (fa.base == ast.null_node) {
                        // Inferred variant literal - check against subject type
                        if (subject_t == .union_type) {
                            const ut = subject_t.union_type;
                            var found = false;
                            for (ut.variants) |v| {
                                if (std.mem.eql(u8, v.name, fa.field)) {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) {
                                self.err.errorWithCode(case.span.start, .E301, "unknown union variant");
                            }
                            continue; // Skip normal type checking
                        } else if (subject_t == .enum_type) {
                            const et = subject_t.enum_type;
                            var found = false;
                            for (et.variants) |v| {
                                if (std.mem.eql(u8, v.name, fa.field)) {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) {
                                self.err.errorWithCode(case.span.start, .E301, "unknown enum variant");
                            }
                            continue; // Skip normal type checking
                        }
                    }
                }
                // Regular expression - check type normally
                const val_type = try self.checkExpr(val_idx);
                // Each value must be comparable to subject
                if (!self.isComparable(subject_type, val_type)) {
                    self.err.errorWithCode(case.span.start, .E300, "case value not comparable to switch subject");
                }
            }

            // Handle payload capture for union switch
            var body_type: TypeIndex = undefined;
            if (case.capture) |capture_name| {
                // Subject must be a union type
                if (subject_t != .union_type) {
                    self.err.errorWithCode(case.span.start, .E300, "payload capture only valid for union switch");
                    body_type = try self.checkExpr(case.body);
                } else {
                    // Get the variant name from the case value (first value)
                    // Value should be .variant_name (field access on inferred type)
                    const ut = subject_t.union_type;
                    var payload_type: TypeIndex = TypeRegistry.VOID;

                    // Find the variant type from the case value
                    if (case.values.len > 0) {
                        const val_node = self.tree.getNode(case.values[0]);
                        if (val_node == .expr and val_node.expr == .field_access) {
                            const variant_name = val_node.expr.field_access.field;
                            for (ut.variants) |v| {
                                if (std.mem.eql(u8, v.name, variant_name)) {
                                    payload_type = v.type_idx;
                                    break;
                                }
                            }
                        }
                    }

                    // Create scope with captured variable
                    var case_scope = Scope.init(self.allocator, self.scope);
                    defer case_scope.deinit();
                    try case_scope.define(.{
                        .name = capture_name,
                        .kind = .variable,
                        .type_idx = payload_type,
                        .node = ast.null_node,
                        .mutable = false,
                    });

                    const old_scope = self.scope;
                    self.scope = &case_scope;
                    body_type = try self.checkExpr(case.body);
                    self.scope = old_scope;
                }
            } else {
                // No capture - check body in current scope
                body_type = try self.checkExpr(case.body);
            }

            if (first_case) {
                result_type = body_type;
                first_case = false;
            } else {
                // All case bodies must have same type
                if (!self.types.equal(result_type, body_type)) {
                    self.err.errorWithCode(case.span.start, .E300, "switch case has different type than previous cases");
                }
            }
        }

        // Check else body if present
        if (se.else_body) |else_idx| {
            const else_type = try self.checkExpr(else_idx);
            if (!first_case and !self.types.equal(result_type, else_type)) {
                self.err.errorWithCode(se.span.start, .E300, "switch else has different type than cases");
            }
            if (first_case) {
                result_type = else_type;
            }
        }

        return result_type;
    }

    /// Check block expression.
    fn checkBlock(self: *Checker, b: ast.Block) CheckError!TypeIndex {
        // Create new scope for block
        var block_scope = Scope.init(self.allocator, self.scope);
        defer block_scope.deinit();

        const old_scope = self.scope;
        self.scope = &block_scope;

        // Check statements
        for (b.stmts) |stmt_idx| {
            try self.checkStmt(stmt_idx);
        }

        self.scope = old_scope;

        // Block value is the final expression, or void
        if (b.expr != null_node) {
            return try self.checkExpr(b.expr);
        }
        return TypeRegistry.VOID;
    }

    /// Check block expression (from function body).
    fn checkBlockExpr(self: *Checker, idx: NodeIndex) CheckError!void {
        const node = self.tree.getNode(idx);
        switch (node) {
            .expr => |e| switch (e) {
                .block => |b| {
                    _ = try self.checkBlock(b);
                },
                else => {},
            },
            else => {},
        }
    }

    // ========================================================================
    // Statement checking
    // ========================================================================

    /// Check a statement.
    fn checkStmt(self: *Checker, idx: NodeIndex) CheckError!void {
        const stmt = self.tree.getStmt(idx) orelse return;

        switch (stmt) {
            .expr_stmt => |es| {
                _ = try self.checkExpr(es.expr);
            },
            .return_stmt => |rs| try self.checkReturn(rs),
            .var_stmt => |vs| try self.checkVarStmt(vs, idx),
            .assign_stmt => |as_stmt| try self.checkAssign(as_stmt),
            .if_stmt => |is| try self.checkIfStmt(is),
            .while_stmt => |ws| try self.checkWhileStmt(ws),
            .for_stmt => |fs| try self.checkForStmt(fs),
            .block_stmt => |bs| try self.checkBlockStmt(bs),
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
            .bad_stmt => {},
        }
    }

    /// Check return statement.
    fn checkReturn(self: *Checker, rs: ast.ReturnStmt) CheckError!void {
        if (rs.value) |val_idx| {
            const val_type = try self.checkExpr(val_idx);
            if (self.current_return_type == TypeRegistry.VOID) {
                self.err.errorWithCode(rs.span.start, .E300, "void function should not return a value");
            } else if (!self.isAssignable(val_type, self.current_return_type)) {
                self.errTypeMismatch(rs.span.start, self.current_return_type, val_type);
            }
        } else {
            if (self.current_return_type != TypeRegistry.VOID) {
                self.err.errorWithCode(rs.span.start, .E300, "non-void function must return a value");
            }
        }
    }

    /// Check var statement (local variable).
    fn checkVarStmt(self: *Checker, vs: ast.VarStmt, idx: NodeIndex) CheckError!void {
        if (self.scope.isDefined(vs.name)) {
            self.errRedefined(vs.span.start, vs.name);
            return;
        }

        var var_type: TypeIndex = invalid_type;

        if (vs.type_expr) |type_idx| {
            var_type = try self.resolveTypeExpr(type_idx);
        }

        if (vs.value) |val_idx| {
            const val_type = try self.checkExpr(val_idx);
            if (var_type == invalid_type) {
                var_type = self.materializeType(val_type);
            } else if (!self.isAssignable(val_type, var_type)) {
                self.errTypeMismatch(vs.span.start, var_type, val_type);
            }
        }

        try self.scope.define(Symbol.init(
            vs.name,
            if (vs.is_const) .constant else .variable,
            var_type,
            idx,
            !vs.is_const,
        ));
    }

    /// Check assignment statement.
    fn checkAssign(self: *Checker, as_stmt: ast.AssignStmt) CheckError!void {
        const target_type = try self.checkExpr(as_stmt.target);
        const value_type = try self.checkExpr(as_stmt.value);

        // Check target is assignable (lvalue)
        const target = self.tree.getExpr(as_stmt.target) orelse return;
        switch (target) {
            .identifier => |id| {
                if (self.scope.lookup(id.name)) |sym| {
                    if (!sym.mutable) {
                        self.err.errorWithCode(as_stmt.span.start, .E303, "cannot assign to constant");
                        return;
                    }
                }
            },
            .index, .field_access => {}, // These are valid lvalues
            else => {
                self.err.errorWithCode(as_stmt.span.start, .E303, "invalid assignment target");
                return;
            },
        }

        if (!self.isAssignable(value_type, target_type)) {
            self.errTypeMismatch(as_stmt.span.start, target_type, value_type);
        }
    }

    /// Check if statement.
    fn checkIfStmt(self: *Checker, is: ast.IfStmt) CheckError!void {
        const cond_type = try self.checkExpr(is.condition);
        const cond = self.types.get(cond_type);

        if (!isBool(cond)) {
            self.err.errorWithCode(is.span.start, .E300, "condition must be bool");
        }

        try self.checkStmt(is.then_branch);

        if (is.else_branch) |else_idx| {
            try self.checkStmt(else_idx);
        }
    }

    /// Check while statement.
    fn checkWhileStmt(self: *Checker, ws: ast.WhileStmt) CheckError!void {
        const cond_type = try self.checkExpr(ws.condition);
        const cond = self.types.get(cond_type);

        if (!isBool(cond)) {
            self.err.errorWithCode(ws.span.start, .E300, "condition must be bool");
        }

        const old_in_loop = self.in_loop;
        self.in_loop = true;
        try self.checkStmt(ws.body);
        self.in_loop = old_in_loop;
    }

    /// Check for statement.
    fn checkForStmt(self: *Checker, fs: ast.ForStmt) CheckError!void {
        const iter_type = try self.checkExpr(fs.iterable);
        const iter = self.types.get(iter_type);

        // Determine element type
        const elem_type: TypeIndex = switch (iter) {
            .array => |a| a.elem,
            .slice => |s| s.elem,
            .basic => |k| if (k == .string_type) TypeRegistry.U8 else invalid_type,
            else => blk: {
                self.err.errorWithCode(fs.span.start, .E303, "cannot iterate over this type");
                break :blk invalid_type;
            },
        };

        // Create scope with loop variable
        var loop_scope = Scope.init(self.allocator, self.scope);
        defer loop_scope.deinit();

        try loop_scope.define(Symbol.init(fs.binding, .variable, elem_type, null_node, false));

        const old_scope = self.scope;
        const old_in_loop = self.in_loop;
        self.scope = &loop_scope;
        self.in_loop = true;

        try self.checkStmt(fs.body);

        self.scope = old_scope;
        self.in_loop = old_in_loop;
    }

    /// Check block statement.
    fn checkBlockStmt(self: *Checker, bs: ast.BlockStmt) CheckError!void {
        var block_scope = Scope.init(self.allocator, self.scope);
        defer block_scope.deinit();

        const old_scope = self.scope;
        self.scope = &block_scope;

        for (bs.stmts) |stmt_idx| {
            try self.checkStmt(stmt_idx);
        }

        self.scope = old_scope;
    }

    // ========================================================================
    // Type resolution
    // ========================================================================

    /// Resolve a type expression to a TypeIndex.
    fn resolveTypeExpr(self: *Checker, idx: NodeIndex) CheckError!TypeIndex {
        const node = self.tree.getNode(idx);
        switch (node) {
            .expr => |e| switch (e) {
                .type_expr => |te| return self.resolveType(te),
                else => return invalid_type,
            },
            else => return invalid_type,
        }
    }

    /// Resolve a TypeExpr to TypeIndex.
    fn resolveType(self: *Checker, te: TypeExpr) CheckError!TypeIndex {
        return switch (te.kind) {
            .named => |name| {
                // Check built-in types first
                if (self.types.lookupBasic(name)) |idx| {
                    return idx;
                }
                // Check user-defined types
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
                // TODO: evaluate size expression as constant
                return try self.types.makeArray(elem, 0);
            },
            .function => {
                // TODO: function types
                return invalid_type;
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

    /// Build a function type from parameters and return type.
    fn buildFuncType(self: *Checker, params: []const ast.Field, return_type_idx: ?NodeIndex) CheckError!TypeIndex {
        var func_params = std.ArrayList(types.FuncParam){ .items = &.{}, .capacity = 0 };
        defer func_params.deinit(self.allocator);

        for (params) |param| {
            const param_type = try self.resolveTypeExpr(param.type_expr);
            try func_params.append(self.allocator, .{
                .name = param.name,
                .type_idx = param_type,
            });
        }

        const ret_type: TypeIndex = if (return_type_idx) |idx|
            try self.resolveTypeExpr(idx)
        else
            TypeRegistry.VOID;

        return try self.types.add(.{ .func = .{
            .params = try self.allocator.dupe(types.FuncParam, func_params.items),
            .return_type = ret_type,
        } });
    }

    /// Build a struct type from fields.
    fn buildStructType(self: *Checker, name: []const u8, fields: []const ast.Field) CheckError!TypeIndex {
        var struct_fields = std.ArrayList(types.StructField){ .items = &.{}, .capacity = 0 };
        defer struct_fields.deinit(self.allocator);

        var offset: u32 = 0;
        for (fields) |field| {
            const field_type = try self.resolveTypeExpr(field.type_expr);
            const field_size = self.typeSize(field_type);
            try struct_fields.append(self.allocator, .{
                .name = field.name,
                .type_idx = field_type,
                .offset = offset,
            });
            offset += field_size;
        }

        return try self.types.add(.{ .struct_type = .{
            .name = name,
            .fields = try self.allocator.dupe(types.StructField, struct_fields.items),
            .size = offset,
            .alignment = 8, // simplified: always 8-byte aligned
        } });
    }

    /// Build an enum type from an AST enum declaration.
    fn buildEnumType(self: *Checker, e: ast.EnumDecl) CheckError!TypeIndex {
        // Resolve backing type (default to i32 if not specified)
        var backing_type: TypeIndex = TypeRegistry.I32;
        if (e.backing_type) |bt_node| {
            backing_type = try self.resolveTypeExpr(bt_node);
            // Validate it's an integer type
            const bt = self.types.get(backing_type);
            switch (bt) {
                .basic => |k| {
                    if (!k.isInteger()) {
                        self.err.errorAt(e.span.start, "enum backing type must be an integer type");
                        backing_type = TypeRegistry.I32;
                    }
                },
                else => {
                    self.err.errorAt(e.span.start, "enum backing type must be an integer type");
                    backing_type = TypeRegistry.I32;
                },
            }
        }

        var enum_variants = std.ArrayList(types.EnumVariant){ .items = &.{}, .capacity = 0 };
        defer enum_variants.deinit(self.allocator);

        var next_value: i64 = 0;
        for (e.variants) |variant| {
            var value = next_value;
            if (variant.value) |val_node| {
                // Evaluate the constant expression
                const val_type = try self.checkExpr(val_node);
                _ = val_type;
                // For now, just look for a literal
                if (self.tree.getExpr(val_node)) |expr| {
                    switch (expr) {
                        .literal => |lit| {
                            if (lit.kind == .int) {
                                value = std.fmt.parseInt(i64, lit.value, 10) catch 0;
                            }
                        },
                        else => {},
                    }
                }
            }
            try enum_variants.append(self.allocator, .{
                .name = variant.name,
                .value = value,
            });
            next_value = value + 1;
        }

        return try self.types.add(.{ .enum_type = .{
            .name = e.name,
            .backing_type = backing_type,
            .variants = try self.allocator.dupe(types.EnumVariant, enum_variants.items),
        } });
    }

    /// Build a union type from a union declaration.
    fn buildUnionType(self: *Checker, u: ast.UnionDecl) CheckError!TypeIndex {
        var union_variants = std.ArrayList(types.UnionVariant){ .items = &.{}, .capacity = 0 };
        defer union_variants.deinit(self.allocator);

        for (u.variants) |variant| {
            var payload_type: TypeIndex = types.invalid_type;
            if (variant.type_expr) |type_node| {
                payload_type = try self.resolveTypeExpr(type_node);
            }
            try union_variants.append(self.allocator, .{
                .name = variant.name,
                .type_idx = payload_type,
            });
        }

        // Tag type is u8 if <= 256 variants, u16 otherwise
        const tag_type: TypeIndex = if (u.variants.len <= 256) TypeRegistry.U8 else TypeRegistry.U16;

        return try self.types.add(.{ .union_type = .{
            .name = u.name,
            .variants = try self.allocator.dupe(types.UnionVariant, union_variants.items),
            .tag_type = tag_type,
        } });
    }

    // ========================================================================
    // Type utilities
    // ========================================================================

    /// Get the size of a type in bytes.
    fn typeSize(self: *Checker, idx: TypeIndex) u32 {
        const t = self.types.get(idx);
        return switch (t) {
            .basic => |k| k.size(),
            .pointer, .slice, .func => 8, // pointer size
            .optional => |o| self.typeSize(o.elem) + 1, // simplified
            .array => |a| @intCast(a.length * self.typeSize(a.elem)),
            .struct_type => |s| s.size,
            .enum_type => |e| self.typeSize(e.backing_type),
            .union_type => |ut| blk: {
                // Union size = tag size + max payload size
                var max_payload: u32 = 0;
                for (ut.variants) |v| {
                    if (v.type_idx != types.invalid_type) {
                        const payload_size = self.typeSize(v.type_idx);
                        if (payload_size > max_payload) max_payload = payload_size;
                    }
                }
                break :blk self.typeSize(ut.tag_type) + max_payload;
            },
            else => 0,
        };
    }

    /// Materialize an untyped type to a concrete type.
    fn materializeType(self: *Checker, idx: TypeIndex) TypeIndex {
        const t = self.types.get(idx);
        return switch (t) {
            .basic => |k| switch (k) {
                .untyped_int => TypeRegistry.INT,
                .untyped_float => TypeRegistry.FLOAT,
                .untyped_bool => TypeRegistry.BOOL,
                .untyped_string => TypeRegistry.STRING,
                else => idx,
            },
            else => idx,
        };
    }

    /// Check if a value of type `from` can be assigned to a variable of type `to`.
    fn isAssignable(self: *Checker, from: TypeIndex, to: TypeIndex) bool {
        if (from == invalid_type or to == invalid_type) return true; // Skip for error recovery
        return self.types.isAssignable(from, to);
    }

    /// Check if two types are comparable.
    fn isComparable(self: *Checker, a: TypeIndex, b: TypeIndex) bool {
        // Same types are comparable
        if (self.types.equal(a, b)) return true;

        // Numeric types are comparable to each other
        const ta = self.types.get(a);
        const tb = self.types.get(b);
        if (isNumeric(ta) and isNumeric(tb)) return true;

        // String types are comparable (for == and !=)
        if (isString(ta) and isString(tb)) return true;

        return false;
    }

    // ========================================================================
    // Error helpers
    // ========================================================================

    fn errUndefined(self: *Checker, pos: Pos, name: []const u8) void {
        _ = name;
        self.err.errorWithCode(pos, .E301, "undefined variable");
    }

    fn errRedefined(self: *Checker, pos: Pos, name: []const u8) void {
        _ = name;
        self.err.errorWithCode(pos, .E302, "redefined identifier");
    }

    fn errTypeMismatch(self: *Checker, pos: Pos, expected: TypeIndex, got: TypeIndex) void {
        _ = expected;
        _ = got;
        self.err.errorWithCode(pos, .E300, "type mismatch");
    }

    fn errInvalidOp(self: *Checker, pos: Pos, op_kind: []const u8, left: TypeIndex, right: TypeIndex) void {
        _ = op_kind;
        _ = left;
        _ = right;
        self.err.errorWithCode(pos, .E303, "invalid operation");
    }
};

// ============================================================================
// Type predicates
// ============================================================================

fn isNumeric(t: Type) bool {
    return switch (t) {
        .basic => |k| k.isNumeric(),
        else => false,
    };
}

fn isInteger(t: Type) bool {
    return switch (t) {
        .basic => |k| k.isInteger(),
        else => false,
    };
}

fn isBool(t: Type) bool {
    return switch (t) {
        .basic => |k| k == .bool_type or k == .untyped_bool,
        else => false,
    };
}

fn isString(t: Type) bool {
    return switch (t) {
        .basic => |k| k == .string_type or k == .untyped_string,
        else => false,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "checker simple function" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source_mod = @import("source.zig");
    const scanner_mod = @import("scanner.zig");
    const parser_mod = @import("parser.zig");

    const content = "fn add(a: int, b: int) int { return a + b }";
    var src = source_mod.Source.init(alloc, "test.cot", content);
    var err_reporter = ErrorReporter.init(&src, null);
    var scan = scanner_mod.Scanner.initWithErrors(&src, &err_reporter);
    var tree = ast.Ast.init(alloc);
    var parser = parser_mod.Parser.init(alloc, &scan, &tree, &err_reporter);
    try parser.parseFile();

    var type_reg = try TypeRegistry.init(alloc);
    var global_scope = Scope.init(alloc, null);
    defer global_scope.deinit();

    var checker = Checker.init(alloc, &tree, &type_reg, &err_reporter, &global_scope);
    defer checker.deinit();

    try checker.checkFile();

    // Should have no type errors
    try std.testing.expect(!err_reporter.hasErrors());
}

test "checker undefined variable" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source_mod = @import("source.zig");
    const scanner_mod = @import("scanner.zig");
    const parser_mod = @import("parser.zig");

    const content = "fn main() { x = 1 }";
    var src = source_mod.Source.init(alloc, "test.cot", content);
    var err_reporter = ErrorReporter.init(&src, null);
    var scan = scanner_mod.Scanner.initWithErrors(&src, &err_reporter);
    var tree = ast.Ast.init(alloc);
    var parser = parser_mod.Parser.init(alloc, &scan, &tree, &err_reporter);
    try parser.parseFile();

    var type_reg = try TypeRegistry.init(alloc);
    var global_scope = Scope.init(alloc, null);
    defer global_scope.deinit();

    var checker = Checker.init(alloc, &tree, &type_reg, &err_reporter, &global_scope);
    defer checker.deinit();

    try checker.checkFile();

    // Should report undefined variable error
    try std.testing.expect(err_reporter.hasErrors());
}

test "checker type inference" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source_mod = @import("source.zig");
    const scanner_mod = @import("scanner.zig");
    const parser_mod = @import("parser.zig");

    const content = "var x = 42";
    var src = source_mod.Source.init(alloc, "test.cot", content);
    var err_reporter = ErrorReporter.init(&src, null);
    var scan = scanner_mod.Scanner.initWithErrors(&src, &err_reporter);
    var tree = ast.Ast.init(alloc);
    var parser = parser_mod.Parser.init(alloc, &scan, &tree, &err_reporter);
    try parser.parseFile();

    var type_reg = try TypeRegistry.init(alloc);
    var global_scope = Scope.init(alloc, null);
    defer global_scope.deinit();

    var checker = Checker.init(alloc, &tree, &type_reg, &err_reporter, &global_scope);
    defer checker.deinit();

    try checker.checkFile();

    // Should infer int type
    try std.testing.expect(!err_reporter.hasErrors());

    // Check that x has type int
    const sym = global_scope.lookup("x");
    try std.testing.expect(sym != null);
    try std.testing.expectEqual(TypeRegistry.INT, sym.?.type_idx);
}

test "checker struct field access" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source_mod = @import("source.zig");
    const scanner_mod = @import("scanner.zig");
    const parser_mod = @import("parser.zig");

    const content =
        \\struct Point { x: int, y: int }
        \\fn test(p: Point) int { return p.x }
    ;
    var src = source_mod.Source.init(alloc, "test.cot", content);
    var err_reporter = ErrorReporter.init(&src, null);
    var scan = scanner_mod.Scanner.initWithErrors(&src, &err_reporter);
    var tree = ast.Ast.init(alloc);
    var parser = parser_mod.Parser.init(alloc, &scan, &tree, &err_reporter);
    try parser.parseFile();

    var type_reg = try TypeRegistry.init(alloc);
    var global_scope = Scope.init(alloc, null);
    defer global_scope.deinit();

    var checker = Checker.init(alloc, &tree, &type_reg, &err_reporter, &global_scope);
    defer checker.deinit();

    try checker.checkFile();

    try std.testing.expect(!err_reporter.hasErrors());
}

test "checker break outside loop" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source_mod = @import("source.zig");
    const scanner_mod = @import("scanner.zig");
    const parser_mod = @import("parser.zig");

    const content = "fn main() { break }";
    var src = source_mod.Source.init(alloc, "test.cot", content);
    var err_reporter = ErrorReporter.init(&src, null);
    var scan = scanner_mod.Scanner.initWithErrors(&src, &err_reporter);
    var tree = ast.Ast.init(alloc);
    var parser = parser_mod.Parser.init(alloc, &scan, &tree, &err_reporter);
    try parser.parseFile();

    var type_reg = try TypeRegistry.init(alloc);
    var global_scope = Scope.init(alloc, null);
    defer global_scope.deinit();

    var checker = Checker.init(alloc, &tree, &type_reg, &err_reporter, &global_scope);
    defer checker.deinit();

    try checker.checkFile();

    // Should report error
    try std.testing.expect(err_reporter.hasErrors());
}

test "scope lookup" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var outer = Scope.init(alloc, null);
    defer outer.deinit();

    try outer.define(Symbol.init("x", .variable, TypeRegistry.INT, 0, true));

    var inner = Scope.init(alloc, &outer);
    defer inner.deinit();

    try inner.define(Symbol.init("y", .variable, TypeRegistry.STRING, 1, true));

    // Inner can see outer
    try std.testing.expect(inner.lookup("x") != null);
    try std.testing.expect(inner.lookup("y") != null);

    // Outer can't see inner
    try std.testing.expect(outer.lookup("x") != null);
    try std.testing.expect(outer.lookup("y") == null);
}

// Exhaustive test - ensures all AST expression types are handled.
// If a new expression type is added to ast.Expr, this test will fail to compile.
test "AST expr coverage - exhaustive" {
    // This test uses an exhaustive switch on ast.Expr to ensure
    // all expression types are accounted for in the type checker.
    // When a new expression type is added, this switch will fail to compile,
    // reminding us to implement checkExpr handling for the new type.
    const ExprTag = std.meta.Tag(ast.Expr);
    const all_tags = [_]ExprTag{
        .identifier,
        .literal,
        .binary,
        .unary,
        .call,
        .index,
        .slice_expr,
        .field_access,
        .array_literal,
        .paren,
        .if_expr,
        .switch_expr,
        .block,
        .struct_init,
        .new_expr,
        .type_expr,
        .bad_expr,
    };

    for (all_tags) |tag| {
        const is_known = switch (tag) {
            .identifier,
            .literal,
            .binary,
            .unary,
            .call,
            .index,
            .slice_expr,
            .field_access,
            .array_literal,
            .paren,
            .if_expr,
            .switch_expr,
            .block,
            .struct_init,
            .new_expr,
            .type_expr,
            .bad_expr,
            => true,
        };
        try std.testing.expect(is_known);
    }
}
