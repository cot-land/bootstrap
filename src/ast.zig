///! Abstract Syntax Tree node definitions.
///!
///! Maps to Go's cmd/compile/internal/syntax/nodes.go
///! Uses Zig tagged unions instead of Go interfaces.

const std = @import("std");
const source = @import("source.zig");
const token = @import("token.zig");

const Span = source.Span;
const Pos = source.Pos;
const Token = token.Token;

// ============================================================================
// Core Types
// ============================================================================

/// Index into an expression/statement/declaration pool.
/// Using indices instead of pointers allows arena allocation and compact storage.
pub const NodeIndex = u32;
pub const null_node: NodeIndex = std.math.maxInt(NodeIndex);

/// List of node indices (for parameter lists, statement lists, etc.)
pub const NodeList = []const NodeIndex;

// ============================================================================
// File (top-level)
// ============================================================================

/// A source file containing declarations.
pub const File = struct {
    /// File name
    filename: []const u8,
    /// Top-level declarations
    decls: []const NodeIndex,
    /// Span of the entire file
    span: Span,
};

// ============================================================================
// Declarations
// ============================================================================

pub const Decl = union(enum) {
    fn_decl: FnDecl,
    var_decl: VarDecl,
    const_decl: ConstDecl,
    struct_decl: StructDecl,
    enum_decl: EnumDecl,
    union_decl: UnionDecl,
    // For error recovery
    bad_decl: BadDecl,

    pub fn span(self: Decl) Span {
        return switch (self) {
            .fn_decl => |d| d.span,
            .var_decl => |d| d.span,
            .const_decl => |d| d.span,
            .struct_decl => |d| d.span,
            .enum_decl => |d| d.span,
            .union_decl => |d| d.span,
            .bad_decl => |d| d.span,
        };
    }
};

/// fn name(params) return_type { body }
pub const FnDecl = struct {
    name: []const u8,
    params: []const Field,
    return_type: ?NodeIndex, // null = void
    body: ?NodeIndex, // null = forward declaration
    span: Span,
};

/// var name: type = value
/// let name: type = value (alias for var)
pub const VarDecl = struct {
    name: []const u8,
    type_expr: ?NodeIndex, // null = inferred
    value: ?NodeIndex, // null = uninitialized
    span: Span,
};

/// const name: type = value
pub const ConstDecl = struct {
    name: []const u8,
    type_expr: ?NodeIndex,
    value: NodeIndex, // const must have value
    span: Span,
};

/// struct { fields }
pub const StructDecl = struct {
    name: []const u8,
    fields: []const Field,
    span: Span,
};

/// enum Name { variants } or enum Name: BackingType { variants }
pub const EnumDecl = struct {
    name: []const u8,
    backing_type: ?NodeIndex, // optional backing type like u8, i32
    variants: []const EnumVariant,
    span: Span,
};

/// Placeholder for malformed declaration
pub const BadDecl = struct {
    span: Span,
};

/// Field in struct or function parameter
pub const Field = struct {
    name: []const u8,
    type_expr: NodeIndex,
    span: Span,
};

/// Enum variant
pub const EnumVariant = struct {
    name: []const u8,
    value: ?NodeIndex, // explicit value
    span: Span,
};

/// union Name { variants } - Tagged union declaration
pub const UnionDecl = struct {
    name: []const u8,
    variants: []const UnionVariant,
    span: Span,
};

/// Union variant: name: Type or name (no payload)
pub const UnionVariant = struct {
    name: []const u8,
    type_expr: ?NodeIndex, // null = no payload (unit variant)
    span: Span,
};

// ============================================================================
// Expressions
// ============================================================================

pub const Expr = union(enum) {
    identifier: Identifier,
    literal: Literal,
    binary: Binary,
    unary: Unary,
    call: Call,
    index: Index,
    slice_expr: SliceExpr,
    field_access: FieldAccess,
    array_literal: ArrayLiteral,
    paren: Paren,
    if_expr: IfExpr,
    switch_expr: SwitchExpr,
    block: Block,
    struct_init: StructInit,
    // Heap allocation: new Map<K,V>(), new List<T>()
    new_expr: NewExpr,
    // Type expressions
    type_expr: TypeExpr,
    // For error recovery
    bad_expr: BadExpr,

    pub fn span(self: Expr) Span {
        return switch (self) {
            .identifier => |e| e.span,
            .literal => |e| e.span,
            .binary => |e| e.span,
            .unary => |e| e.span,
            .call => |e| e.span,
            .index => |e| e.span,
            .slice_expr => |e| e.span,
            .field_access => |e| e.span,
            .array_literal => |e| e.span,
            .paren => |e| e.span,
            .if_expr => |e| e.span,
            .switch_expr => |e| e.span,
            .block => |e| e.span,
            .struct_init => |e| e.span,
            .new_expr => |e| e.span,
            .type_expr => |e| e.span,
            .bad_expr => |e| e.span,
        };
    }
};

/// Variable or type name
pub const Identifier = struct {
    name: []const u8,
    span: Span,
};

/// Literal value (int, float, string, char, bool)
pub const Literal = struct {
    kind: LiteralKind,
    value: []const u8, // raw text
    span: Span,
};

pub const LiteralKind = enum {
    int,
    float,
    string,
    char,
    true_lit,
    false_lit,
    null_lit,
};

/// Binary operation (x op y)
pub const Binary = struct {
    op: Token,
    left: NodeIndex,
    right: NodeIndex,
    span: Span,
};

/// Unary operation (op x)
pub const Unary = struct {
    op: Token,
    operand: NodeIndex,
    span: Span,
};

/// Function call (callee(args))
pub const Call = struct {
    callee: NodeIndex,
    args: []const NodeIndex,
    span: Span,
};

/// Index expression (base[index])
pub const Index = struct {
    base: NodeIndex,
    index: NodeIndex,
    span: Span,
};

/// Slice expression (base[start:end])
/// Creates a slice from an array or another slice.
/// Either start or end can be null_node for default bounds.
pub const SliceExpr = struct {
    base: NodeIndex,
    start: NodeIndex, // null_node = from beginning
    end: NodeIndex, // null_node = to end
    span: Span,
};

/// Field access (base.field)
pub const FieldAccess = struct {
    base: NodeIndex,
    field: []const u8,
    span: Span,
};

/// Array literal ([elem1, elem2, ...])
pub const ArrayLiteral = struct {
    elements: []const NodeIndex,
    span: Span,
};

/// Parenthesized expression
pub const Paren = struct {
    inner: NodeIndex,
    span: Span,
};

/// If expression (if cond then_expr else else_expr)
pub const IfExpr = struct {
    condition: NodeIndex,
    then_branch: NodeIndex,
    else_branch: ?NodeIndex,
    span: Span,
};

/// Switch expression
/// switch value { .a => x, .b, .c => y, else => z }
/// With payload capture: switch u { .ok |val| => val, .err |e| => 0 }
pub const SwitchExpr = struct {
    subject: NodeIndex, // value being switched on
    cases: []const SwitchCase, // case arms
    else_body: ?NodeIndex, // else => body (optional)
    span: Span,
};

/// A single switch case arm
pub const SwitchCase = struct {
    values: []const NodeIndex, // can match multiple values: .a, .b => ...
    body: NodeIndex, // expression or block
    capture: ?[]const u8, // optional payload capture: .ok |val| => ...
    span: Span,
};

/// Block expression { stmts; expr }
pub const Block = struct {
    stmts: []const NodeIndex,
    /// Final expression (value of block), or null_node
    expr: NodeIndex,
    span: Span,
};

/// Struct initialization: Point{.x = 10, .y = 20}
pub const StructInit = struct {
    /// Type name (e.g., "Point"), or empty for anonymous
    type_name: []const u8,
    /// Field initializers
    fields: []const FieldInit,
    span: Span,
};

/// Heap allocation expression: new Map<K,V>(), new List<T>()
pub const NewExpr = struct {
    /// The type being allocated (a type expression node)
    type_expr: NodeIndex,
    span: Span,
};

/// Field initializer: .field = value
pub const FieldInit = struct {
    name: []const u8,
    value: NodeIndex,
    span: Span,
};

/// Placeholder for malformed expression
pub const BadExpr = struct {
    span: Span,
};

// ============================================================================
// Type Expressions
// ============================================================================

pub const TypeExpr = struct {
    kind: TypeKind,
    span: Span,
};

pub const TypeKind = union(enum) {
    /// Named type (int, string, MyStruct, etc.)
    named: []const u8,
    /// Pointer type (*T)
    pointer: NodeIndex,
    /// Optional type (?T)
    optional: NodeIndex,
    /// Slice type ([]T)
    slice: NodeIndex,
    /// Array type ([N]T)
    array: struct {
        size: NodeIndex, // size expression
        elem: NodeIndex,
    },
    /// Function type (fn(params) ret)
    function: struct {
        params: []const NodeIndex,
        return_type: ?NodeIndex,
    },
    /// Map type (Map<K, V>)
    map: struct {
        key: NodeIndex, // key type
        value: NodeIndex, // value type
    },
    /// List type (List<T>)
    list: NodeIndex, // element type
};

// ============================================================================
// Statements
// ============================================================================

pub const Stmt = union(enum) {
    expr_stmt: ExprStmt,
    return_stmt: ReturnStmt,
    var_stmt: VarStmt,
    assign_stmt: AssignStmt,
    if_stmt: IfStmt,
    while_stmt: WhileStmt,
    for_stmt: ForStmt,
    block_stmt: BlockStmt,
    break_stmt: BreakStmt,
    continue_stmt: ContinueStmt,
    // For error recovery
    bad_stmt: BadStmt,

    pub fn span(self: Stmt) Span {
        return switch (self) {
            .expr_stmt => |s| s.span,
            .return_stmt => |s| s.span,
            .var_stmt => |s| s.span,
            .assign_stmt => |s| s.span,
            .if_stmt => |s| s.span,
            .while_stmt => |s| s.span,
            .for_stmt => |s| s.span,
            .block_stmt => |s| s.span,
            .break_stmt => |s| s.span,
            .continue_stmt => |s| s.span,
            .bad_stmt => |s| s.span,
        };
    }
};

/// Expression statement
pub const ExprStmt = struct {
    expr: NodeIndex,
    span: Span,
};

/// return expr
pub const ReturnStmt = struct {
    value: ?NodeIndex,
    span: Span,
};

/// var/let name: type = value (local variable)
pub const VarStmt = struct {
    name: []const u8,
    type_expr: ?NodeIndex,
    value: ?NodeIndex,
    is_const: bool,
    span: Span,
};

/// name = value, name += value, etc.
pub const AssignStmt = struct {
    target: NodeIndex,
    op: ?Token, // null = simple assign, else compound (+=, -=, etc.)
    value: NodeIndex,
    span: Span,
};

/// if condition { then } else { else }
pub const IfStmt = struct {
    condition: NodeIndex,
    then_branch: NodeIndex, // block
    else_branch: ?NodeIndex, // block or another if_stmt
    span: Span,
};

/// while condition { body }
pub const WhileStmt = struct {
    condition: NodeIndex,
    body: NodeIndex,
    span: Span,
};

/// for item in iterable { body }
pub const ForStmt = struct {
    binding: []const u8,
    iterable: NodeIndex,
    body: NodeIndex,
    span: Span,
};

/// { statements }
pub const BlockStmt = struct {
    stmts: []const NodeIndex,
    span: Span,
};

/// break
pub const BreakStmt = struct {
    span: Span,
};

/// continue
pub const ContinueStmt = struct {
    span: Span,
};

/// Placeholder for malformed statement
pub const BadStmt = struct {
    span: Span,
};

// ============================================================================
// Node Storage (Arena-based)
// ============================================================================

/// Unified node that can be any AST element.
/// This is what gets stored in the node pool.
pub const Node = union(enum) {
    decl: Decl,
    expr: Expr,
    stmt: Stmt,

    pub fn span(self: Node) Span {
        return switch (self) {
            .decl => |d| d.span(),
            .expr => |e| e.span(),
            .stmt => |s| s.span(),
        };
    }
};

/// Storage for all AST nodes.
/// Uses arena allocation for fast allocation and bulk deallocation.
pub const Ast = struct {
    /// All nodes in the tree
    nodes: std.ArrayList(Node),
    /// The allocator used
    allocator: std.mem.Allocator,
    /// Root file node
    file: ?File,

    pub fn init(allocator: std.mem.Allocator) Ast {
        return .{
            .nodes = std.ArrayList(Node){ .items = &.{}, .capacity = 0 },
            .allocator = allocator,
            .file = null,
        };
    }

    pub fn deinit(self: *Ast) void {
        self.nodes.deinit(self.allocator);
    }

    /// Add a node and return its index.
    pub fn addNode(self: *Ast, node: Node) !NodeIndex {
        const idx: NodeIndex = @intCast(self.nodes.items.len);
        try self.nodes.append(self.allocator, node);
        return idx;
    }

    /// Get a node by index.
    pub fn getNode(self: *const Ast, idx: NodeIndex) Node {
        if (idx == null_node) {
            // Return a bad node for null indices
            return .{ .expr = .{ .bad_expr = .{ .span = Span.fromPos(Pos.zero) } } };
        }
        return self.nodes.items[idx];
    }

    /// Get a node as an expression.
    pub fn getExpr(self: *const Ast, idx: NodeIndex) ?Expr {
        if (idx == null_node) return null;
        const node = self.nodes.items[idx];
        return switch (node) {
            .expr => |e| e,
            else => null,
        };
    }

    /// Get a node as a statement.
    pub fn getStmt(self: *const Ast, idx: NodeIndex) ?Stmt {
        if (idx == null_node) return null;
        const node = self.nodes.items[idx];
        return switch (node) {
            .stmt => |s| s,
            else => null,
        };
    }

    /// Get a node as a declaration.
    pub fn getDecl(self: *const Ast, idx: NodeIndex) ?Decl {
        if (idx == null_node) return null;
        const node = self.nodes.items[idx];
        return switch (node) {
            .decl => |d| d,
            else => null,
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ast basic creation" {
    var ast = Ast.init(std.testing.allocator);
    defer ast.deinit();

    // Create an identifier expression
    const span = Span.init(Pos{ .offset = 0 }, Pos{ .offset = 4 });
    const idx = try ast.addNode(.{
        .expr = .{
            .identifier = .{
                .name = "test",
                .span = span,
            },
        },
    });

    try std.testing.expectEqual(@as(NodeIndex, 0), idx);

    const node = ast.getNode(idx);
    try std.testing.expect(node == .expr);
}

test "ast literal node" {
    var ast = Ast.init(std.testing.allocator);
    defer ast.deinit();

    const span = Span.init(Pos{ .offset = 0 }, Pos{ .offset = 2 });
    const idx = try ast.addNode(.{
        .expr = .{
            .literal = .{
                .kind = .int,
                .value = "42",
                .span = span,
            },
        },
    });

    const expr = ast.getExpr(idx);
    try std.testing.expect(expr != null);
    try std.testing.expect(expr.? == .literal);
    try std.testing.expectEqualStrings("42", expr.?.literal.value);
}

test "ast binary expression" {
    var ast = Ast.init(std.testing.allocator);
    defer ast.deinit();

    const span = Span.init(Pos{ .offset = 0 }, Pos{ .offset = 5 });

    // Create left operand (1)
    const left = try ast.addNode(.{
        .expr = .{
            .literal = .{
                .kind = .int,
                .value = "1",
                .span = span,
            },
        },
    });

    // Create right operand (2)
    const right = try ast.addNode(.{
        .expr = .{
            .literal = .{
                .kind = .int,
                .value = "2",
                .span = span,
            },
        },
    });

    // Create binary expression (1 + 2)
    const binary = try ast.addNode(.{
        .expr = .{
            .binary = .{
                .op = .plus,
                .left = left,
                .right = right,
                .span = span,
            },
        },
    });

    const expr = ast.getExpr(binary);
    try std.testing.expect(expr != null);
    try std.testing.expect(expr.? == .binary);
    try std.testing.expectEqual(Token.plus, expr.?.binary.op);
}

test "ast null node handling" {
    var ast = Ast.init(std.testing.allocator);
    defer ast.deinit();

    // Getting null_node should return a bad node, not crash
    const node = ast.getNode(null_node);
    try std.testing.expect(node == .expr);
    try std.testing.expect(node.expr == .bad_expr);

    // getExpr/getStmt/getDecl should return null for null_node
    try std.testing.expect(ast.getExpr(null_node) == null);
    try std.testing.expect(ast.getStmt(null_node) == null);
    try std.testing.expect(ast.getDecl(null_node) == null);
}
