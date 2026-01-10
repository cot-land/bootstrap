///! AST-to-IR lowering pass.
///!
///! Inspired by:
///! - Go: cmd/compile/internal/noder (two-pass, type-annotated lowering)
///! - Zig: src/Sema.zig (dense instruction mapping, block scoping)
///! - Roc: crates/compiler/mono/src/ir.rs (recursive descent, continuations)
///!
///! Transforms type-checked AST into flat IR suitable for SSA construction.

const std = @import("std");
const ast = @import("ast.zig");
const ir = @import("ir.zig");
const types = @import("types.zig");
const source = @import("source.zig");
const errors = @import("errors.zig");
const debug = @import("debug.zig");

const Allocator = std.mem.Allocator;
const Ast = ast.Ast;
const NodeIndex = ast.NodeIndex;
const TypeIndex = types.TypeIndex;
const TypeRegistry = types.TypeRegistry;
const Span = source.Span;
const Pos = source.Pos;
const ErrorReporter = errors.ErrorReporter;

// Scoped logger
const log = debug.scoped(.ir);

// ============================================================================
// Lowerer Context
// ============================================================================

pub const Lowerer = struct {
    allocator: Allocator,
    tree: *const Ast,
    type_reg: *TypeRegistry,
    err: *ErrorReporter,
    builder: ir.Builder,

    // Current function context (like Go's Curfn)
    current_func: ?*ir.FuncBuilder = null,

    pub fn init(
        allocator: Allocator,
        tree: *const Ast,
        type_reg: *TypeRegistry,
        err: *ErrorReporter,
    ) Lowerer {
        return .{
            .allocator = allocator,
            .tree = tree,
            .type_reg = type_reg,
            .err = err,
            .builder = ir.Builder.init(allocator, type_reg),
        };
    }

    pub fn deinit(self: *Lowerer) void {
        _ = self;
        // Builder owns its memory
    }

    /// Lower entire AST to IR.
    pub fn lower(self: *Lowerer) !ir.IR {
        log.debug("lowering AST to IR", .{});

        // Process all declarations from the file
        if (self.tree.file) |file| {
            for (file.decls) |decl_idx| {
                try self.lowerDecl(decl_idx);
            }
        }

        return self.builder.getIR();
    }

    // ========================================================================
    // Declaration Lowering
    // ========================================================================

    fn lowerDecl(self: *Lowerer, idx: NodeIndex) !void {
        const decl = self.tree.getDecl(idx) orelse return;

        switch (decl) {
            .fn_decl => |fn_decl| try self.lowerFnDecl(fn_decl, idx),
            .var_decl => |var_decl| try self.lowerVarDecl(var_decl, true),
            .const_decl => |const_decl| try self.lowerConstDecl(const_decl),
            .struct_decl => |struct_decl| try self.lowerStructDecl(struct_decl),
            .enum_decl => {},
            .bad_decl => {},  // Skip invalid declarations
        }
    }

    fn lowerFnDecl(self: *Lowerer, fn_decl: ast.FnDecl, _: NodeIndex) !void {
        const name = fn_decl.name;
        const return_type = fn_decl.return_type orelse TypeRegistry.VOID;
        const span = fn_decl.span;

        log.debug("lowering function: {s}", .{name});

        // Start building function
        self.builder.startFunc(name, TypeRegistry.VOID, return_type, span);

        // Get the function builder
        if (self.builder.current_func) |*fb| {
            self.current_func = fb;

            // Add parameters
            for (fn_decl.params) |param| {
                const param_type = param.type_expr;
                _ = try fb.addParam(param.name, param_type);
                log.debug("  param: {s}", .{param.name});
            }

            // Lower function body
            if (fn_decl.body) |body_idx| {
                log.debug("  lowering body block {d}", .{body_idx});
                _ = try self.lowerBlock(body_idx);
            } else {
                log.debug("  no body (forward declaration)", .{});
            }

            self.current_func = null;
        }

        // Finish function
        try self.builder.endFunc();
    }

    fn lowerVarDecl(self: *Lowerer, var_decl: ast.VarDecl, is_global: bool) !void {
        if (is_global) {
            // Global variable (var declarations are mutable)
            const span = Span.fromPos(Pos.zero);
            const global = ir.Global.init(
                var_decl.name,
                var_decl.type_expr orelse TypeRegistry.VOID,
                false,  // not const (mutable)
                span,
            );
            try self.builder.addGlobal(global);
            log.debug("global var: {s}", .{var_decl.name});
        } else if (self.current_func) |fb| {
            // Local variable
            const type_idx = var_decl.type_expr orelse TypeRegistry.VOID;
            const size = self.type_reg.sizeOf(type_idx);
            const local_idx = try fb.addLocalWithSize(var_decl.name, type_idx, true, size);  // var = mutable

            // If there's an initializer, emit store
            if (var_decl.value) |value_idx| {
                const value_node = try self.lowerExpr(value_idx);
                const store = ir.Node.init(.store, type_idx, Span.fromPos(Pos.zero))
                    .withArgs(&.{ @intCast(local_idx), value_node });
                _ = try fb.emit(store);
            }

            log.debug("  local var: {s} size={d}", .{ var_decl.name, size });
        }
    }

    fn lowerVarStmt(self: *Lowerer, var_stmt: ast.VarStmt) !void {
        const fb = self.current_func orelse return;

        // Infer type from initializer expression
        var type_idx: TypeIndex = TypeRegistry.VOID;
        if (var_stmt.value) |value_idx| {
            type_idx = self.inferTypeFromExpr(value_idx);
        }

        const is_mutable = !var_stmt.is_const;
        const size = self.type_reg.sizeOf(type_idx);
        const local_idx = try fb.addLocalWithSize(var_stmt.name, type_idx, is_mutable, size);
        log.debug("  local var: {s} type={d} size={d}", .{ var_stmt.name, type_idx, size });

        // If there's an initializer, check if it's a struct init or array literal
        if (var_stmt.value) |value_idx| {
            const value_node = self.tree.getNode(value_idx);
            if (value_node == .expr and value_node.expr == .struct_init) {
                // Handle struct init inline - store each field
                try self.lowerStructInitInline(value_node.expr.struct_init, local_idx);
            } else if (value_node == .expr and value_node.expr == .array_literal) {
                // Handle array literal inline - store each element
                try self.lowerArrayLiteralInline(value_node.expr.array_literal, local_idx);
            } else {
                // Regular expression - lower and store
                const value_ir_node = try self.lowerExpr(value_idx);
                const store = ir.Node.init(.store, type_idx, Span.fromPos(Pos.zero))
                    .withArgs(&.{ @intCast(local_idx), value_ir_node });
                _ = try fb.emit(store);
            }
        }

        log.debug("  local var: {s}", .{var_stmt.name});
    }

    /// Lower struct init directly to field stores
    fn lowerStructInitInline(self: *Lowerer, si: ast.StructInit, local_idx: usize) !void {
        const fb = self.current_func orelse return;

        // Get struct type to find field offsets
        const struct_type_idx = self.type_reg.lookupByName(si.type_name) orelse return;
        const t = self.type_reg.get(struct_type_idx);
        const st = switch (t) {
            .struct_type => |s| s,
            else => return,
        };

        // For each field initializer, emit a store at the field offset
        for (si.fields) |field_init| {
            // Find field offset
            var field_offset: u32 = 0;
            var field_type_idx: TypeIndex = TypeRegistry.VOID;
            for (st.fields) |f| {
                if (std.mem.eql(u8, f.name, field_init.name)) {
                    field_offset = f.offset;
                    field_type_idx = f.type_idx;
                    break;
                }
            }

            // Lower the field value
            const value_node = try self.lowerExpr(field_init.value);

            // Emit store_field: store value at local[offset]
            const store = ir.Node.init(.store, field_type_idx, Span.fromPos(Pos.zero))
                .withArgs(&.{ @intCast(local_idx), value_node })
                .withAux(@intCast(field_offset));
            _ = try fb.emit(store);

            log.debug("  struct field store: .{s} at offset {d}", .{ field_init.name, field_offset });
        }
    }

    /// Lower array literal directly to element stores
    fn lowerArrayLiteralInline(self: *Lowerer, al: ast.ArrayLiteral, local_idx: usize) !void {
        const fb = self.current_func orelse return;

        // Each element is stored at offset = index * 8 (64-bit integers)
        const elem_size: u32 = 8;

        for (al.elements, 0..) |elem_idx, i| {
            // Lower the element value
            const value_node = try self.lowerExpr(elem_idx);

            // Compute element offset
            const offset: u32 = @intCast(i * elem_size);

            // Emit store: store value at local[offset]
            const store = ir.Node.init(.store, TypeRegistry.INT, Span.fromPos(Pos.zero))
                .withArgs(&.{ @intCast(local_idx), value_node })
                .withAux(@intCast(offset));
            _ = try fb.emit(store);

            log.debug("  array element store: [{d}] at offset {d}", .{ i, offset });
        }
    }

    fn lowerConstDecl(self: *Lowerer, const_decl: ast.ConstDecl) !void {
        // Constants are similar to immutable globals
        const span = Span.fromPos(Pos.zero);
        const global = ir.Global.init(
            const_decl.name,
            const_decl.type_expr orelse TypeRegistry.VOID,
            true, // is_const
            span,
        );
        try self.builder.addGlobal(global);
        log.debug("const: {s}", .{const_decl.name});
    }

    fn lowerStructDecl(self: *Lowerer, struct_decl: ast.StructDecl) !void {
        // Struct fields are already stored in the TypeRegistry.
        // Just register the struct def with its name.
        const struct_def = ir.StructDef{
            .name = struct_decl.name,
            .type_idx = TypeRegistry.VOID,  // Struct type index from type checker
            .span = struct_decl.span,
        };
        try self.builder.addStruct(struct_def);
        log.debug("struct: {s}", .{struct_decl.name});
    }

    // ========================================================================
    // Statement Lowering
    // ========================================================================

    /// Lower a block, returning true if it ends with a terminator (return/break/continue)
    fn lowerBlock(self: *Lowerer, idx: NodeIndex) Allocator.Error!bool {
        const node = self.tree.getNode(idx);
        log.debug("  lowerBlock: node type {s}", .{@tagName(node)});
        var terminated = false;
        switch (node) {
            .stmt => |stmt| {
                log.debug("  stmt type: {s}", .{@tagName(stmt)});
                switch (stmt) {
                    .block_stmt => |block| {
                        log.debug("  block_stmt has {d} statements", .{block.stmts.len});
                        for (block.stmts) |stmt_idx| {
                            try self.lowerStmt(stmt_idx);
                            // Check if this was a terminating statement
                            const stmt_node = self.tree.getNode(stmt_idx);
                            if (stmt_node == .stmt) {
                                switch (stmt_node.stmt) {
                                    .return_stmt => terminated = true,
                                    .break_stmt, .continue_stmt => terminated = true,
                                    else => {},
                                }
                            }
                        }
                    },
                    .return_stmt => {
                        log.debug("  not a block_stmt, lowering as stmt", .{});
                        try self.lowerStmt(idx);
                        terminated = true;
                    },
                    else => {
                        log.debug("  not a block_stmt, lowering as stmt", .{});
                        try self.lowerStmt(idx);
                    },
                }
            },
            .expr => |expr| {
                // Handle block expressions (used for function bodies)
                log.debug("  expr type: {s}", .{@tagName(expr)});
                switch (expr) {
                    .block => |block| {
                        log.debug("  block expr has {d} statements", .{block.stmts.len});
                        for (block.stmts) |stmt_idx| {
                            try self.lowerStmt(stmt_idx);
                            // Check if this was a terminating statement
                            const stmt_node = self.tree.getNode(stmt_idx);
                            if (stmt_node == .stmt) {
                                switch (stmt_node.stmt) {
                                    .return_stmt => terminated = true,
                                    .break_stmt, .continue_stmt => terminated = true,
                                    else => {},
                                }
                            }
                        }
                    },
                    else => {
                        log.debug("  not a block expr, lowering as expr", .{});
                        _ = try self.lowerExpr(idx);
                    },
                }
            },
            else => {
                log.debug("  unexpected node type, skipping", .{});
            },
        }
        return terminated;
    }

    fn lowerStmt(self: *Lowerer, idx: NodeIndex) Allocator.Error!void {
        const node = self.tree.getNode(idx);
        const stmt = switch (node) {
            .stmt => |s| s,
            else => return,
        };

        switch (stmt) {
            .expr_stmt => |expr_stmt| {
                // Expression statement - evaluate for side effects
                _ = try self.lowerExpr(expr_stmt.expr);
            },
            .return_stmt => |ret| {
                try self.lowerReturn(ret);
            },
            .var_stmt => |var_stmt| {
                try self.lowerVarStmt(var_stmt);
            },
            .assign_stmt => |assign| {
                try self.lowerAssign(assign);
            },
            .if_stmt => |if_stmt| {
                try self.lowerIf(if_stmt);
            },
            .while_stmt => |while_stmt| {
                try self.lowerWhile(while_stmt);
            },
            .for_stmt => |for_stmt| {
                try self.lowerFor(for_stmt);
            },
            .block_stmt => |block| {
                for (block.stmts) |stmt_idx| {
                    try self.lowerStmt(stmt_idx);
                }
            },
            .break_stmt => {
                try self.lowerBreak();
            },
            .continue_stmt => {
                try self.lowerContinue();
            },
            .bad_stmt => {},  // Skip invalid statements
        }
    }

    fn lowerReturn(self: *Lowerer, ret: ast.ReturnStmt) Allocator.Error!void {
        const fb = self.current_func orelse return;

        if (ret.value) |value_idx| {
            const value_node = try self.lowerExpr(value_idx);
            const ret_node = ir.Node.init(.ret, fb.return_type, Span.fromPos(Pos.zero))
                .withArgs(&.{value_node});
            _ = try fb.emit(ret_node);
            log.debug("  return <expr>", .{});
        } else {
            const ret_node = ir.Node.init(.ret, TypeRegistry.VOID, Span.fromPos(Pos.zero));
            _ = try fb.emit(ret_node);
            log.debug("  return void", .{});
        }
    }

    fn lowerAssign(self: *Lowerer, assign: ast.AssignStmt) Allocator.Error!void {
        const fb = self.current_func orelse return;

        // Get target (must be an identifier for now)
        const target_node = self.tree.getNode(assign.target);
        switch (target_node) {
            .expr => |expr| {
                switch (expr) {
                    .identifier => |ident| {
                        const name = ident.name;
                        if (fb.lookupLocal(name)) |local_idx| {
                            const value_node = try self.lowerExpr(assign.value);
                            const local_type = fb.locals.items[local_idx].type_idx;
                            const store = ir.Node.init(.store, local_type, Span.fromPos(Pos.zero))
                                .withArgs(&.{ @intCast(local_idx), value_node });
                            _ = try fb.emit(store);
                            log.debug("  assign: {s}", .{name});
                        }
                    },
                    else => {},
                }
            },
            else => {},
        }
    }

    fn lowerIf(self: *Lowerer, if_stmt: ast.IfStmt) Allocator.Error!void {
        const fb = self.current_func orelse return;

        // Lower condition
        const cond_node = try self.lowerExpr(if_stmt.condition);

        // Create blocks for then, else, and merge
        const then_block = try fb.newBlock("if.then");
        const else_block = if (if_stmt.else_branch != null)
            try fb.newBlock("if.else")
        else
            null;
        const merge_block = try fb.newBlock("if.merge");

        // Emit branch
        const branch = ir.Node.init(.branch, TypeRegistry.VOID, Span.fromPos(Pos.zero))
            .withArgs(&.{ cond_node, then_block, else_block orelse merge_block });
        _ = try fb.emit(branch);

        // Lower then block
        fb.setBlock(then_block);
        const then_terminated = try self.lowerBlock(if_stmt.then_branch);
        // Only emit jump to merge if block didn't terminate (with return/break/continue)
        if (!then_terminated) {
            const jump_merge = ir.Node.init(.jump, TypeRegistry.VOID, Span.fromPos(Pos.zero))
                .withAux(@intCast(merge_block));
            _ = try fb.emit(jump_merge);
        }

        // Lower else block if present
        if (if_stmt.else_branch) |else_branch| {
            fb.setBlock(else_block.?);
            const else_terminated = try self.lowerBlock(else_branch);
            // Only emit jump to merge if block didn't terminate
            if (!else_terminated) {
                const jump_merge2 = ir.Node.init(.jump, TypeRegistry.VOID, Span.fromPos(Pos.zero))
                    .withAux(@intCast(merge_block));
                _ = try fb.emit(jump_merge2);
            }
        }

        // Continue in merge block
        fb.setBlock(merge_block);
        log.debug("  if statement", .{});
    }

    fn lowerWhile(self: *Lowerer, while_stmt: ast.WhileStmt) Allocator.Error!void {
        const fb = self.current_func orelse return;

        // Create blocks for condition, body, and exit
        const cond_block = try fb.newBlock("while.cond");
        const body_block = try fb.newBlock("while.body");
        const exit_block = try fb.newBlock("while.exit");

        // Jump to condition block (target stored in aux)
        const jump_cond = ir.Node.init(.jump, TypeRegistry.VOID, Span.fromPos(Pos.zero))
            .withAux(@intCast(cond_block));
        _ = try fb.emit(jump_cond);

        // Condition block
        fb.setBlock(cond_block);
        const cond_node = try self.lowerExpr(while_stmt.condition);
        const branch = ir.Node.init(.branch, TypeRegistry.VOID, Span.fromPos(Pos.zero))
            .withArgs(&.{ cond_node, body_block, exit_block });
        _ = try fb.emit(branch);

        // Body block
        fb.setBlock(body_block);
        const body_terminated = try self.lowerBlock(while_stmt.body);
        // Only emit jump back to condition if body didn't terminate
        if (!body_terminated) {
            const jump_back = ir.Node.init(.jump, TypeRegistry.VOID, Span.fromPos(Pos.zero))
                .withAux(@intCast(cond_block));
            _ = try fb.emit(jump_back);
        }

        // Continue in exit block
        fb.setBlock(exit_block);
        log.debug("  while loop", .{});
    }

    fn lowerFor(self: *Lowerer, for_stmt: ast.ForStmt) Allocator.Error!void {
        // Desugar for-in to while loop
        // TODO: Implement proper for-in lowering
        _ = self;
        _ = for_stmt;
        log.debug("  for loop (TODO)", .{});
    }

    fn lowerBreak(self: *Lowerer) Allocator.Error!void {
        // TODO: Need to track loop exit blocks
        _ = self;
        log.debug("  break (TODO)", .{});
    }

    fn lowerContinue(self: *Lowerer) Allocator.Error!void {
        // TODO: Need to track loop condition blocks
        _ = self;
        log.debug("  continue (TODO)", .{});
    }

    // ========================================================================
    // Expression Lowering
    // ========================================================================

    fn lowerExpr(self: *Lowerer, idx: NodeIndex) Allocator.Error!ir.NodeIndex {
        const node = self.tree.getNode(idx);
        const expr = switch (node) {
            .expr => |e| e,
            else => return ir.null_node,
        };

        return switch (expr) {
            .identifier => |ident| self.lowerIdentifier(ident),
            .literal => |lit| self.lowerLiteral(lit),
            .binary => |bin| self.lowerBinary(bin),
            .unary => |un| self.lowerUnary(un),
            .call => |call| self.lowerCall(call),
            .index => |index| self.lowerIndex(index),
            .slice_expr => |se| self.lowerSliceExpr(se),
            .field_access => |field| self.lowerFieldAccess(field),
            .array_literal => |al| self.lowerArrayLiteral(al),
            .if_expr => |if_expr| self.lowerIfExpr(if_expr),
            .paren => |paren| self.lowerExpr(paren.inner),
            .struct_init => |si| self.lowerStructInit(si),
            .block => ir.null_node,  // Block expressions not yet implemented
            .type_expr => ir.null_node,  // Type expressions don't produce runtime values
            .bad_expr => ir.null_node,  // Skip invalid expressions
        };
    }

    fn lowerIdentifier(self: *Lowerer, ident: ast.Identifier) Allocator.Error!ir.NodeIndex {
        const fb = self.current_func orelse return ir.null_node;

        if (fb.lookupLocal(ident.name)) |local_idx| {
            const local = fb.locals.items[local_idx];
            const load = ir.Node.init(.load, local.type_idx, Span.fromPos(Pos.zero))
                .withAux(@intCast(local_idx));
            return try fb.emit(load);
        }

        // TODO: Check globals
        return ir.null_node;
    }

    fn lowerLiteral(self: *Lowerer, lit: ast.Literal) Allocator.Error!ir.NodeIndex {
        const fb = self.current_func orelse return ir.null_node;

        return switch (lit.kind) {
            .int => {
                const value = std.fmt.parseInt(i64, lit.value, 10) catch 0;
                const node = ir.Node.init(.const_int, TypeRegistry.INT, Span.fromPos(Pos.zero))
                    .withAux(value);
                log.debug("  const_int: {d}", .{value});
                return try fb.emit(node);
            },
            .float => {
                const node = ir.Node.init(.const_float, TypeRegistry.FLOAT, Span.fromPos(Pos.zero));
                return try fb.emit(node);
            },
            .string => {
                // Strip quotes from string literal: "hello" -> hello
                const raw = lit.value;
                const stripped = if (raw.len >= 2 and raw[0] == '"' and raw[raw.len - 1] == '"')
                    raw[1 .. raw.len - 1]
                else
                    raw;
                const node = ir.Node.init(.const_string, TypeRegistry.STRING, Span.fromPos(Pos.zero))
                    .withAuxStr(stripped);
                return try fb.emit(node);
            },
            .char => {
                const value: i64 = if (lit.value.len > 0) @intCast(lit.value[0]) else 0;
                const node = ir.Node.init(.const_int, TypeRegistry.I32, Span.fromPos(Pos.zero))
                    .withAux(value);
                return try fb.emit(node);
            },
            .true_lit => {
                const node = ir.Node.init(.const_bool, TypeRegistry.BOOL, Span.fromPos(Pos.zero))
                    .withAux(1);
                return try fb.emit(node);
            },
            .false_lit => {
                const node = ir.Node.init(.const_bool, TypeRegistry.BOOL, Span.fromPos(Pos.zero))
                    .withAux(0);
                return try fb.emit(node);
            },
            .null_lit => {
                const node = ir.Node.init(.const_null, TypeRegistry.VOID, Span.fromPos(Pos.zero));
                return try fb.emit(node);
            },
        };
    }

    fn lowerBinary(self: *Lowerer, bin: ast.Binary) Allocator.Error!ir.NodeIndex {
        const fb = self.current_func orelse return ir.null_node;

        // Check for string literal comparisons - constant fold them
        if (bin.op == .equal_equal or bin.op == .bang_equal) {
            if (try self.tryFoldStringComparison(bin)) |result| {
                return result;
            }
        }

        const left = try self.lowerExpr(bin.left);
        const right = try self.lowerExpr(bin.right);

        const op: ir.Op = switch (bin.op) {
            .plus => .add,
            .minus => .sub,
            .star => .mul,
            .slash => .div,
            .percent => .mod,
            .equal_equal => .eq,
            .bang_equal => .ne,
            .less => .lt,
            .less_equal => .le,
            .greater => .gt,
            .greater_equal => .ge,
            .kw_and => .@"and",
            .kw_or => .@"or",
            else => .add,
        };

        // Determine result type: comparisons return bool
        const result_type = switch (bin.op) {
            .equal_equal, .bang_equal, .less, .less_equal, .greater, .greater_equal => TypeRegistry.BOOL,
            else => TypeRegistry.INT,
        };
        const node = ir.Node.init(op, result_type, Span.fromPos(Pos.zero))
            .withArgs(&.{ left, right });

        return try fb.emit(node);
    }

    /// Try to constant-fold string literal comparison.
    /// Returns the result node if both operands are string literals, null otherwise.
    fn tryFoldStringComparison(self: *Lowerer, bin: ast.Binary) Allocator.Error!?ir.NodeIndex {
        const fb = self.current_func orelse return null;

        // Get left operand - must be string literal
        const left_node = self.tree.getNode(bin.left);
        const left_str = switch (left_node) {
            .expr => |expr| switch (expr) {
                .literal => |lit| if (lit.kind == .string) stripQuotes(lit.value) else return null,
                else => return null,
            },
            else => return null,
        };

        // Get right operand - must be string literal
        const right_node = self.tree.getNode(bin.right);
        const right_str = switch (right_node) {
            .expr => |expr| switch (expr) {
                .literal => |lit| if (lit.kind == .string) stripQuotes(lit.value) else return null,
                else => return null,
            },
            else => return null,
        };

        // Compare the strings
        const are_equal = std.mem.eql(u8, left_str, right_str);
        const result: i64 = switch (bin.op) {
            .equal_equal => if (are_equal) 1 else 0,
            .bang_equal => if (are_equal) 0 else 1,
            else => return null,
        };

        log.debug("  string comparison constant folded: \"{s}\" vs \"{s}\" = {d}", .{ left_str, right_str, result });

        const node = ir.Node.init(.const_bool, TypeRegistry.BOOL, Span.fromPos(Pos.zero))
            .withAux(result);
        return try fb.emit(node);
    }

    /// Helper to strip quotes from a string literal
    fn stripQuotes(raw: []const u8) []const u8 {
        if (raw.len >= 2 and raw[0] == '"' and raw[raw.len - 1] == '"') {
            return raw[1 .. raw.len - 1];
        }
        return raw;
    }

    fn lowerUnary(self: *Lowerer, un: ast.Unary) Allocator.Error!ir.NodeIndex {
        const fb = self.current_func orelse return ir.null_node;

        const operand = try self.lowerExpr(un.operand);

        const op: ir.Op = switch (un.op) {
            .minus => .neg,
            .bang => .not,
            else => .neg,
        };

        const result_type = TypeRegistry.INT;
        const node = ir.Node.init(op, result_type, Span.fromPos(Pos.zero))
            .withArgs(&.{operand});

        return try fb.emit(node);
    }

    fn lowerCall(self: *Lowerer, call: ast.Call) Allocator.Error!ir.NodeIndex {
        const fb = self.current_func orelse return ir.null_node;

        // Get callee name first to check for builtins
        const callee_node = self.tree.getNode(call.callee);
        var func_name: []const u8 = "unknown";
        switch (callee_node) {
            .expr => |expr| {
                switch (expr) {
                    .identifier => |ident| {
                        func_name = ident.name;
                    },
                    else => {},
                }
            },
            else => {},
        }

        // Handle builtin len()
        if (std.mem.eql(u8, func_name, "len")) {
            return self.lowerBuiltinLen(call);
        }

        // Lower arguments for regular call
        var args = std.ArrayList(ir.NodeIndex){ .items = &.{}, .capacity = 0 };
        defer args.deinit(self.allocator);

        for (call.args) |arg_idx| {
            const arg_node = try self.lowerExpr(arg_idx);
            try args.append(self.allocator, arg_node);
        }

        const node = ir.Node.init(.call, TypeRegistry.VOID, Span.fromPos(Pos.zero))
            .withArgs(try self.allocator.dupe(ir.NodeIndex, args.items))
            .withAuxStr(func_name);

        log.debug("  call: {s}", .{func_name});
        return try fb.emit(node);
    }

    fn lowerBuiltinLen(self: *Lowerer, call: ast.Call) Allocator.Error!ir.NodeIndex {
        const fb = self.current_func orelse return ir.null_node;

        if (call.args.len != 1) return ir.null_node;

        // Check if argument is a constant expression we can fold
        const arg_node = self.tree.getNode(call.args[0]);
        switch (arg_node) {
            .expr => |expr| {
                switch (expr) {
                    .literal => |lit| {
                        if (lit.kind == .string) {
                            // Strip quotes and get length
                            const raw = lit.value;
                            const stripped = if (raw.len >= 2 and raw[0] == '"' and raw[raw.len - 1] == '"')
                                raw[1 .. raw.len - 1]
                            else
                                raw;
                            // Return constant with string length
                            const node = ir.Node.init(.const_int, TypeRegistry.INT, Span.fromPos(Pos.zero))
                                .withAux(@intCast(stripped.len));
                            log.debug("  len() constant folded to {d}", .{stripped.len});
                            return try fb.emit(node);
                        }
                    },
                    .slice_expr => |se| {
                        // Try to constant fold slice length (end - start)
                        const start_val = self.tryGetConstInt(se.start);
                        const end_val = self.tryGetConstInt(se.end);
                        if (start_val != null and end_val != null) {
                            const len_val = end_val.? - start_val.?;
                            const node = ir.Node.init(.const_int, TypeRegistry.INT, Span.fromPos(Pos.zero))
                                .withAux(@intCast(len_val));
                            log.debug("  len(slice) constant folded to {d}", .{len_val});
                            return try fb.emit(node);
                        }
                    },
                    .array_literal => |al| {
                        // Array literal length is known at compile time
                        const node = ir.Node.init(.const_int, TypeRegistry.INT, Span.fromPos(Pos.zero))
                            .withAux(@intCast(al.elements.len));
                        log.debug("  len(array) constant folded to {d}", .{al.elements.len});
                        return try fb.emit(node);
                    },
                    .identifier => |ident| {
                        // Check if this is a slice or array variable
                        if (fb.lookupLocal(ident.name)) |local_idx| {
                            const local = fb.locals.items[local_idx];
                            const local_type = self.type_reg.get(local.type_idx);

                            switch (local_type) {
                                .slice => {
                                    // For slices, load len from offset 8 (ptr is at 0, len is at 8)
                                    // Emit field access: args[0] = local index, aux = 8 (len offset)
                                    const node = ir.Node.init(.field, TypeRegistry.INT, Span.fromPos(Pos.zero))
                                        .withArgs(&.{@as(ir.NodeIndex, @intCast(local_idx))})
                                        .withAux(8); // len is at offset 8
                                    log.debug("  len(slice var) runtime: local={d}, offset=8", .{local_idx});
                                    return try fb.emit(node);
                                },
                                .array => |a| {
                                    // Array length is known at compile time
                                    const node = ir.Node.init(.const_int, TypeRegistry.INT, Span.fromPos(Pos.zero))
                                        .withAux(@intCast(a.length));
                                    log.debug("  len(array var) constant folded to {d}", .{a.length});
                                    return try fb.emit(node);
                                },
                                else => {},
                            }
                        }
                    },
                    else => {},
                }
            },
            else => {},
        }

        // For non-constant expressions, we need runtime len support
        // For now, just lower the argument and emit a nop (TODO: proper runtime len)
        _ = try self.lowerExpr(call.args[0]);
        const node = ir.Node.init(.const_int, TypeRegistry.INT, Span.fromPos(Pos.zero))
            .withAux(0);  // Placeholder - runtime len not yet implemented
        log.debug("  len() runtime (not yet implemented)", .{});
        return try fb.emit(node);
    }

    /// Try to extract a constant integer from an expression.
    fn tryGetConstInt(self: *Lowerer, idx: ast.NodeIndex) ?i64 {
        if (idx == ast.null_node) return null;
        const node = self.tree.getNode(idx);
        switch (node) {
            .expr => |expr| {
                switch (expr) {
                    .literal => |lit| {
                        if (lit.kind == .int) {
                            return std.fmt.parseInt(i64, lit.value, 10) catch null;
                        }
                    },
                    else => {},
                }
            },
            else => {},
        }
        return null;
    }

    fn lowerIndex(self: *Lowerer, index: ast.Index) Allocator.Error!ir.NodeIndex {
        const fb = self.current_func orelse return ir.null_node;

        // Check if base is an identifier (local array variable)
        const base_node = self.tree.getNode(index.base);
        if (base_node == .expr and base_node.expr == .identifier) {
            const ident = base_node.expr.identifier;
            if (fb.lookupLocal(ident.name)) |local_idx| {
                const local = fb.locals.items[local_idx];

                // Check if local is an array type
                const local_type = self.type_reg.get(local.type_idx);
                if (local_type == .array) {
                    const arr = local_type.array;
                    const elem_size: u32 = 8; // 64-bit elements

                    // Check if index is a constant literal
                    const idx_ast_node = self.tree.getNode(index.index);
                    if (idx_ast_node == .expr and idx_ast_node.expr == .literal) {
                        const lit = idx_ast_node.expr.literal;
                        if (lit.kind == .int) {
                            // Constant index - compute offset at compile time
                            const idx_val = std.fmt.parseInt(u32, lit.value, 10) catch 0;
                            const offset = idx_val * elem_size;

                            // Emit addr_field with computed offset (reusing struct field access pattern)
                            const addr_node = ir.Node.init(.addr_field, arr.elem, Span.fromPos(Pos.zero))
                                .withArgs(&.{@intCast(local_idx)})
                                .withAux(@intCast(offset));
                            log.debug("  array index (const): [{d}] at offset {d}", .{ idx_val, offset });
                            return try fb.emit(addr_node);
                        }
                    }

                    // Dynamic index - emit addr_index op
                    // args[0] = local_idx, args[1] = index value, aux = elem_size
                    const idx_node = try self.lowerExpr(index.index);
                    const addr_node = ir.Node.init(.addr_index, arr.elem, Span.fromPos(Pos.zero))
                        .withArgs(&.{ @intCast(local_idx), idx_node })
                        .withAux(@intCast(elem_size));
                    log.debug("  array index (dynamic): elem_size={d}", .{elem_size});
                    return try fb.emit(addr_node);
                }
            }
        }

        // Fall back to generic index op for other cases
        const base = try self.lowerExpr(index.base);
        const idx = try self.lowerExpr(index.index);

        const node = ir.Node.init(.index, TypeRegistry.VOID, Span.fromPos(Pos.zero))
            .withArgs(&.{ base, idx });

        return try fb.emit(node);
    }

    fn lowerSliceExpr(self: *Lowerer, slice_expr: ast.SliceExpr) Allocator.Error!ir.NodeIndex {
        const fb = self.current_func orelse return ir.null_node;

        // Compute the slice result type from the base expression
        const base_type_idx = self.inferTypeFromExpr(slice_expr.base);
        const base_type = self.type_reg.get(base_type_idx);

        // Get element size for the slice
        const elem_size: u32 = switch (base_type) {
            .array => |a| self.type_reg.sizeOf(a.elem),
            .slice => |s| self.type_reg.sizeOf(s.elem),
            .basic => |k| if (k == .string_type) 1 else 0,
            else => 0,
        };

        const slice_type: TypeIndex = switch (base_type) {
            .array => |a| self.type_reg.makeSlice(a.elem) catch TypeRegistry.VOID,
            .slice => base_type_idx, // Slicing a slice returns same type
            .basic => |k| if (k == .string_type) self.type_reg.makeSlice(TypeRegistry.U8) catch TypeRegistry.VOID else TypeRegistry.VOID,
            else => TypeRegistry.VOID,
        };

        // Check if base is an identifier (local variable)
        const base_node = self.tree.getNode(slice_expr.base);
        if (base_node == .expr and base_node.expr == .identifier) {
            const ident = base_node.expr.identifier;
            if (fb.lookupLocal(ident.name)) |local_idx| {
                // Lower start index (default to 0 if not provided)
                var start: ir.NodeIndex = ir.null_node;
                if (slice_expr.start != ast.null_node) {
                    start = try self.lowerExpr(slice_expr.start);
                } else {
                    const zero_node = ir.Node.init(.const_int, TypeRegistry.INT, Span.fromPos(Pos.zero))
                        .withAux(0);
                    start = try fb.emit(zero_node);
                }

                // Lower end index (null_node means use length of base)
                var end: ir.NodeIndex = ir.null_node;
                if (slice_expr.end != ast.null_node) {
                    end = try self.lowerExpr(slice_expr.end);
                } else {
                    // Use array length as end
                    const arr_len: i64 = switch (base_type) {
                        .array => |a| @intCast(a.length),
                        else => 0,
                    };
                    const len_node = ir.Node.init(.const_int, TypeRegistry.INT, Span.fromPos(Pos.zero))
                        .withAux(arr_len);
                    end = try fb.emit(len_node);
                }

                // Emit slice op: args[0] = local_idx, args[1] = start, args[2] = end
                // aux = element size for pointer arithmetic
                const node = ir.Node.init(.slice, slice_type, slice_expr.span)
                    .withArgs(&.{ @as(ir.NodeIndex, @intCast(local_idx)), start, end })
                    .withAux(@intCast(elem_size));

                log.debug("  slice expr: local={d}, start node={d}, end node={d}, elem_size={d}", .{
                    local_idx, start, end, elem_size,
                });
                return try fb.emit(node);
            }
        }

        // Fallback for other cases (TODO: handle slicing slices, etc.)
        log.debug("  slice expr: fallback path (not fully implemented)", .{});
        const zero_node = ir.Node.init(.const_int, TypeRegistry.INT, Span.fromPos(Pos.zero))
            .withAux(0);
        return try fb.emit(zero_node);
    }

    fn lowerFieldAccess(self: *Lowerer, field: ast.FieldAccess) Allocator.Error!ir.NodeIndex {
        const fb = self.current_func orelse return ir.null_node;

        // Get the base expression to determine its type
        const base_node = self.tree.getNode(field.base);
        var base_type_idx: TypeIndex = TypeRegistry.VOID;

        // Check if base is an identifier (local variable)
        if (base_node == .expr) {
            switch (base_node.expr) {
                .identifier => |ident| {
                    if (fb.lookupLocal(ident.name)) |local_idx| {
                        base_type_idx = fb.locals.items[local_idx].type_idx;
                    }
                },
                else => {},
            }
        }

        // Look up struct type and find field offset
        const base_type = self.type_reg.get(base_type_idx);
        var field_offset: u32 = 0;
        var field_type_idx: TypeIndex = TypeRegistry.VOID;

        switch (base_type) {
            .struct_type => |st| {
                for (st.fields) |f| {
                    if (std.mem.eql(u8, f.name, field.field)) {
                        field_offset = f.offset;
                        field_type_idx = f.type_idx;
                        break;
                    }
                }
            },
            else => {},
        }

        log.debug("  field_access: .{s} at offset {d}", .{ field.field, field_offset });

        // Emit: addr_local for base, then load at offset
        const base_node_idx = self.tree.getNode(field.base);
        if (base_node_idx == .expr and base_node_idx.expr == .identifier) {
            const ident = base_node_idx.expr.identifier;
            if (fb.lookupLocal(ident.name)) |local_idx| {
                // Emit addr_field: get address of field within struct
                const addr_node = ir.Node.init(.addr_field, field_type_idx, Span.fromPos(Pos.zero))
                    .withArgs(&.{@intCast(local_idx)})
                    .withAux(@intCast(field_offset));
                return try fb.emit(addr_node);
            }
        }

        // Fallback: emit basic field op
        const base = try self.lowerExpr(field.base);
        const node = ir.Node.init(.field, field_type_idx, Span.fromPos(Pos.zero))
            .withArgs(&.{base})
            .withAux(@intCast(field_offset));
        return try fb.emit(node);
    }

    fn lowerStructInit(self: *Lowerer, si: ast.StructInit) Allocator.Error!ir.NodeIndex {
        const fb = self.current_func orelse return ir.null_node;

        // For now, emit a placeholder struct_init op
        // Full implementation will allocate stack space and initialize fields
        log.debug("  struct_init: {s}", .{si.type_name});

        // Lower each field value
        for (si.fields) |field_init| {
            _ = try self.lowerExpr(field_init.value);
        }

        // Placeholder: return null_node until full codegen is implemented
        _ = fb;
        return ir.null_node;
    }

    fn lowerArrayLiteral(self: *Lowerer, al: ast.ArrayLiteral) Allocator.Error!ir.NodeIndex {
        const fb = self.current_func orelse return ir.null_node;

        log.debug("  array_literal: {d} elements", .{al.elements.len});

        // Lower each element value
        for (al.elements) |elem_idx| {
            _ = try self.lowerExpr(elem_idx);
        }

        // Placeholder: return null_node until full codegen is implemented
        // Full implementation will allocate stack space and store elements
        _ = fb;
        return ir.null_node;
    }

    fn lowerIfExpr(self: *Lowerer, if_expr: ast.IfExpr) Allocator.Error!ir.NodeIndex {
        const fb = self.current_func orelse return ir.null_node;

        const cond = try self.lowerExpr(if_expr.condition);
        const then_val = try self.lowerExpr(if_expr.then_branch);
        const else_val = if (if_expr.else_branch) |e| try self.lowerExpr(e) else ir.null_node;

        const node = ir.Node.init(.select, TypeRegistry.VOID, Span.fromPos(Pos.zero))
            .withArgs(&.{ cond, then_val, else_val });

        return try fb.emit(node);
    }

    // ========================================================================
    // Type Inference Helper
    // ========================================================================

    /// Infer the type of an AST expression node.
    /// Used for type inference in variable declarations like `var i = 1`.
    fn inferTypeFromExpr(self: *Lowerer, node_idx: NodeIndex) TypeIndex {
        const node = self.tree.getNode(node_idx);

        switch (node) {
            .expr => |expr| {
                switch (expr) {
                    // Literals - check the kind
                    .literal => |lit| {
                        return switch (lit.kind) {
                            .int => TypeRegistry.INT,
                            .float => TypeRegistry.FLOAT,
                            .string => TypeRegistry.STRING,
                            .char => TypeRegistry.INT, // char is an int
                            .true_lit, .false_lit => TypeRegistry.BOOL,
                            .null_lit => TypeRegistry.VOID,
                        };
                    },

                    // Struct init - look up the struct type
                    .struct_init => |si| {
                        return self.type_reg.lookupByName(si.type_name) orelse TypeRegistry.VOID;
                    },

                    // Array literal - infer from elements (assuming homogeneous)
                    .array_literal => |al| {
                        // If has elements, infer elem type from first element
                        if (al.elements.len > 0) {
                            const elem_type = self.inferTypeFromExpr(al.elements[0]);
                            return self.type_reg.makeArray(elem_type, al.elements.len) catch TypeRegistry.VOID;
                        }
                        return TypeRegistry.VOID;
                    },

                    // Identifier - look up the variable's type
                    .identifier => |ident| {
                        const fb = self.current_func orelse return TypeRegistry.VOID;
                        for (fb.locals.items) |local| {
                            if (std.mem.eql(u8, local.name, ident.name)) {
                                return local.type_idx;
                            }
                        }
                        return TypeRegistry.VOID;
                    },

                    // Binary ops - infer from operands (simplified: return left type)
                    .binary => |bin| {
                        return self.inferTypeFromExpr(bin.left);
                    },

                    // Unary ops - infer from operand
                    .unary => |un| {
                        return self.inferTypeFromExpr(un.operand);
                    },

                    // Paren - unwrap
                    .paren => |p| {
                        return self.inferTypeFromExpr(p.inner);
                    },

                    // Call - would need function return type info
                    .call => return TypeRegistry.VOID, // TODO: look up function return type

                    // Field access
                    .field_access => return TypeRegistry.VOID, // TODO: look up field type

                    // Index - would need array element type
                    .index => |idx| {
                        const arr_type_idx = self.inferTypeFromExpr(idx.base);
                        const arr_type = self.type_reg.get(arr_type_idx);
                        if (arr_type == .array) {
                            return arr_type.array.elem;
                        }
                        return TypeRegistry.VOID;
                    },

                    // Slice expression - creates a slice of base's element type
                    .slice_expr => |se| {
                        const base_type_idx = self.inferTypeFromExpr(se.base);
                        const base_type = self.type_reg.get(base_type_idx);
                        return switch (base_type) {
                            .array => |a| self.type_reg.makeSlice(a.elem) catch TypeRegistry.VOID,
                            .slice => base_type_idx, // Slicing a slice returns same type
                            .basic => |k| if (k == .string_type) self.type_reg.makeSlice(TypeRegistry.U8) catch TypeRegistry.VOID else TypeRegistry.VOID,
                            else => TypeRegistry.VOID,
                        };
                    },

                    else => return TypeRegistry.VOID,
                }
            },
            else => return TypeRegistry.VOID,
        }
    }
};

// ============================================================================
// Convenience function
// ============================================================================

/// Lower a type-checked AST to IR.
pub fn lowerAst(
    allocator: Allocator,
    tree: *const Ast,
    type_reg: *TypeRegistry,
    err: *ErrorReporter,
) !ir.IR {
    var lowerer = Lowerer.init(allocator, tree, type_reg, err);
    defer lowerer.deinit();
    return try lowerer.lower();
}

// ============================================================================
// Tests
// ============================================================================

test "lowerer init" {
    const allocator = std.testing.allocator;
    var tree = ast.Ast.init(allocator);
    defer tree.deinit();
    var type_reg = try types.TypeRegistry.init(allocator);
    defer type_reg.deinit();
    var src = source.Source.init(allocator, "test", "");
    defer src.deinit();
    var err = errors.ErrorReporter.init(&src, null);

    var lowerer = Lowerer.init(allocator, &tree, &type_reg, &err);
    defer lowerer.deinit();

    try std.testing.expect(lowerer.current_func == null);
}
