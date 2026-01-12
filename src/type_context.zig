///! Type Context - Shared utility for looking up declared types from the AST.
///!
///! This provides a single source of truth for type lookups used by both
///! the type checker and lowerer. It reads declared types directly from
///! the AST rather than maintaining separate maps.
///!
///! Design rationale: See TYPE_FLOW_DESIGN.md

const std = @import("std");
const ast = @import("ast.zig");
const types = @import("types.zig");

const Ast = ast.Ast;
const NodeIndex = ast.NodeIndex;
const TypeIndex = types.TypeIndex;
const TypeRegistry = types.TypeRegistry;

pub const TypeContext = struct {
    tree: *const Ast,
    type_reg: *TypeRegistry,

    /// Initialize a TypeContext with references to the AST and type registry.
    pub fn init(tree: *const Ast, type_reg: *TypeRegistry) TypeContext {
        return .{
            .tree = tree,
            .type_reg = type_reg,
        };
    }

    /// Get a function's declared return type by name.
    /// Returns null if the function is not found.
    /// Returns VOID if the function has no explicit return type.
    pub fn getFuncReturnType(self: TypeContext, func_name: []const u8) ?TypeIndex {
        const file = self.tree.file orelse return null;

        // Search through all declarations for the function
        for (file.decls) |decl_idx| {
            const node = self.tree.getNode(decl_idx);
            if (node != .decl) continue;

            switch (node.decl) {
                .fn_decl => |fn_decl| {
                    if (std.mem.eql(u8, fn_decl.name, func_name)) {
                        // Found the function - resolve its return type
                        if (fn_decl.return_type) |rt_node| {
                            return self.resolveTypeExprNode(rt_node);
                        } else {
                            return TypeRegistry.VOID;
                        }
                    }
                },
                else => {},
            }
        }

        return null; // Function not found
    }

    /// Resolve an AST type expression node to a TypeIndex.
    /// This mirrors the logic in lower.zig's resolveTypeExprNode.
    pub fn resolveTypeExprNode(self: TypeContext, node_idx: NodeIndex) TypeIndex {
        const node = self.tree.getNode(node_idx);
        if (node != .expr) return TypeRegistry.VOID;
        if (node.expr != .type_expr) return TypeRegistry.VOID;

        const type_expr = node.expr.type_expr;
        return switch (type_expr.kind) {
            .named => |name| self.resolveNamedType(name),
            .pointer => |ptr_elem| self.resolvePointerType(ptr_elem),
            .optional => |opt_elem| self.resolveOptionalType(opt_elem),
            .array => |arr| self.resolveArrayType(arr.elem, arr.size),
            .slice => |slice_elem| self.resolveSliceType(slice_elem),
            .list => |list_elem| self.resolveListType(list_elem),
            .map => |m| self.resolveMapType(m.key, m.value),
            .function => TypeRegistry.VOID, // Function types not used as values currently
        };
    }

    /// Resolve a named type (int, u8, MyStruct, etc.)
    fn resolveNamedType(self: TypeContext, name: []const u8) TypeIndex {
        // Check built-in types first
        if (std.mem.eql(u8, name, "i64") or std.mem.eql(u8, name, "int")) return TypeRegistry.INT;
        if (std.mem.eql(u8, name, "i32")) return TypeRegistry.I32;
        if (std.mem.eql(u8, name, "i16")) return TypeRegistry.I16;
        if (std.mem.eql(u8, name, "i8")) return TypeRegistry.I8;
        if (std.mem.eql(u8, name, "u64")) return TypeRegistry.U64;
        if (std.mem.eql(u8, name, "u32")) return TypeRegistry.U32;
        if (std.mem.eql(u8, name, "u16")) return TypeRegistry.U16;
        if (std.mem.eql(u8, name, "u8")) return TypeRegistry.U8;
        if (std.mem.eql(u8, name, "f64") or std.mem.eql(u8, name, "float")) return TypeRegistry.FLOAT;
        if (std.mem.eql(u8, name, "f32")) return TypeRegistry.F32;
        if (std.mem.eql(u8, name, "bool")) return TypeRegistry.BOOL;
        if (std.mem.eql(u8, name, "string")) return TypeRegistry.STRING;
        if (std.mem.eql(u8, name, "void")) return TypeRegistry.VOID;

        // Look up user-defined types in registry
        return self.type_reg.lookupByName(name) orelse TypeRegistry.VOID;
    }

    /// Resolve a pointer type (*T)
    fn resolvePointerType(self: TypeContext, elem_idx: NodeIndex) TypeIndex {
        const elem_type = self.resolveTypeExprNode(elem_idx);
        return self.type_reg.makePointer(elem_type) catch TypeRegistry.VOID;
    }

    /// Resolve an optional type (?T)
    fn resolveOptionalType(self: TypeContext, elem_idx: NodeIndex) TypeIndex {
        const elem_type = self.resolveTypeExprNode(elem_idx);
        return self.type_reg.makeOptional(elem_type) catch TypeRegistry.VOID;
    }

    /// Resolve an array type ([N]T)
    fn resolveArrayType(self: TypeContext, elem_idx: NodeIndex, size_idx: NodeIndex) TypeIndex {
        const elem_type = self.resolveTypeExprNode(elem_idx);
        // For now, we need to evaluate the size expression - this is tricky
        // The size is a NodeIndex pointing to an expression (typically a literal)
        // For simplicity, we extract the literal value
        const size = self.evaluateSizeExpr(size_idx);
        return self.type_reg.makeArray(elem_type, size) catch TypeRegistry.VOID;
    }

    /// Evaluate a size expression (for array types)
    fn evaluateSizeExpr(self: TypeContext, size_idx: NodeIndex) u32 {
        const node = self.tree.getNode(size_idx);
        if (node == .expr) {
            if (node.expr == .literal) {
                const lit = node.expr.literal;
                if (lit.kind == .int) {
                    return std.fmt.parseInt(u32, lit.value, 10) catch 0;
                }
            }
        }
        return 0;
    }

    /// Resolve a slice type ([]T)
    fn resolveSliceType(self: TypeContext, elem_idx: NodeIndex) TypeIndex {
        const elem_type = self.resolveTypeExprNode(elem_idx);
        return self.type_reg.makeSlice(elem_type) catch TypeRegistry.VOID;
    }

    /// Resolve a List<T> type
    fn resolveListType(self: TypeContext, elem_idx: NodeIndex) TypeIndex {
        const elem_type = self.resolveTypeExprNode(elem_idx);
        return self.type_reg.makeList(elem_type) catch TypeRegistry.VOID;
    }

    /// Resolve a Map<K, V> type
    fn resolveMapType(self: TypeContext, key_idx: NodeIndex, value_idx: NodeIndex) TypeIndex {
        const key_type = self.resolveTypeExprNode(key_idx);
        const val_type = self.resolveTypeExprNode(value_idx);
        return self.type_reg.makeMap(key_type, val_type) catch TypeRegistry.VOID;
    }

    // ========================================================================
    // Type Query Methods - Used by Lowerer for proper type propagation
    // ========================================================================

    /// Get a struct field's type by field name.
    /// Returns null if the type is not a struct or field not found.
    pub fn getFieldType(self: TypeContext, struct_type_idx: TypeIndex, field_name: []const u8) ?TypeIndex {
        const t = self.type_reg.get(struct_type_idx);
        switch (t) {
            .struct_type => |st| {
                for (st.fields) |field| {
                    if (std.mem.eql(u8, field.name, field_name)) {
                        return field.type_idx;
                    }
                }
            },
            else => {},
        }
        return null;
    }

    /// Get the element type of an array, slice, list, or string.
    /// Returns null if the type doesn't have elements.
    pub fn getElementType(self: TypeContext, type_idx: TypeIndex) ?TypeIndex {
        const t = self.type_reg.get(type_idx);
        return switch (t) {
            .array => |a| a.elem,
            .slice => |s| s.elem,
            .list_type => |l| l.elem,
            .basic => |k| if (k == .string_type) TypeRegistry.U8 else null,
            else => null,
        };
    }

    /// Get the key type of a Map.
    /// Returns null if the type is not a Map.
    pub fn getMapKeyType(self: TypeContext, type_idx: TypeIndex) ?TypeIndex {
        const t = self.type_reg.get(type_idx);
        return switch (t) {
            .map_type => |m| m.key,
            else => null,
        };
    }

    /// Get the value type of a Map.
    /// Returns null if the type is not a Map.
    pub fn getMapValueType(self: TypeContext, type_idx: TypeIndex) ?TypeIndex {
        const t = self.type_reg.get(type_idx);
        return switch (t) {
            .map_type => |m| m.value,
            else => null,
        };
    }

    /// Get the element type of a List.
    /// Returns null if the type is not a List.
    pub fn getListElementType(self: TypeContext, type_idx: TypeIndex) ?TypeIndex {
        const t = self.type_reg.get(type_idx);
        return switch (t) {
            .list_type => |l| l.elem,
            else => null,
        };
    }

    /// Check if a type is a struct and return its info.
    /// Returns null if not a struct.
    pub fn getStructInfo(self: TypeContext, type_idx: TypeIndex) ?types.StructType {
        const t = self.type_reg.get(type_idx);
        return switch (t) {
            .struct_type => |st| st,
            else => null,
        };
    }

    /// Check if a type is an enum and return its backing type.
    /// Returns null if not an enum.
    pub fn getEnumBackingType(self: TypeContext, type_idx: TypeIndex) ?TypeIndex {
        const t = self.type_reg.get(type_idx);
        return switch (t) {
            .enum_type => |e| e.backing_type,
            else => null,
        };
    }

    /// Check if a type is a union and return its info.
    /// Returns null if not a union.
    pub fn getUnionInfo(self: TypeContext, type_idx: TypeIndex) ?types.UnionType {
        const t = self.type_reg.get(type_idx);
        return switch (t) {
            .union_type => |u| u,
            else => null,
        };
    }

    /// Get a union variant's payload type by variant name.
    /// Returns null if not a union or variant not found.
    /// Returns VOID if variant has no payload.
    pub fn getUnionPayloadType(self: TypeContext, union_type_idx: TypeIndex, variant_name: []const u8) ?TypeIndex {
        const t = self.type_reg.get(union_type_idx);
        switch (t) {
            .union_type => |u| {
                for (u.variants) |variant| {
                    if (std.mem.eql(u8, variant.name, variant_name)) {
                        return variant.type_idx;
                    }
                }
            },
            else => {},
        }
        return null;
    }

    /// Create a pointer type to the given type.
    /// Returns VOID on failure.
    pub fn makePointerTo(self: TypeContext, elem_type: TypeIndex) TypeIndex {
        return self.type_reg.makePointer(elem_type) catch TypeRegistry.VOID;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "TypeContext basic construction" {
    const testing = std.testing;
    var type_reg = try TypeRegistry.init(testing.allocator);
    defer type_reg.deinit();

    var tree = Ast.init(testing.allocator);
    defer tree.deinit();

    const ctx = TypeContext.init(&tree, &type_reg);
    _ = ctx;
}

test "getFuncReturnType returns null for missing function" {
    const testing = std.testing;
    var type_reg = try TypeRegistry.init(testing.allocator);
    defer type_reg.deinit();

    var tree = Ast.init(testing.allocator);
    defer tree.deinit();

    const ctx = TypeContext.init(&tree, &type_reg);

    // No file in tree, should return null
    try testing.expectEqual(@as(?TypeIndex, null), ctx.getFuncReturnType("nonexistent"));
}
