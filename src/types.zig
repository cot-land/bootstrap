///! Type representation for cot.
///!
///! Maps to Go's cmd/compile/internal/types2/
///! - basic.go (Basic types)
///! - pointer.go, slice.go, array.go (Composite types)
///! - struct.go (Struct types)
///! - signature.go (Function types)

const std = @import("std");

// ============================================================================
// Type Index
// ============================================================================

/// Index into type pool. Using indices allows type interning and comparison.
pub const TypeIndex = u32;
pub const invalid_type: TypeIndex = std.math.maxInt(TypeIndex);

// ============================================================================
// Basic Types
// ============================================================================

/// Kind of basic type (maps to Go's BasicKind).
pub const BasicKind = enum(u8) {
    // Invalid type
    invalid,

    // Boolean
    bool_type,

    // Signed integers
    i8_type,
    i16_type,
    i32_type,
    i64_type,

    // Unsigned integers
    u8_type,
    u16_type,
    u32_type,
    u64_type,

    // Floating point
    f32_type,
    f64_type,

    // Void (no return value)
    void_type,

    // Special: untyped literals (resolved during type checking)
    untyped_int,
    untyped_float,
    untyped_bool,
    untyped_null,

    /// Get the name of this basic type.
    pub fn name(self: BasicKind) []const u8 {
        return switch (self) {
            .invalid => "invalid",
            .bool_type => "bool",
            .i8_type => "i8",
            .i16_type => "i16",
            .i32_type => "i32",
            .i64_type => "i64",
            .u8_type => "u8",
            .u16_type => "u16",
            .u32_type => "u32",
            .u64_type => "u64",
            .f32_type => "f32",
            .f64_type => "f64",
            .void_type => "void",
            .untyped_int => "untyped int",
            .untyped_float => "untyped float",
            .untyped_bool => "untyped bool",
            .untyped_null => "untyped null",
        };
    }

    /// Check if this is a numeric type.
    pub fn isNumeric(self: BasicKind) bool {
        return self.isInteger() or self.isFloat();
    }

    /// Check if this is an integer type.
    pub fn isInteger(self: BasicKind) bool {
        return switch (self) {
            .i8_type, .i16_type, .i32_type, .i64_type => true,
            .u8_type, .u16_type, .u32_type, .u64_type => true,
            .untyped_int => true,
            else => false,
        };
    }

    /// Check if this is a signed integer type.
    pub fn isSigned(self: BasicKind) bool {
        return switch (self) {
            .i8_type, .i16_type, .i32_type, .i64_type => true,
            else => false,
        };
    }

    /// Check if this is a floating point type.
    pub fn isFloat(self: BasicKind) bool {
        return switch (self) {
            .f32_type, .f64_type, .untyped_float => true,
            else => false,
        };
    }

    /// Check if this is an untyped type.
    pub fn isUntyped(self: BasicKind) bool {
        return switch (self) {
            .untyped_int, .untyped_float, .untyped_bool, .untyped_null => true,
            else => false,
        };
    }

    /// Get the size in bytes (0 for unsized types).
    pub fn size(self: BasicKind) u8 {
        return switch (self) {
            .bool_type => 1,
            .i8_type, .u8_type => 1,
            .i16_type, .u16_type => 2,
            .i32_type, .u32_type, .f32_type => 4,
            .i64_type, .u64_type, .f64_type => 8,
            else => 0, // void, untyped
        };
    }
};

// ============================================================================
// Fixed Types (for DBL compatibility)
// ============================================================================

/// Alpha type: fixed-length string (like DBL's a30)
pub const AlphaType = struct {
    length: u32, // number of characters
};

/// Decimal type: fixed-point decimal (like DBL's d10 or d8.2)
pub const DecimalType = struct {
    precision: u8, // total digits
    scale: u8, // digits after decimal point (0 for integer decimal)
};

// ============================================================================
// Composite Types
// ============================================================================

/// Pointer type: *T
pub const PointerType = struct {
    elem: TypeIndex,
};

/// Optional type: ?T
pub const OptionalType = struct {
    elem: TypeIndex,
};

/// Slice type: []T
pub const SliceType = struct {
    elem: TypeIndex,
};

/// Array type: [N]T
pub const ArrayType = struct {
    elem: TypeIndex,
    length: u64,
};

/// Struct field
pub const StructField = struct {
    name: []const u8,
    type_idx: TypeIndex,
    offset: u32, // byte offset in struct (computed during type checking)
};

/// Struct type
pub const StructType = struct {
    name: []const u8, // empty for anonymous structs
    fields: []const StructField,
    size: u32, // total size in bytes (computed during type checking)
    alignment: u8, // alignment requirement
};

/// Enum variant
pub const EnumVariant = struct {
    name: []const u8,
    value: i64, // resolved integer value
};

/// Enum type
pub const EnumType = struct {
    name: []const u8,
    backing_type: TypeIndex, // u8, i32, etc. (defaults to i32 if not specified)
    variants: []const EnumVariant,
};

/// Tagged union variant
pub const UnionVariant = struct {
    name: []const u8,
    type_idx: TypeIndex, // The payload type (invalid_type for unit variants)
};

/// Tagged union type
pub const UnionType = struct {
    name: []const u8,
    variants: []const UnionVariant,
    tag_type: TypeIndex, // The internal tag type (usually u8 or u16)
};

/// Function parameter
pub const FuncParam = struct {
    name: []const u8,
    type_idx: TypeIndex,
};

/// Function type
pub const FuncType = struct {
    params: []const FuncParam,
    return_type: TypeIndex, // invalid_type for void
};

/// Named type (user-defined type alias or struct)
pub const NamedType = struct {
    name: []const u8,
    underlying: TypeIndex,
};

/// Map type: Map<K, V> - built-in hash map
pub const MapType = struct {
    key: TypeIndex,
    value: TypeIndex,
};

/// List type: List<T> - built-in dynamic array
pub const ListType = struct {
    elem: TypeIndex,
};

// ============================================================================
// Type Union
// ============================================================================

/// A type in cot.
pub const Type = union(enum) {
    basic: BasicKind,
    alpha: AlphaType,
    decimal: DecimalType,
    pointer: PointerType,
    optional: OptionalType,
    slice: SliceType,
    array: ArrayType,
    struct_type: StructType,
    enum_type: EnumType,
    union_type: UnionType,
    func: FuncType,
    named: NamedType,
    map_type: MapType,
    list_type: ListType,

    /// Get a string representation of this type.
    pub fn format(
        self: Type,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        switch (self) {
            .basic => |k| try writer.writeAll(k.name()),
            .alpha => |a| try writer.print("alpha({d})", .{a.length}),
            .decimal => |d| {
                if (d.scale == 0) {
                    try writer.print("decimal({d})", .{d.precision});
                } else {
                    try writer.print("decimal({d},{d})", .{ d.precision, d.scale });
                }
            },
            .pointer => try writer.writeAll("*..."),
            .optional => try writer.writeAll("?..."),
            .slice => try writer.writeAll("[]..."),
            .array => |a| try writer.print("[{d}]...", .{a.length}),
            .struct_type => |s| {
                if (s.name.len > 0) {
                    try writer.writeAll(s.name);
                } else {
                    try writer.writeAll("struct{...}");
                }
            },
            .enum_type => |e| try writer.writeAll(e.name),
            .union_type => |u| try writer.writeAll(u.name),
            .func => try writer.writeAll("fn(...)"),
            .named => |n| try writer.writeAll(n.name),
            .map_type => try writer.writeAll("Map<...>"),
            .list_type => try writer.writeAll("List<...>"),
        }
    }
};

// ============================================================================
// Type Registry (interning)
// ============================================================================

/// Type registry for interning types.
/// Ensures each unique type has a single TypeIndex.
pub const TypeRegistry = struct {
    types: std.ArrayList(Type),
    allocator: std.mem.Allocator,

    // Pre-allocated indices for basic types
    pub const INVALID: TypeIndex = 0;
    pub const BOOL: TypeIndex = 1;
    pub const I8: TypeIndex = 2;
    pub const I16: TypeIndex = 3;
    pub const I32: TypeIndex = 4;
    pub const I64: TypeIndex = 5;
    pub const U8: TypeIndex = 6;
    pub const U16: TypeIndex = 7;
    pub const U32: TypeIndex = 8;
    pub const U64: TypeIndex = 9;
    pub const F32: TypeIndex = 10;
    pub const F64: TypeIndex = 11;
    pub const VOID: TypeIndex = 12;
    pub const STRING: TypeIndex = 13; // []u8 slice (string alias)

    // Type aliases (cot's friendly names)
    pub const INT: TypeIndex = I64; // int = i64
    pub const FLOAT: TypeIndex = F64; // float = f64
    pub const BYTE: TypeIndex = U8; // byte = u8

    pub fn init(allocator: std.mem.Allocator) !TypeRegistry {
        var reg = TypeRegistry{
            .types = std.ArrayList(Type){ .items = &.{}, .capacity = 0 },
            .allocator = allocator,
        };

        // Pre-register basic types in order
        try reg.types.append(allocator, .{ .basic = .invalid }); // 0
        try reg.types.append(allocator, .{ .basic = .bool_type }); // 1
        try reg.types.append(allocator, .{ .basic = .i8_type }); // 2
        try reg.types.append(allocator, .{ .basic = .i16_type }); // 3
        try reg.types.append(allocator, .{ .basic = .i32_type }); // 4
        try reg.types.append(allocator, .{ .basic = .i64_type }); // 5
        try reg.types.append(allocator, .{ .basic = .u8_type }); // 6
        try reg.types.append(allocator, .{ .basic = .u16_type }); // 7
        try reg.types.append(allocator, .{ .basic = .u32_type }); // 8
        try reg.types.append(allocator, .{ .basic = .u64_type }); // 9
        try reg.types.append(allocator, .{ .basic = .f32_type }); // 10
        try reg.types.append(allocator, .{ .basic = .f64_type }); // 11
        try reg.types.append(allocator, .{ .basic = .void_type }); // 12
        try reg.types.append(allocator, .{ .slice = .{ .elem = U8 } }); // 13 = []u8 (string)

        return reg;
    }

    pub fn deinit(self: *TypeRegistry) void {
        self.types.deinit(self.allocator);
    }

    /// Get a type by index.
    pub fn get(self: *const TypeRegistry, idx: TypeIndex) Type {
        if (idx >= self.types.items.len) {
            return .{ .basic = .invalid };
        }
        return self.types.items[idx];
    }

    /// Get the size of a type in bytes.
    /// This is like Go's CalcSize() - computes the actual storage size.
    pub fn sizeOf(self: *const TypeRegistry, idx: TypeIndex) u32 {
        const t = self.get(idx);
        return switch (t) {
            .basic => |b| switch (b) {
                .i8_type, .u8_type, .bool_type => 1,
                .i16_type, .u16_type => 2,
                .i32_type, .u32_type, .f32_type => 4,
                .i64_type, .u64_type, .f64_type => 8,
                .void_type, .invalid => 0,
                else => 8, // Default basic types to 8 bytes
            },
            .pointer => 8, // 64-bit pointer
            .optional => |o| self.sizeOf(o.elem) + 8, // value + flag (simplified, rounded)
            .slice => 16, // ptr + len
            .array => |a| self.sizeOf(a.elem) * @as(u32, @intCast(a.length)),
            .struct_type => |s| blk: {
                var size: u32 = 0;
                for (s.fields) |field| {
                    // Simplified: no padding for now
                    size += self.sizeOf(field.type_idx);
                }
                break :blk size;
            },
            .enum_type => |e| self.sizeOf(e.backing_type),
            .union_type => |u| blk: {
                // Union size = 8-byte aligned tag + max payload size
                // Codegen assumes tag at offset 0 (8 bytes) and payload at offset 8
                var max_payload: u32 = 0;
                for (u.variants) |v| {
                    if (v.type_idx != invalid_type) {
                        const payload_size = self.sizeOf(v.type_idx);
                        if (payload_size > max_payload) max_payload = payload_size;
                    }
                }
                // Use 8 bytes for tag (aligned) + max payload aligned to 8
                const payload_aligned = (max_payload + 7) / 8 * 8;
                break :blk 8 + payload_aligned;
            },
            // Map and List are heap-allocated, so pointer size
            .map_type => 8, // pointer to heap-allocated map
            .list_type => 8, // pointer to heap-allocated list
            else => 8, // Default to 8 bytes for unknown types
        };
    }

    /// Add a new type and return its index.
    pub fn add(self: *TypeRegistry, t: Type) !TypeIndex {
        const idx: TypeIndex = @intCast(self.types.items.len);
        try self.types.append(self.allocator, t);
        return idx;
    }

    /// Create a pointer type.
    pub fn makePointer(self: *TypeRegistry, elem: TypeIndex) !TypeIndex {
        return self.add(.{ .pointer = .{ .elem = elem } });
    }

    /// Create an optional type.
    pub fn makeOptional(self: *TypeRegistry, elem: TypeIndex) !TypeIndex {
        return self.add(.{ .optional = .{ .elem = elem } });
    }

    /// Create a slice type.
    pub fn makeSlice(self: *TypeRegistry, elem: TypeIndex) !TypeIndex {
        return self.add(.{ .slice = .{ .elem = elem } });
    }

    /// Create an array type.
    pub fn makeArray(self: *TypeRegistry, elem: TypeIndex, length: u64) !TypeIndex {
        return self.add(.{ .array = .{ .elem = elem, .length = length } });
    }

    /// Create an alpha type.
    pub fn makeAlpha(self: *TypeRegistry, length: u32) !TypeIndex {
        return self.add(.{ .alpha = .{ .length = length } });
    }

    /// Create a decimal type.
    pub fn makeDecimal(self: *TypeRegistry, precision: u8, scale: u8) !TypeIndex {
        return self.add(.{ .decimal = .{ .precision = precision, .scale = scale } });
    }

    /// Create a map type: Map<K, V>
    pub fn makeMap(self: *TypeRegistry, key: TypeIndex, value: TypeIndex) !TypeIndex {
        return self.add(.{ .map_type = .{ .key = key, .value = value } });
    }

    /// Create a list type: List<T>
    pub fn makeList(self: *TypeRegistry, elem: TypeIndex) !TypeIndex {
        return self.add(.{ .list_type = .{ .elem = elem } });
    }

    /// Look up a type name and return its index.
    /// Returns null if not found.
    pub fn lookupBasic(self: *const TypeRegistry, name: []const u8) ?TypeIndex {
        _ = self;
        // Built-in type names
        if (std.mem.eql(u8, name, "bool")) return BOOL;
        if (std.mem.eql(u8, name, "i8")) return I8;
        if (std.mem.eql(u8, name, "i16")) return I16;
        if (std.mem.eql(u8, name, "i32")) return I32;
        if (std.mem.eql(u8, name, "i64")) return I64;
        if (std.mem.eql(u8, name, "u8")) return U8;
        if (std.mem.eql(u8, name, "u16")) return U16;
        if (std.mem.eql(u8, name, "u32")) return U32;
        if (std.mem.eql(u8, name, "u64")) return U64;
        if (std.mem.eql(u8, name, "f32")) return F32;
        if (std.mem.eql(u8, name, "f64")) return F64;
        if (std.mem.eql(u8, name, "void")) return VOID;

        // Aliases
        if (std.mem.eql(u8, name, "int")) return INT;
        if (std.mem.eql(u8, name, "float")) return FLOAT;
        if (std.mem.eql(u8, name, "byte")) return BYTE;
        if (std.mem.eql(u8, name, "string")) return STRING; // string = []u8

        return null;
    }

    /// Check if two types are equal.
    pub fn equal(self: *const TypeRegistry, a: TypeIndex, b: TypeIndex) bool {
        if (a == b) return true;

        const ta = self.get(a);
        const tb = self.get(b);

        return switch (ta) {
            .basic => |ka| switch (tb) {
                .basic => |kb| ka == kb,
                else => false,
            },
            .pointer => |pa| switch (tb) {
                .pointer => |pb| self.equal(pa.elem, pb.elem),
                else => false,
            },
            .optional => |oa| switch (tb) {
                .optional => |ob| self.equal(oa.elem, ob.elem),
                else => false,
            },
            .slice => |sa| switch (tb) {
                .slice => |sb| self.equal(sa.elem, sb.elem),
                else => false,
            },
            .array => |aa| switch (tb) {
                .array => |ab| aa.length == ab.length and self.equal(aa.elem, ab.elem),
                else => false,
            },
            else => false, // struct, func, named need more complex comparison
        };
    }

    /// Look up a type by name (for struct, enum, union, and basic types).
    pub fn lookupByName(self: *const TypeRegistry, name: []const u8) ?TypeIndex {
        // Check basic types first
        if (std.mem.eql(u8, name, "i8")) return I8;
        if (std.mem.eql(u8, name, "i16")) return I16;
        if (std.mem.eql(u8, name, "i32")) return I32;
        if (std.mem.eql(u8, name, "i64")) return I64;
        if (std.mem.eql(u8, name, "u8")) return U8;
        if (std.mem.eql(u8, name, "u16")) return U16;
        if (std.mem.eql(u8, name, "u32")) return U32;
        if (std.mem.eql(u8, name, "u64")) return U64;
        if (std.mem.eql(u8, name, "bool")) return BOOL;
        if (std.mem.eql(u8, name, "void")) return VOID;

        // Check user-defined types
        for (self.types.items, 0..) |t, idx| {
            switch (t) {
                .struct_type => |st| {
                    if (std.mem.eql(u8, st.name, name)) {
                        return @intCast(idx);
                    }
                },
                .enum_type => |et| {
                    if (std.mem.eql(u8, et.name, name)) {
                        return @intCast(idx);
                    }
                },
                .union_type => |ut| {
                    if (std.mem.eql(u8, ut.name, name)) {
                        return @intCast(idx);
                    }
                },
                else => {},
            }
        }
        return null;
    }

    /// Check if a type is assignable to another.
    /// (e.g., untyped int can be assigned to any integer type)
    pub fn isAssignable(self: *const TypeRegistry, from: TypeIndex, to: TypeIndex) bool {
        if (self.equal(from, to)) return true;

        const tf = self.get(from);
        const tt = self.get(to);

        // Handle untyped -> typed conversions
        return switch (tf) {
            .basic => |kf| switch (tt) {
                .basic => |kt| {
                    if (kf == .untyped_int and kt.isInteger()) return true;
                    if (kf == .untyped_float and kt.isFloat()) return true;
                    if (kf == .untyped_bool and kt == .bool_type) return true;
                    if (kf == .untyped_null) {
                        // null is assignable to optional types (handled below)
                        return false;
                    }
                    return false;
                },
                .optional => true, // null is assignable to any optional
                else => false,
            },
            else => false,
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "type registry basic types" {
    var reg = try TypeRegistry.init(std.testing.allocator);
    defer reg.deinit();

    // Check pre-registered types
    try std.testing.expectEqual(Type{ .basic = .bool_type }, reg.get(TypeRegistry.BOOL));
    try std.testing.expectEqual(Type{ .basic = .i64_type }, reg.get(TypeRegistry.I64));
    try std.testing.expectEqual(Type{ .basic = .void_type }, reg.get(TypeRegistry.VOID));

    // Check aliases
    try std.testing.expectEqual(TypeRegistry.I64, TypeRegistry.INT);
    try std.testing.expectEqual(TypeRegistry.F64, TypeRegistry.FLOAT);
    try std.testing.expectEqual(TypeRegistry.U8, TypeRegistry.BYTE);
}

test "type registry lookup" {
    var reg = try TypeRegistry.init(std.testing.allocator);
    defer reg.deinit();

    try std.testing.expectEqual(TypeRegistry.BOOL, reg.lookupBasic("bool").?);
    try std.testing.expectEqual(TypeRegistry.INT, reg.lookupBasic("int").?);
    try std.testing.expectEqual(TypeRegistry.VOID, reg.lookupBasic("void").?);
    try std.testing.expect(reg.lookupBasic("unknown") == null);
}

test "type registry composite types" {
    var reg = try TypeRegistry.init(std.testing.allocator);
    defer reg.deinit();

    // Create *int
    const ptr_int = try reg.makePointer(TypeRegistry.INT);
    const t = reg.get(ptr_int);
    try std.testing.expect(t == .pointer);
    try std.testing.expectEqual(TypeRegistry.INT, t.pointer.elem);

    // Create ?int
    const opt_int = try reg.makeOptional(TypeRegistry.INT);
    const t2 = reg.get(opt_int);
    try std.testing.expect(t2 == .optional);

    // Create []u8
    const slice_u8 = try reg.makeSlice(TypeRegistry.U8);
    const t3 = reg.get(slice_u8);
    try std.testing.expect(t3 == .slice);

    // Create [10]i32
    const arr = try reg.makeArray(TypeRegistry.I32, 10);
    const t4 = reg.get(arr);
    try std.testing.expect(t4 == .array);
    try std.testing.expectEqual(@as(u64, 10), t4.array.length);
}

test "type registry fixed types" {
    var reg = try TypeRegistry.init(std.testing.allocator);
    defer reg.deinit();

    // Create alpha(30)
    const a30 = try reg.makeAlpha(30);
    const t1 = reg.get(a30);
    try std.testing.expect(t1 == .alpha);
    try std.testing.expectEqual(@as(u32, 30), t1.alpha.length);

    // Create decimal(10)
    const d10 = try reg.makeDecimal(10, 0);
    const t2 = reg.get(d10);
    try std.testing.expect(t2 == .decimal);
    try std.testing.expectEqual(@as(u8, 10), t2.decimal.precision);
    try std.testing.expectEqual(@as(u8, 0), t2.decimal.scale);

    // Create decimal(8,2)
    const d8_2 = try reg.makeDecimal(8, 2);
    const t3 = reg.get(d8_2);
    try std.testing.expect(t3 == .decimal);
    try std.testing.expectEqual(@as(u8, 8), t3.decimal.precision);
    try std.testing.expectEqual(@as(u8, 2), t3.decimal.scale);
}

test "type equality" {
    var reg = try TypeRegistry.init(std.testing.allocator);
    defer reg.deinit();

    // Same basic types are equal
    try std.testing.expect(reg.equal(TypeRegistry.INT, TypeRegistry.INT));
    try std.testing.expect(reg.equal(TypeRegistry.INT, TypeRegistry.I64)); // alias

    // Different basic types are not equal
    try std.testing.expect(!reg.equal(TypeRegistry.INT, TypeRegistry.FLOAT));

    // Same composite types are equal
    const ptr1 = try reg.makePointer(TypeRegistry.INT);
    const ptr2 = try reg.makePointer(TypeRegistry.INT);
    try std.testing.expect(reg.equal(ptr1, ptr2));

    // Different composite types are not equal
    const ptr3 = try reg.makePointer(TypeRegistry.FLOAT);
    try std.testing.expect(!reg.equal(ptr1, ptr3));
}

test "basic kind properties" {
    try std.testing.expect(BasicKind.i64_type.isInteger());
    try std.testing.expect(BasicKind.i64_type.isSigned());
    try std.testing.expect(!BasicKind.u64_type.isSigned());
    try std.testing.expect(BasicKind.f64_type.isFloat());
    try std.testing.expect(BasicKind.f64_type.isNumeric());
    try std.testing.expect(BasicKind.untyped_int.isUntyped());
    try std.testing.expectEqual(@as(u8, 8), BasicKind.i64_type.size());
}
