///! Strongly Typed Intermediate Representation for cot.
///!
///! This replaces the original ir.zig which used generic args arrays with
///! implicit semantics. Each operation now has a specific struct with named,
///! typed fields - eliminating entire classes of bugs where args are
///! misinterpreted between pipeline phases.
///!
///! Design principles:
///! 1. Every operation has explicit, named fields
///! 2. No implicit interpretation of args - the type tells you what it is
///! 3. LocalIdx vs NodeIndex are distinct - can't accidentally mix them
///! 4. Compile-time errors for wrong field access

const std = @import("std");
const types = @import("types.zig");
const source = @import("source.zig");

const TypeIndex = types.TypeIndex;
const TypeRegistry = types.TypeRegistry;
const Span = source.Span;
const Pos = source.Pos;
const Allocator = std.mem.Allocator;

// ============================================================================
// Distinct Index Types - Prevents Mixing Local Indices with Node References
// ============================================================================

/// Index into the node pool. Represents a computed value (result of an operation).
pub const NodeIndex = u32;
pub const null_node: NodeIndex = std.math.maxInt(NodeIndex);

/// Index into the local variable table. NOT a computed value.
pub const LocalIdx = u32;
pub const null_local: LocalIdx = std.math.maxInt(LocalIdx);

/// Index into the block pool.
pub const BlockIndex = u32;
pub const null_block: BlockIndex = std.math.maxInt(BlockIndex);

/// Index into the function's parameter list.
pub const ParamIdx = u32;

/// Index into the string literal table.
pub const StringIdx = u32;

// ============================================================================
// Binary and Unary Operation Kinds
// ============================================================================

/// Binary arithmetic and comparison operations.
pub const BinaryOp = enum(u8) {
    // Arithmetic
    add,
    sub,
    mul,
    div,
    mod,

    // Comparison
    eq,
    ne,
    lt,
    le,
    gt,
    ge,

    // Logical
    @"and",
    @"or",

    // Bitwise
    bit_and,
    bit_or,
    bit_xor,
    shl,
    shr,

    pub fn isComparison(self: BinaryOp) bool {
        return switch (self) {
            .eq, .ne, .lt, .le, .gt, .ge => true,
            else => false,
        };
    }

    pub fn isArithmetic(self: BinaryOp) bool {
        return switch (self) {
            .add, .sub, .mul, .div, .mod => true,
            else => false,
        };
    }
};

/// Unary operations.
pub const UnaryOp = enum(u8) {
    neg, // Arithmetic negation: -x
    not, // Logical not: !x
    bit_not, // Bitwise not: ~x
};

// ============================================================================
// Typed Operation Payloads
// ============================================================================

/// Payload for integer constant.
pub const ConstInt = struct {
    value: i64,
};

/// Payload for float constant.
pub const ConstFloat = struct {
    value: f64,
};

/// Payload for boolean constant.
pub const ConstBool = struct {
    value: bool,
};

/// Payload for string literal reference.
pub const ConstSlice = struct {
    string_index: StringIdx,
};

/// Reference to a local variable by index.
pub const LocalRef = struct {
    local_idx: LocalIdx,
};

/// Binary operation with two operands.
pub const Binary = struct {
    op: BinaryOp,
    left: NodeIndex,
    right: NodeIndex,
};

/// Unary operation with one operand.
pub const Unary = struct {
    op: UnaryOp,
    operand: NodeIndex,
};

/// Store to a local variable.
pub const StoreLocal = struct {
    local_idx: LocalIdx,
    value: NodeIndex,
};

/// Load field from local struct variable.
pub const FieldLocal = struct {
    local_idx: LocalIdx,
    offset: i64,
};

/// Store to field in local struct variable.
pub const StoreLocalField = struct {
    local_idx: LocalIdx,
    offset: i64,
    value: NodeIndex,
};

/// Load field from computed struct value.
pub const FieldValue = struct {
    base: NodeIndex,
    offset: i64,
};

/// Index into local array/slice.
pub const IndexLocal = struct {
    local_idx: LocalIdx,
    index: NodeIndex,
    elem_size: u32,
};

/// Index into computed array/slice value.
pub const IndexValue = struct {
    base: NodeIndex,
    index: NodeIndex,
    elem_size: u32,
};

/// Slice operation on local.
pub const SliceLocal = struct {
    local_idx: LocalIdx,
    start: NodeIndex,
    end: NodeIndex,
    elem_size: u32,
};

/// Slice operation on computed value.
pub const SliceValue = struct {
    base: NodeIndex,
    start: NodeIndex,
    end: NodeIndex,
    elem_size: u32,
};

/// Load through pointer stored in local.
pub const PtrLoad = struct {
    ptr_local: LocalIdx,
};

/// Store through pointer stored in local.
pub const PtrStore = struct {
    ptr_local: LocalIdx,
    value: NodeIndex,
};

/// Load field through pointer stored in local.
pub const PtrField = struct {
    ptr_local: LocalIdx,
    offset: i64,
};

/// Store to field through pointer stored in local.
pub const PtrFieldStore = struct {
    ptr_local: LocalIdx,
    offset: i64,
    value: NodeIndex,
};

/// Load through computed pointer value.
pub const PtrLoadValue = struct {
    ptr: NodeIndex,
};

/// Store through computed pointer value.
pub const PtrStoreValue = struct {
    ptr: NodeIndex,
    value: NodeIndex,
};

/// Add constant offset to base address.
pub const AddrOffset = struct {
    base: NodeIndex,
    offset: i64,
};

/// Compute array element address.
pub const AddrIndex = struct {
    base: NodeIndex,
    index: NodeIndex,
    elem_size: u32,
};

/// Function call.
pub const Call = struct {
    /// Function name (for now, until we have function indices)
    func_name: []const u8,
    /// Arguments to the function
    args: []const NodeIndex,
    /// Is this a builtin call?
    is_builtin: bool,
};

/// Return from function.
pub const Return = struct {
    /// Value to return, or null for void return
    value: ?NodeIndex,
};

/// Unconditional jump.
pub const Jump = struct {
    target: BlockIndex,
};

/// Conditional branch.
pub const Branch = struct {
    condition: NodeIndex,
    then_block: BlockIndex,
    else_block: BlockIndex,
};

/// Phi node source (value from a predecessor block).
pub const PhiSource = struct {
    block: BlockIndex,
    value: NodeIndex,
};

/// Phi node for SSA.
pub const Phi = struct {
    sources: []const PhiSource,
};

/// Ternary select operation.
pub const Select = struct {
    condition: NodeIndex,
    then_value: NodeIndex,
    else_value: NodeIndex,
};

/// List operations.
pub const ListPush = struct {
    handle: NodeIndex,
    value: NodeIndex,
};

pub const ListGet = struct {
    handle: NodeIndex,
    index: NodeIndex,
};

pub const ListSet = struct {
    handle: NodeIndex,
    index: NodeIndex,
    value: NodeIndex,
};

pub const ListLen = struct {
    handle: NodeIndex,
};

/// Map operations.
pub const MapSet = struct {
    handle: NodeIndex,
    key_ptr: NodeIndex,
    key_len: NodeIndex,
    value: NodeIndex,
};

pub const MapGet = struct {
    handle: NodeIndex,
    key_ptr: NodeIndex,
    key_len: NodeIndex,
};

pub const MapHas = struct {
    handle: NodeIndex,
    key_ptr: NodeIndex,
    key_len: NodeIndex,
};

pub const MapSize = struct {
    handle: NodeIndex,
};

/// String concatenation.
pub const StrConcat = struct {
    left: NodeIndex,
    right: NodeIndex,
};

/// Union initialization.
pub const UnionInit = struct {
    variant_idx: u32,
    payload: ?NodeIndex,
};

/// Get union tag.
pub const UnionTag = struct {
    value: NodeIndex,
};

/// Get union payload.
pub const UnionPayload = struct {
    variant_idx: u32,
    value: NodeIndex,
};

/// File read operation.
pub const FileRead = struct {
    path: NodeIndex,
};

/// File write operation.
pub const FileWrite = struct {
    path: NodeIndex,
    data_ptr: NodeIndex,
    data_len: NodeIndex,
};

/// File exists check.
pub const FileExists = struct {
    path: NodeIndex,
};

/// Get command line argument.
pub const ArgsGet = struct {
    index: NodeIndex,
};

/// Type conversion.
pub const Convert = struct {
    operand: NodeIndex,
    from_type: TypeIndex,
    to_type: TypeIndex,
};

/// Pointer cast.
pub const PtrCast = struct {
    operand: NodeIndex,
};

/// Get list data pointer (for FFI).
pub const ListDataPtr = struct {
    handle: NodeIndex,
};

/// Get list byte size (for FFI).
pub const ListByteSize = struct {
    handle: NodeIndex,
};

/// Slice index operation.
pub const SliceIndex = struct {
    slice_local: LocalIdx,
    index: NodeIndex,
    elem_size: u32,
};

// ============================================================================
// The Node: A Tagged Union with Typed Payloads
// ============================================================================

/// An IR node represents a single operation with strongly typed operands.
/// The Data union ensures each operation can only access its own fields.
pub const Node = struct {
    /// Result type of this operation.
    type_idx: TypeIndex,
    /// Source location for error messages.
    span: Span,
    /// Block this node belongs to.
    block: BlockIndex,
    /// The operation and its typed payload.
    data: Data,

    /// The tagged union of all possible operations.
    pub const Data = union(enum) {
        // ========== Constants ==========
        const_int: ConstInt,
        const_float: ConstFloat,
        const_bool: ConstBool,
        const_null: void,
        const_slice: ConstSlice,

        // ========== Local Variable Access ==========
        /// Reference to local variable value.
        local_ref: LocalRef,
        /// Get address of local variable.
        addr_local: LocalRef,
        /// Load value from local.
        load_local: LocalRef,
        /// Store value to local.
        store_local: StoreLocal,

        // ========== Binary and Unary Operations ==========
        binary: Binary,
        unary: Unary,

        // ========== Struct Field Access ==========
        /// Load field from local struct.
        field_local: FieldLocal,
        /// Store to field in local struct.
        store_local_field: StoreLocalField,
        /// Load field from computed struct value.
        field_value: FieldValue,

        // ========== Array/Slice Indexing ==========
        /// Index into local array/slice.
        index_local: IndexLocal,
        /// Index into computed array/slice.
        index_value: IndexValue,
        /// Create slice from local.
        slice_local: SliceLocal,
        /// Create slice from computed value.
        slice_value: SliceValue,
        /// Index into slice stored in local.
        slice_index: SliceIndex,

        // ========== Pointer Operations (pointer in local) ==========
        /// Load through pointer in local.
        ptr_load: PtrLoad,
        /// Store through pointer in local.
        ptr_store: PtrStore,
        /// Load field through pointer in local.
        ptr_field: PtrField,
        /// Store to field through pointer in local.
        ptr_field_store: PtrFieldStore,

        // ========== Pointer Operations (computed pointer) ==========
        /// Load through computed pointer value.
        ptr_load_value: PtrLoadValue,
        /// Store through computed pointer value.
        ptr_store_value: PtrStoreValue,

        // ========== Address Arithmetic ==========
        /// Add constant offset to address.
        addr_offset: AddrOffset,
        /// Compute array element address.
        addr_index: AddrIndex,

        // ========== Control Flow ==========
        call: Call,
        ret: Return,
        jump: Jump,
        branch: Branch,
        phi: Phi,
        select: Select,

        // ========== List Operations ==========
        list_new: void,
        list_push: ListPush,
        list_get: ListGet,
        list_set: ListSet,
        list_len: ListLen,
        list_free: ListLen, // Same payload as list_len
        list_data_ptr: ListDataPtr,
        list_byte_size: ListByteSize,

        // ========== Map Operations ==========
        map_new: void,
        map_set: MapSet,
        map_get: MapGet,
        map_has: MapHas,
        map_size: MapSize,
        map_free: MapSize, // Same payload as map_size

        // ========== String Operations ==========
        str_concat: StrConcat,

        // ========== Union Operations ==========
        union_init: UnionInit,
        union_tag: UnionTag,
        union_payload: UnionPayload,

        // ========== File I/O ==========
        file_read: FileRead,
        file_write: FileWrite,
        file_exists: FileExists,
        file_free: PtrLoadValue, // Free ptr from file_read

        // ========== Command Line Args ==========
        args_count: void,
        args_get: ArgsGet,

        // ========== Conversions ==========
        convert: Convert,
        ptr_cast: PtrCast,

        // ========== Misc ==========
        nop: void,
    };

    /// Create a new node with the given data.
    pub fn init(data: Data, type_idx: TypeIndex, span: Span) Node {
        return .{
            .type_idx = type_idx,
            .span = span,
            .block = null_block,
            .data = data,
        };
    }

    /// Set the block for this node.
    pub fn withBlock(self: Node, block: BlockIndex) Node {
        var n = self;
        n.block = block;
        return n;
    }

    /// Check if this node is a terminator (ends a basic block).
    pub fn isTerminator(self: *const Node) bool {
        return switch (self.data) {
            .ret, .jump, .branch => true,
            else => false,
        };
    }

    /// Check if this node has side effects.
    pub fn hasSideEffects(self: *const Node) bool {
        return switch (self.data) {
            .store_local,
            .ptr_store,
            .ptr_store_value,
            .ptr_field_store,
            .call,
            .ret,
            .jump,
            .branch,
            .list_new,
            .list_push,
            .list_set,
            .list_free,
            .map_new,
            .map_set,
            .map_free,
            .file_write,
            .file_free,
            => true,
            else => false,
        };
    }

    /// Get all NodeIndex references in this node (for use tracking).
    /// Returns a slice of all node references.
    pub fn getNodeRefs(self: *const Node, allocator: Allocator) ![]NodeIndex {
        var refs = std.ArrayList(NodeIndex){ .items = &.{}, .capacity = 0 };

        switch (self.data) {
            .const_int, .const_float, .const_bool, .const_null, .const_slice => {},
            .local_ref, .addr_local, .load_local => {},
            .nop, .list_new, .map_new, .args_count => {},

            .store_local => |s| try refs.append(allocator, s.value),
            .binary => |b| {
                try refs.append(allocator, b.left);
                try refs.append(allocator, b.right);
            },
            .unary => |u| try refs.append(allocator, u.operand),
            .field_local => {},
            .store_local_field => |s| try refs.append(allocator, s.value),
            .field_value => |f| try refs.append(allocator, f.base),
            .index_local => |i| try refs.append(allocator, i.index),
            .index_value => |i| {
                try refs.append(allocator, i.base);
                try refs.append(allocator, i.index);
            },
            .slice_local => |s| {
                try refs.append(allocator, s.start);
                try refs.append(allocator, s.end);
            },
            .slice_value => |s| {
                try refs.append(allocator, s.base);
                try refs.append(allocator, s.start);
                try refs.append(allocator, s.end);
            },
            .slice_index => |s| try refs.append(allocator, s.index),
            .ptr_load => {},
            .ptr_store => |p| try refs.append(allocator, p.value),
            .ptr_field => {},
            .ptr_field_store => |p| try refs.append(allocator, p.value),
            .ptr_load_value => |p| try refs.append(allocator, p.ptr),
            .ptr_store_value => |p| {
                try refs.append(allocator, p.ptr);
                try refs.append(allocator, p.value);
            },
            .addr_offset => |a| try refs.append(allocator, a.base),
            .addr_index => |a| {
                try refs.append(allocator, a.base);
                try refs.append(allocator, a.index);
            },
            .call => |c| {
                for (c.args) |arg| {
                    try refs.append(allocator, arg);
                }
            },
            .ret => |r| {
                if (r.value) |v| try refs.append(allocator, v);
            },
            .jump => {},
            .branch => |b| try refs.append(allocator, b.condition),
            .phi => |p| {
                for (p.sources) |s| {
                    try refs.append(allocator, s.value);
                }
            },
            .select => |s| {
                try refs.append(allocator, s.condition);
                try refs.append(allocator, s.then_value);
                try refs.append(allocator, s.else_value);
            },
            .list_push => |l| {
                try refs.append(allocator, l.handle);
                try refs.append(allocator, l.value);
            },
            .list_get => |l| {
                try refs.append(allocator, l.handle);
                try refs.append(allocator, l.index);
            },
            .list_set => |l| {
                try refs.append(allocator, l.handle);
                try refs.append(allocator, l.index);
                try refs.append(allocator, l.value);
            },
            .list_len => |l| try refs.append(allocator, l.handle),
            .list_free => |l| try refs.append(allocator, l.handle),
            .list_data_ptr => |l| try refs.append(allocator, l.handle),
            .list_byte_size => |l| try refs.append(allocator, l.handle),
            .map_set => |m| {
                try refs.append(allocator, m.handle);
                try refs.append(allocator, m.key_ptr);
                try refs.append(allocator, m.key_len);
                try refs.append(allocator, m.value);
            },
            .map_get => |m| {
                try refs.append(allocator, m.handle);
                try refs.append(allocator, m.key_ptr);
                try refs.append(allocator, m.key_len);
            },
            .map_has => |m| {
                try refs.append(allocator, m.handle);
                try refs.append(allocator, m.key_ptr);
                try refs.append(allocator, m.key_len);
            },
            .map_size => |m| try refs.append(allocator, m.handle),
            .map_free => |m| try refs.append(allocator, m.handle),
            .str_concat => |s| {
                try refs.append(allocator, s.left);
                try refs.append(allocator, s.right);
            },
            .union_init => |u| {
                if (u.payload) |p| try refs.append(allocator, p);
            },
            .union_tag => |u| try refs.append(allocator, u.value),
            .union_payload => |u| try refs.append(allocator, u.value),
            .file_read => |f| try refs.append(allocator, f.path),
            .file_write => |f| {
                try refs.append(allocator, f.path);
                try refs.append(allocator, f.data_ptr);
                try refs.append(allocator, f.data_len);
            },
            .file_exists => |f| try refs.append(allocator, f.path),
            .file_free => |f| try refs.append(allocator, f.ptr),
            .args_get => |a| try refs.append(allocator, a.index),
            .convert => |c| try refs.append(allocator, c.operand),
            .ptr_cast => |p| try refs.append(allocator, p.operand),
        }

        return refs.toOwnedSlice(allocator);
    }
};

// ============================================================================
// Basic Block
// ============================================================================

/// A basic block is a sequence of operations with single entry/exit.
pub const Block = struct {
    /// Block index (for identification).
    index: BlockIndex,
    /// Predecessor blocks.
    preds: []const BlockIndex,
    /// Successor blocks.
    succs: []const BlockIndex,
    /// Nodes in this block (in order).
    nodes: []const NodeIndex,
    /// Optional label for debugging.
    label: []const u8,

    pub fn init(index: BlockIndex) Block {
        return .{
            .index = index,
            .preds = &.{},
            .succs = &.{},
            .nodes = &.{},
            .label = "",
        };
    }
};

// ============================================================================
// Local Variable
// ============================================================================

/// A local variable in a function.
pub const Local = struct {
    /// Variable name.
    name: []const u8,
    /// Variable type.
    type_idx: TypeIndex,
    /// Is this variable mutable?
    mutable: bool,
    /// Is this a parameter?
    is_param: bool,
    /// Parameter index (if is_param).
    param_idx: ParamIdx,
    /// Size in bytes (computed from type).
    size: u32,
    /// Stack frame offset.
    offset: i32,

    pub fn init(name: []const u8, type_idx: TypeIndex, mutable: bool) Local {
        return .{
            .name = name,
            .type_idx = type_idx,
            .mutable = mutable,
            .is_param = false,
            .param_idx = 0,
            .size = 8,
            .offset = 0,
        };
    }

    pub fn initParam(name: []const u8, type_idx: TypeIndex, param_idx: ParamIdx, size: u32) Local {
        return .{
            .name = name,
            .type_idx = type_idx,
            .mutable = false,
            .is_param = true,
            .param_idx = param_idx,
            .size = size,
            .offset = 0,
        };
    }

    pub fn initWithSize(name: []const u8, type_idx: TypeIndex, mutable: bool, size: u32) Local {
        return .{
            .name = name,
            .type_idx = type_idx,
            .mutable = mutable,
            .is_param = false,
            .param_idx = 0,
            .size = size,
            .offset = 0,
        };
    }
};

// ============================================================================
// Function
// ============================================================================

/// A function in the IR.
pub const Func = struct {
    /// Function name.
    name: []const u8,
    /// Function type.
    type_idx: TypeIndex,
    /// Return type.
    return_type: TypeIndex,
    /// Parameters.
    params: []const Local,
    /// Local variables (includes parameters).
    locals: []const Local,
    /// Basic blocks.
    blocks: []const Block,
    /// Entry block index.
    entry: BlockIndex,
    /// All nodes in the function.
    nodes: []const Node,
    /// Source span.
    span_start: i32,
    span_end: i32,
    /// Stack frame size.
    frame_size: i32,
};

// ============================================================================
// Function Builder
// ============================================================================

/// Builder for constructing functions with proper ownership.
pub const FuncBuilder = struct {
    allocator: Allocator,
    name: []const u8,
    type_idx: TypeIndex,
    return_type: TypeIndex,
    span_start: i32,
    span_end: i32,

    locals: std.ArrayList(Local),
    blocks: std.ArrayList(Block),
    nodes: std.ArrayList(Node),
    current_block: BlockIndex,

    // Block building state
    block_nodes: std.ArrayList(NodeIndex),

    // Name to local index mapping
    local_map: std.StringHashMap(LocalIdx),

    // Max struct return size from function calls (for frame allocation)
    max_call_ret_size: u32,

    pub fn init(allocator: Allocator, name: []const u8, type_idx: TypeIndex, return_type: TypeIndex, span_start: i32, span_end: i32) FuncBuilder {
        var fb = FuncBuilder{
            .allocator = allocator,
            .name = name,
            .type_idx = type_idx,
            .return_type = return_type,
            .span_start = span_start,
            .span_end = span_end,
            .locals = .{ .items = &.{}, .capacity = 0 },
            .blocks = .{ .items = &.{}, .capacity = 0 },
            .nodes = .{ .items = &.{}, .capacity = 0 },
            .current_block = 0,
            .block_nodes = .{ .items = &.{}, .capacity = 0 },
            .local_map = std.StringHashMap(LocalIdx).init(allocator),
            .max_call_ret_size = 0,
        };

        // Create entry block
        fb.blocks.append(allocator, Block.init(0)) catch {};

        return fb;
    }

    /// Initialize with a Span (convenience for Builder.startFunc)
    pub fn initWithSpan(allocator: Allocator, name: []const u8, type_idx: TypeIndex, return_type: TypeIndex, span: Span) FuncBuilder {
        return init(allocator, name, type_idx, return_type, @intCast(span.start.offset), @intCast(span.end.offset));
    }

    pub fn deinit(self: *FuncBuilder) void {
        self.locals.deinit(self.allocator);
        self.blocks.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        self.block_nodes.deinit(self.allocator);
        self.local_map.deinit();
    }

    /// Add a local variable, return its index.
    pub fn addLocal(self: *FuncBuilder, local: Local) !LocalIdx {
        const idx: LocalIdx = @intCast(self.locals.items.len);
        try self.locals.append(self.allocator, local);
        try self.local_map.put(local.name, idx);
        return idx;
    }

    /// Add a parameter with explicit size.
    pub fn addParam(self: *FuncBuilder, name: []const u8, type_idx: TypeIndex, size: u32) !LocalIdx {
        const idx: LocalIdx = @intCast(self.locals.items.len);
        const param_idx: ParamIdx = idx; // params are first
        try self.locals.append(self.allocator, Local.initParam(name, type_idx, param_idx, size));
        try self.local_map.put(name, idx);
        return idx;
    }

    /// Add a local variable with explicit size.
    pub fn addLocalWithSize(self: *FuncBuilder, name: []const u8, type_idx: TypeIndex, mutable: bool, size: u32) !LocalIdx {
        const idx: LocalIdx = @intCast(self.locals.items.len);
        try self.locals.append(self.allocator, Local.initWithSize(name, type_idx, mutable, size));
        try self.local_map.put(name, idx);
        return idx;
    }

    /// Look up a local by name.
    pub fn lookupLocal(self: *const FuncBuilder, name: []const u8) ?LocalIdx {
        return self.local_map.get(name);
    }

    /// Create a new basic block.
    pub fn newBlock(self: *FuncBuilder, label: []const u8) !BlockIndex {
        const idx: BlockIndex = @intCast(self.blocks.items.len);
        var block = Block.init(idx);
        block.label = label;
        try self.blocks.append(self.allocator, block);
        return idx;
    }

    /// Set current block for emitting nodes.
    pub fn setBlock(self: *FuncBuilder, block: BlockIndex) void {
        self.current_block = block;
    }

    /// Start a new basic block (legacy name, calls newBlock and setBlock).
    pub fn startBlock(self: *FuncBuilder, label: []const u8) !BlockIndex {
        // Finish current block if it has nodes
        if (self.block_nodes.items.len > 0) {
            try self.finishBlock();
        }

        const idx = try self.newBlock(label);
        self.setBlock(idx);
        return idx;
    }

    /// Finish the current block.
    fn finishBlock(self: *FuncBuilder) !void {
        if (self.current_block < self.blocks.items.len) {
            self.blocks.items[self.current_block].nodes = try self.block_nodes.toOwnedSlice(self.allocator);
        }
        self.block_nodes = .{ .items = &.{}, .capacity = 0 };
    }

    /// Emit a node to the current block.
    pub fn emit(self: *FuncBuilder, node: Node) !NodeIndex {
        const idx: NodeIndex = @intCast(self.nodes.items.len);
        var n = node;
        n.block = self.current_block;
        try self.nodes.append(self.allocator, n);

        // Add to current block's node list
        var block = &self.blocks.items[self.current_block];
        var block_nodes_list = std.ArrayList(NodeIndex){ .items = &.{}, .capacity = 0 };
        for (block.nodes) |ni| {
            try block_nodes_list.append(self.allocator, ni);
        }
        try block_nodes_list.append(self.allocator, idx);
        block.nodes = try block_nodes_list.toOwnedSlice(self.allocator);

        return idx;
    }

    // ========================================================================
    // Convenience emit methods - make common patterns easy and type-safe
    // ========================================================================

    /// Emit integer constant.
    pub fn emitConstInt(self: *FuncBuilder, value: i64, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .const_int = .{ .value = value } }, TypeRegistry.INT, span));
    }

    /// Emit integer constant with specific type.
    pub fn emitConstIntTyped(self: *FuncBuilder, value: i64, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .const_int = .{ .value = value } }, type_idx, span));
    }

    /// Emit float constant.
    pub fn emitConstFloat(self: *FuncBuilder, value: f64, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .const_float = .{ .value = value } }, TypeRegistry.FLOAT, span));
    }

    /// Emit boolean constant.
    pub fn emitConstBool(self: *FuncBuilder, value: bool, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .const_bool = .{ .value = value } }, TypeRegistry.BOOL, span));
    }

    /// Emit string literal reference.
    pub fn emitConstSlice(self: *FuncBuilder, string_index: StringIdx, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .const_slice = .{ .string_index = string_index } }, type_idx, span));
    }

    /// Emit null constant.
    pub fn emitConstNull(self: *FuncBuilder, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .const_null = {} }, type_idx, span));
    }

    /// Emit load from local variable.
    pub fn emitLoadLocal(self: *FuncBuilder, local_idx: LocalIdx, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .load_local = .{ .local_idx = local_idx } }, type_idx, span));
    }

    /// Emit store to local variable.
    pub fn emitStoreLocal(self: *FuncBuilder, local_idx: LocalIdx, value: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .store_local = .{ .local_idx = local_idx, .value = value } }, TypeRegistry.VOID, span));
    }

    /// Emit binary operation.
    pub fn emitBinary(self: *FuncBuilder, op: BinaryOp, left: NodeIndex, right: NodeIndex, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .binary = .{ .op = op, .left = left, .right = right } }, type_idx, span));
    }

    /// Emit unary operation.
    pub fn emitUnary(self: *FuncBuilder, op: UnaryOp, operand: NodeIndex, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .unary = .{ .op = op, .operand = operand } }, type_idx, span));
    }

    /// Emit field access from local struct.
    pub fn emitFieldLocal(self: *FuncBuilder, local_idx: LocalIdx, offset: i64, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .field_local = .{ .local_idx = local_idx, .offset = offset } }, type_idx, span));
    }

    /// Emit store to field in local struct.
    pub fn emitStoreLocalField(self: *FuncBuilder, local_idx: LocalIdx, offset: i64, value: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .store_local_field = .{ .local_idx = local_idx, .offset = offset, .value = value } }, TypeRegistry.VOID, span));
    }

    /// Emit field access from computed value.
    pub fn emitFieldValue(self: *FuncBuilder, base: NodeIndex, offset: i64, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .field_value = .{ .base = base, .offset = offset } }, type_idx, span));
    }

    /// Emit address of local variable.
    pub fn emitAddrLocal(self: *FuncBuilder, local_idx: LocalIdx, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .addr_local = .{ .local_idx = local_idx } }, type_idx, span));
    }

    /// Emit address offset computation (base + constant offset).
    pub fn emitAddrOffset(self: *FuncBuilder, base: NodeIndex, offset: i64, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .addr_offset = .{ .base = base, .offset = offset } }, type_idx, span));
    }

    /// Emit address index computation (base + index * elem_size).
    pub fn emitAddrIndex(self: *FuncBuilder, base: NodeIndex, index: NodeIndex, elem_size: u32, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .addr_index = .{ .base = base, .index = index, .elem_size = elem_size } }, type_idx, span));
    }

    /// Emit pointer load through local.
    pub fn emitPtrLoad(self: *FuncBuilder, ptr_local: LocalIdx, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .ptr_load = .{ .ptr_local = ptr_local } }, type_idx, span));
    }

    /// Emit pointer store through local.
    pub fn emitPtrStore(self: *FuncBuilder, ptr_local: LocalIdx, value: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .ptr_store = .{ .ptr_local = ptr_local, .value = value } }, TypeRegistry.VOID, span));
    }

    /// Emit field load through pointer in local.
    pub fn emitPtrField(self: *FuncBuilder, ptr_local: LocalIdx, offset: i64, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .ptr_field = .{ .ptr_local = ptr_local, .offset = offset } }, type_idx, span));
    }

    /// Emit field store through pointer in local.
    pub fn emitPtrFieldStore(self: *FuncBuilder, ptr_local: LocalIdx, offset: i64, value: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .ptr_field_store = .{ .ptr_local = ptr_local, .offset = offset, .value = value } }, TypeRegistry.VOID, span));
    }

    /// Emit pointer load through computed pointer value.
    pub fn emitPtrLoadValue(self: *FuncBuilder, ptr: NodeIndex, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .ptr_load_value = .{ .ptr = ptr } }, type_idx, span));
    }

    /// Emit pointer store through computed pointer value.
    pub fn emitPtrStoreValue(self: *FuncBuilder, ptr: NodeIndex, value: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .ptr_store_value = .{ .ptr = ptr, .value = value } }, TypeRegistry.VOID, span));
    }

    /// Emit index into local array/slice.
    pub fn emitIndexLocal(self: *FuncBuilder, local_idx: LocalIdx, index: NodeIndex, elem_size: u32, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .index_local = .{ .local_idx = local_idx, .index = index, .elem_size = elem_size } }, type_idx, span));
    }

    /// Emit index into computed array/slice.
    pub fn emitIndexValue(self: *FuncBuilder, base: NodeIndex, index: NodeIndex, elem_size: u32, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .index_value = .{ .base = base, .index = index, .elem_size = elem_size } }, type_idx, span));
    }

    /// Emit slice index operation.
    pub fn emitSliceIndex(self: *FuncBuilder, slice_local: LocalIdx, index: NodeIndex, elem_size: u32, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .slice_index = .{ .slice_local = slice_local, .index = index, .elem_size = elem_size } }, type_idx, span));
    }

    /// Emit function call.
    pub fn emitCall(self: *FuncBuilder, func_name: []const u8, args: []const NodeIndex, is_builtin: bool, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .call = .{ .func_name = func_name, .args = args, .is_builtin = is_builtin } }, type_idx, span));
    }

    /// Emit return.
    pub fn emitRet(self: *FuncBuilder, value: ?NodeIndex, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .ret = .{ .value = value } }, type_idx, span));
    }

    /// Emit unconditional jump.
    pub fn emitJump(self: *FuncBuilder, target: BlockIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .jump = .{ .target = target } }, TypeRegistry.VOID, span));
    }

    /// Emit conditional branch.
    pub fn emitBranch(self: *FuncBuilder, condition: NodeIndex, then_block: BlockIndex, else_block: BlockIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .branch = .{ .condition = condition, .then_block = then_block, .else_block = else_block } }, TypeRegistry.VOID, span));
    }

    /// Emit select (ternary).
    pub fn emitSelect(self: *FuncBuilder, condition: NodeIndex, then_value: NodeIndex, else_value: NodeIndex, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .select = .{ .condition = condition, .then_value = then_value, .else_value = else_value } }, type_idx, span));
    }

    /// Emit list new.
    pub fn emitListNew(self: *FuncBuilder, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .list_new = {} }, type_idx, span));
    }

    /// Emit list push.
    pub fn emitListPush(self: *FuncBuilder, handle: NodeIndex, value: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .list_push = .{ .handle = handle, .value = value } }, TypeRegistry.VOID, span));
    }

    /// Emit list get.
    pub fn emitListGet(self: *FuncBuilder, handle: NodeIndex, index: NodeIndex, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .list_get = .{ .handle = handle, .index = index } }, type_idx, span));
    }

    /// Emit list set.
    pub fn emitListSet(self: *FuncBuilder, handle: NodeIndex, index: NodeIndex, value: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .list_set = .{ .handle = handle, .index = index, .value = value } }, TypeRegistry.VOID, span));
    }

    /// Emit list len.
    pub fn emitListLen(self: *FuncBuilder, handle: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .list_len = .{ .handle = handle } }, TypeRegistry.INT, span));
    }

    /// Emit map new.
    pub fn emitMapNew(self: *FuncBuilder, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .map_new = {} }, type_idx, span));
    }

    /// Emit map set.
    pub fn emitMapSet(self: *FuncBuilder, handle: NodeIndex, key_ptr: NodeIndex, key_len: NodeIndex, value: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .map_set = .{ .handle = handle, .key_ptr = key_ptr, .key_len = key_len, .value = value } }, TypeRegistry.VOID, span));
    }

    /// Emit map get.
    pub fn emitMapGet(self: *FuncBuilder, handle: NodeIndex, key_ptr: NodeIndex, key_len: NodeIndex, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .map_get = .{ .handle = handle, .key_ptr = key_ptr, .key_len = key_len } }, type_idx, span));
    }

    /// Emit string concat.
    pub fn emitStrConcat(self: *FuncBuilder, left: NodeIndex, right: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .str_concat = .{ .left = left, .right = right } }, TypeRegistry.STRING, span));
    }

    /// Emit union init.
    pub fn emitUnionInit(self: *FuncBuilder, variant_idx: u32, payload: ?NodeIndex, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .union_init = .{ .variant_idx = variant_idx, .payload = payload } }, type_idx, span));
    }

    /// Emit union tag.
    pub fn emitUnionTag(self: *FuncBuilder, value: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .union_tag = .{ .value = value } }, TypeRegistry.INT, span));
    }

    /// Emit union payload.
    pub fn emitUnionPayload(self: *FuncBuilder, variant_idx: u32, value: NodeIndex, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .union_payload = .{ .variant_idx = variant_idx, .value = value } }, type_idx, span));
    }

    /// Emit type conversion.
    pub fn emitConvert(self: *FuncBuilder, operand: NodeIndex, from_type: TypeIndex, to_type: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .convert = .{ .operand = operand, .from_type = from_type, .to_type = to_type } }, to_type, span));
    }

    /// Emit file read.
    pub fn emitFileRead(self: *FuncBuilder, path: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .file_read = .{ .path = path } }, TypeRegistry.STRING, span));
    }

    /// Emit file write.
    pub fn emitFileWrite(self: *FuncBuilder, path: NodeIndex, data_ptr: NodeIndex, data_len: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .file_write = .{ .path = path, .data_ptr = data_ptr, .data_len = data_len } }, TypeRegistry.INT, span));
    }

    /// Emit file exists check.
    pub fn emitFileExists(self: *FuncBuilder, path: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .file_exists = .{ .path = path } }, TypeRegistry.INT, span));
    }

    /// Emit file free.
    pub fn emitFileFree(self: *FuncBuilder, ptr: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .file_free = .{ .ptr = ptr } }, TypeRegistry.VOID, span));
    }

    /// Emit list data pointer.
    pub fn emitListDataPtr(self: *FuncBuilder, handle: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .list_data_ptr = .{ .handle = handle } }, TypeRegistry.INT, span));
    }

    /// Emit list byte size.
    pub fn emitListByteSize(self: *FuncBuilder, handle: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .list_byte_size = .{ .handle = handle } }, TypeRegistry.INT, span));
    }

    /// Emit args count.
    pub fn emitArgsCount(self: *FuncBuilder, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .args_count = {} }, TypeRegistry.INT, span));
    }

    /// Emit args get.
    pub fn emitArgsGet(self: *FuncBuilder, index: NodeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .args_get = .{ .index = index } }, TypeRegistry.STRING, span));
    }

    /// Emit nop.
    pub fn emitNop(self: *FuncBuilder, span: Span) !NodeIndex {
        return self.emit(Node.init(.{ .nop = {} }, TypeRegistry.VOID, span));
    }

    // ========================================================================
    // End convenience methods
    // ========================================================================

    /// Build the final function.
    /// Computes stack frame layout: assigns offsets to locals and calculates total frame size.
    pub fn build(self: *FuncBuilder) !Func {
        // Finish last block
        if (self.block_nodes.items.len > 0) {
            try self.finishBlock();
        }

        // Collect parameters
        var params = std.ArrayList(Local){ .items = &.{}, .capacity = 0 };
        for (self.locals.items) |local| {
            if (local.is_param) {
                try params.append(self.allocator, local);
            }
        }

        // Compute stack frame layout (like Go's AllocFrame)
        // Assign sequential offsets to each local based on their sizes
        var frame_offset: i32 = 0;
        for (self.locals.items) |*local| {
            // Round up to 8-byte alignment (standard for 64-bit values)
            frame_offset = roundUp(frame_offset, 8);
            // Assign offset (negative for x86/rbp-relative)
            local.offset = -frame_offset - @as(i32, @intCast(local.size));
            // Advance by variable size
            frame_offset += @as(i32, @intCast(local.size));
        }

        // Add space for struct return temps (from function calls)
        frame_offset += @as(i32, @intCast(self.max_call_ret_size));

        // Round total frame size to 16-byte alignment (ABI requirement)
        const frame_size: i32 = roundUp(frame_offset, 16);

        return Func{
            .name = self.name,
            .type_idx = self.type_idx,
            .return_type = self.return_type,
            .params = try params.toOwnedSlice(self.allocator),
            .locals = try self.locals.toOwnedSlice(self.allocator),
            .blocks = try self.blocks.toOwnedSlice(self.allocator),
            .entry = 0,
            .nodes = try self.nodes.toOwnedSlice(self.allocator),
            .span_start = self.span_start,
            .span_end = self.span_end,
            .frame_size = frame_size,
        };
    }

    /// Round up to alignment (must be power of 2)
    fn roundUp(offset: i32, alignment: i32) i32 {
        return (offset + alignment - 1) & ~(alignment - 1);
    }
};

// ============================================================================
// Global Variable
// ============================================================================

/// A global variable or constant.
pub const Global = struct {
    /// Name.
    name: []const u8,
    /// Type.
    type_idx: TypeIndex,
    /// Initializer (optional).
    init_value: ?NodeIndex,
    /// Is this a constant?
    is_const: bool,
    /// Source span.
    span: Span,

    pub fn init(name: []const u8, type_idx: TypeIndex, is_const: bool, span: Span) Global {
        return .{
            .name = name,
            .type_idx = type_idx,
            .init_value = null,
            .is_const = is_const,
            .span = span,
        };
    }
};

// ============================================================================
// Struct Definition
// ============================================================================

/// A struct type definition in IR.
pub const StructDef = struct {
    /// Struct name.
    name: []const u8,
    /// Type index in registry.
    type_idx: TypeIndex,
    /// Source span.
    span: Span,
};

// ============================================================================
// IR Program
// ============================================================================

/// Complete IR for a program/module.
pub const IR = struct {
    /// All functions.
    funcs: []const Func,
    /// All global variables/constants.
    globals: []const Global,
    /// All struct definitions.
    structs: []const StructDef,
    /// Type registry (shared with checker).
    types: *TypeRegistry,
    /// Memory allocator.
    allocator: Allocator,

    pub fn init(allocator: Allocator, type_reg: *TypeRegistry) IR {
        return .{
            .funcs = &.{},
            .globals = &.{},
            .structs = &.{},
            .types = type_reg,
            .allocator = allocator,
        };
    }

    /// Get a function by name.
    pub fn getFunc(self: *const IR, name: []const u8) ?*const Func {
        for (self.funcs) |*f| {
            if (std.mem.eql(u8, f.name, name)) {
                return f;
            }
        }
        return null;
    }

    /// Get a global by name.
    pub fn getGlobal(self: *const IR, name: []const u8) ?*const Global {
        for (self.globals) |*g| {
            if (std.mem.eql(u8, g.name, name)) {
                return g;
            }
        }
        return null;
    }
};

// ============================================================================
// IR Builder
// ============================================================================

/// Helper for building IR from checked AST.
pub const Builder = struct {
    ir: IR,
    allocator: Allocator,

    // Current function being built
    current_func: ?FuncBuilder,

    pub fn init(allocator: Allocator, type_reg: *TypeRegistry) Builder {
        return .{
            .ir = IR.init(allocator, type_reg),
            .allocator = allocator,
            .current_func = null,
        };
    }

    /// Start building a new function.
    pub fn startFunc(self: *Builder, name: []const u8, type_idx: TypeIndex, return_type: TypeIndex, span: Span) void {
        self.current_func = FuncBuilder.initWithSpan(self.allocator, name, type_idx, return_type, span);
    }

    /// Finish the current function and add to IR.
    pub fn endFunc(self: *Builder) !void {
        if (self.current_func) |*fb| {
            const func = try fb.build();

            // Add to funcs list
            var funcs = std.ArrayList(Func){ .items = &.{}, .capacity = 0 };
            for (self.ir.funcs) |f| {
                try funcs.append(self.allocator, f);
            }
            try funcs.append(self.allocator, func);
            self.ir.funcs = try funcs.toOwnedSlice(self.allocator);

            self.current_func = null;
        }
    }

    /// Add a global variable.
    pub fn addGlobal(self: *Builder, g: Global) !void {
        var globals = std.ArrayList(Global){ .items = &.{}, .capacity = 0 };
        for (self.ir.globals) |glob| {
            try globals.append(self.allocator, glob);
        }
        try globals.append(self.allocator, g);
        self.ir.globals = try globals.toOwnedSlice(self.allocator);
    }

    /// Add a struct definition.
    pub fn addStruct(self: *Builder, s: StructDef) !void {
        var structs = std.ArrayList(StructDef){ .items = &.{}, .capacity = 0 };
        for (self.ir.structs) |st| {
            try structs.append(self.allocator, st);
        }
        try structs.append(self.allocator, s);
        self.ir.structs = try structs.toOwnedSlice(self.allocator);
    }

    /// Get the built IR.
    pub fn getIR(self: *Builder) IR {
        return self.ir;
    }
};

// ============================================================================
// Debug Printing
// ============================================================================

pub fn debugPrintNode(node: *const Node, writer: anytype) !void {
    switch (node.data) {
        .const_int => |c| try writer.print("const_int {d}", .{c.value}),
        .const_float => |c| try writer.print("const_float {d}", .{c.value}),
        .const_bool => |c| try writer.print("const_bool {}", .{c.value}),
        .const_null => try writer.print("const_null", .{}),
        .const_slice => |c| try writer.print("const_slice idx={d}", .{c.string_index}),

        .local_ref => |l| try writer.print("local_ref local={d}", .{l.local_idx}),
        .addr_local => |l| try writer.print("addr_local local={d}", .{l.local_idx}),
        .load_local => |l| try writer.print("load_local local={d}", .{l.local_idx}),
        .store_local => |s| try writer.print("store_local local={d} value={d}", .{ s.local_idx, s.value }),

        .binary => |b| try writer.print("binary {s} left={d} right={d}", .{ @tagName(b.op), b.left, b.right }),
        .unary => |u| try writer.print("unary {s} operand={d}", .{ @tagName(u.op), u.operand }),

        .field_local => |f| try writer.print("field_local local={d} offset={d}", .{ f.local_idx, f.offset }),
        .field_value => |f| try writer.print("field_value base={d} offset={d}", .{ f.base, f.offset }),

        .addr_offset => |a| try writer.print("addr_offset base={d} offset={d}", .{ a.base, a.offset }),

        .call => |c| try writer.print("call {s} args={d}", .{ c.func_name, c.args.len }),
        .ret => |r| {
            if (r.value) |v| {
                try writer.print("ret value={d}", .{v});
            } else {
                try writer.print("ret void", .{});
            }
        },
        .jump => |j| try writer.print("jump block={d}", .{j.target}),
        .branch => |b| try writer.print("branch cond={d} then={d} else={d}", .{ b.condition, b.then_block, b.else_block }),

        else => try writer.print("{s}", .{@tagName(node.data)}),
    }
}

// ============================================================================
// Tests
// ============================================================================

test "strongly typed node creation" {
    const allocator = std.testing.allocator;

    // Create a const_int node
    const int_node = Node.init(
        .{ .const_int = .{ .value = 42 } },
        TypeRegistry.INT,
        Span.fromPos(Pos.zero),
    );
    try std.testing.expectEqual(@as(i64, 42), int_node.data.const_int.value);

    // Create a binary add node
    const add_node = Node.init(
        .{ .binary = .{ .op = .add, .left = 0, .right = 1 } },
        TypeRegistry.INT,
        Span.fromPos(Pos.zero),
    );
    try std.testing.expectEqual(BinaryOp.add, add_node.data.binary.op);
    try std.testing.expectEqual(@as(NodeIndex, 0), add_node.data.binary.left);
    try std.testing.expectEqual(@as(NodeIndex, 1), add_node.data.binary.right);

    // Create a store_local node - demonstrates type safety
    const store_node = Node.init(
        .{ .store_local = .{ .local_idx = 5, .value = 10 } },
        TypeRegistry.VOID,
        Span.fromPos(Pos.zero),
    );
    // local_idx is LocalIdx (u32), value is NodeIndex (u32) - but semantically distinct
    try std.testing.expectEqual(@as(LocalIdx, 5), store_node.data.store_local.local_idx);
    try std.testing.expectEqual(@as(NodeIndex, 10), store_node.data.store_local.value);

    // Test getNodeRefs
    const refs = try add_node.getNodeRefs(allocator);
    defer allocator.free(refs);
    try std.testing.expectEqual(@as(usize, 2), refs.len);
    try std.testing.expectEqual(@as(NodeIndex, 0), refs[0]);
    try std.testing.expectEqual(@as(NodeIndex, 1), refs[1]);
}

test "function builder" {
    // Use arena allocator to avoid tracking all the intermediate allocations
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var fb = FuncBuilder.init(allocator, "test", 0, TypeRegistry.INT, 0, 100);
    // No need for defer fb.deinit() - arena handles cleanup

    // Add a local
    const local_idx = try fb.addLocal(Local.init("x", TypeRegistry.INT, true));
    try std.testing.expectEqual(@as(LocalIdx, 0), local_idx);

    // FuncBuilder.init already creates entry block (index 0), so startBlock creates block 1
    const block_idx = try fb.startBlock("then");
    try std.testing.expectEqual(@as(BlockIndex, 1), block_idx);

    // Emit a const_int
    const const_node = try fb.emit(Node.init(
        .{ .const_int = .{ .value = 42 } },
        TypeRegistry.INT,
        Span.fromPos(Pos.zero),
    ));
    try std.testing.expectEqual(@as(NodeIndex, 0), const_node);

    // Emit a store
    _ = try fb.emit(Node.init(
        .{ .store_local = .{ .local_idx = local_idx, .value = const_node } },
        TypeRegistry.VOID,
        Span.fromPos(Pos.zero),
    ));

    // Emit a return
    _ = try fb.emit(Node.init(
        .{ .ret = .{ .value = const_node } },
        TypeRegistry.INT,
        Span.fromPos(Pos.zero),
    ));

    // Build the function
    const func = try fb.build();
    try std.testing.expectEqual(@as(usize, 1), func.locals.len);
    try std.testing.expectEqual(@as(usize, 3), func.nodes.len);
    // Entry block (0) + then block (1) = 2 blocks
    try std.testing.expectEqual(@as(usize, 2), func.blocks.len);
}
