///! Typed Intermediate Representation for cot.
///!
///! Maps to Go's cmd/compile/internal/ir/
///! - node.go (Node types)
///! - func.go (Function representation)
///! - expr.go, stmt.go (lowered operations)
///!
///! The IR is a typed, lowered form of the AST:
///! - All types are resolved (TypeIndex, not type expressions)
///! - Control flow is explicit (no for-in, only indexed loops)
///! - Compound assignments desugared (a += b → a = a + b)
///! - Method calls become function calls with receiver

const std = @import("std");
const types = @import("types.zig");
const source = @import("source.zig");

const TypeIndex = types.TypeIndex;
const TypeRegistry = types.TypeRegistry;
const Span = source.Span;
const Pos = source.Pos;

// ============================================================================
// Node Index
// ============================================================================

/// Index into IR node pool.
pub const NodeIndex = u32;
pub const null_node: NodeIndex = std.math.maxInt(NodeIndex);

/// Index into block pool.
pub const BlockIndex = u32;
pub const null_block: BlockIndex = std.math.maxInt(BlockIndex);

// ============================================================================
// Operations
// ============================================================================

/// IR operations (opcodes).
/// These are lower-level than AST nodes.
pub const Op = enum(u8) {
    // ========== Constants ==========
    /// Integer constant. aux = value
    const_int,
    /// Float constant. aux_float = value
    const_float,
    /// String constant. aux_str = value
    const_string,
    /// Boolean constant. aux = 0 or 1
    const_bool,
    /// Null constant.
    const_null,

    // ========== Variables ==========
    /// Local variable reference. aux = local index
    local,
    /// Global variable reference. aux_str = name
    global,
    /// Parameter reference. aux = param index
    param,

    // ========== Arithmetic ==========
    /// Add two values.
    add,
    /// Subtract two values.
    sub,
    /// Multiply two values.
    mul,
    /// Divide two values.
    div,
    /// Modulo (remainder).
    mod,
    /// Negate value.
    neg,

    // ========== Comparison ==========
    /// Equal.
    eq,
    /// Not equal.
    ne,
    /// Less than.
    lt,
    /// Less than or equal.
    le,
    /// Greater than.
    gt,
    /// Greater than or equal.
    ge,

    // ========== Logical ==========
    /// Logical AND.
    @"and",
    /// Logical OR.
    @"or",
    /// Logical NOT.
    not,

    // ========== Bitwise ==========
    /// Bitwise AND.
    bit_and,
    /// Bitwise OR.
    bit_or,
    /// Bitwise XOR.
    bit_xor,
    /// Bitwise NOT.
    bit_not,
    /// Shift left.
    shl,
    /// Shift right.
    shr,

    // ========== Memory ==========
    /// Load from address.
    load,
    /// Store to address. args[0] = addr, args[1] = value
    store,
    /// Get address of local. aux = local index
    addr_local,
    /// Get field address. aux = field offset, args[0] = struct addr
    addr_field,
    /// Get array element address. args[0] = array addr, args[1] = index
    addr_index,
    /// Load field through pointer. args[0] = local holding ptr, aux = field offset
    ptr_field,

    // ========== Struct/Array/Union ==========
    /// Get struct field. aux = field index, args[0] = struct value
    field,
    /// Get array/slice element. args[0] = array, args[1] = index
    index,
    /// Slice operation. args[0] = array, args[1] = start, args[2] = end
    slice,
    /// Index into slice. args[0] = slice local, args[1] = index. aux = elem_size
    slice_index,
    /// Initialize union. aux = variant index (tag), args[0] = payload (if any)
    union_init,
    /// Get union tag. args[0] = union value
    union_tag,
    /// Get union payload. aux = variant index, args[0] = union value
    union_payload,

    // ========== Map Operations (runtime calls) ==========
    /// Create new map. Returns handle pointer.
    map_new,
    /// Set key-value. args[0] = handle, args[1] = key_ptr, args[2] = key_len, args[3] = value
    map_set,
    /// Get value by key. args[0] = handle, args[1] = key_ptr, args[2] = key_len
    map_get,
    /// Check if key exists. args[0] = handle, args[1] = key_ptr, args[2] = key_len
    map_has,
    /// Get map size. args[0] = handle
    map_size,
    /// Free map. args[0] = handle
    map_free,

    // ========== List Operations (native layout + FFI) ==========
    /// Create new list. Returns handle pointer.
    list_new,
    /// Push element. args[0] = handle, args[1] = value
    list_push,
    /// Get element by index. args[0] = handle, args[1] = index
    list_get,
    /// Get list length. args[0] = handle
    list_len,
    /// Free list. args[0] = handle
    list_free,

    // ========== Control Flow ==========
    /// Function call. args[0] = func, args[1..] = arguments
    call,
    /// Return from function. args[0] = value (optional)
    ret,
    /// Unconditional jump. aux = target block
    jump,
    /// Conditional branch. args[0] = cond, aux = true block, aux2 = false block
    branch,
    /// Phi node (SSA). args = values from predecessors
    phi,
    /// Select (ternary). args[0] = cond, args[1] = true_val, args[2] = false_val
    select,

    // ========== Conversions ==========
    /// Convert between numeric types.
    convert,
    /// Pointer cast.
    ptr_cast,

    // ========== Misc ==========
    /// No operation (placeholder).
    nop,

    pub fn isTerminator(self: Op) bool {
        return switch (self) {
            .ret, .jump, .branch => true,
            else => false,
        };
    }

    pub fn hasSideEffects(self: Op) bool {
        return switch (self) {
            .store, .call, .ret, .jump, .branch => true,
            // Map operations modify heap state
            .map_new, .map_set, .map_free => true,
            // List operations modify heap state
            .list_new, .list_push, .list_free => true,
            else => false,
        };
    }
};

// ============================================================================
// IR Node
// ============================================================================

/// An IR node represents a single operation.
pub const Node = struct {
    /// Operation type.
    op: Op,
    /// Result type.
    type_idx: TypeIndex,
    /// Inline storage for operand indices (most nodes have 0-3 args).
    args_storage: [4]NodeIndex = .{ 0, 0, 0, 0 },
    /// Number of valid args in args_storage.
    args_len: u8 = 0,
    /// Auxiliary integer data (local index, field offset, etc.)
    aux: i64,
    /// Auxiliary string data (for names).
    aux_str: []const u8,
    /// Source location for error messages.
    span: Span,
    /// Block this node belongs to.
    block: BlockIndex,

    pub fn init(op: Op, type_idx: TypeIndex, span: Span) Node {
        return .{
            .op = op,
            .type_idx = type_idx,
            .args_storage = .{ 0, 0, 0, 0 },
            .args_len = 0,
            .aux = 0,
            .aux_str = "",
            .span = span,
            .block = null_block,
        };
    }

    /// Get args as a slice.
    pub fn args(self: *const Node) []const NodeIndex {
        return self.args_storage[0..self.args_len];
    }

    pub fn withArgs(self: Node, arg_slice: []const NodeIndex) Node {
        var n = self;
        for (arg_slice, 0..) |arg, i| {
            if (i >= 4) break;
            n.args_storage[i] = arg;
        }
        n.args_len = @intCast(@min(arg_slice.len, 4));
        return n;
    }

    pub fn withAux(self: Node, aux: i64) Node {
        var n = self;
        n.aux = aux;
        return n;
    }

    pub fn withAuxStr(self: Node, aux_str: []const u8) Node {
        var n = self;
        n.aux_str = aux_str;
        return n;
    }

    pub fn withBlock(self: Node, block: BlockIndex) Node {
        var n = self;
        n.block = block;
        return n;
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
    /// Stack slot index (deprecated, use offset instead).
    slot: u32,
    /// Is this variable mutable?
    mutable: bool,
    /// Is this a parameter?
    is_param: bool,
    /// Parameter index (if is_param).
    param_idx: u32,
    /// Size in bytes (computed from type).
    size: u32,
    /// Stack frame offset (negative from rbp on x86, positive from sp on arm64).
    offset: i32,

    pub fn init(name: []const u8, type_idx: TypeIndex, slot: u32, mutable: bool) Local {
        return .{
            .name = name,
            .type_idx = type_idx,
            .slot = slot,
            .mutable = mutable,
            .is_param = false,
            .param_idx = 0,
            .size = 8, // Default to 8 bytes, should be computed from type
            .offset = 0, // Will be computed during frame allocation
        };
    }

    pub fn initParam(name: []const u8, type_idx: TypeIndex, param_idx: u32) Local {
        return .{
            .name = name,
            .type_idx = type_idx,
            .slot = param_idx,
            .mutable = false,
            .is_param = true,
            .param_idx = param_idx,
            .size = 8, // Params are typically 8 bytes
            .offset = 0,
        };
    }

    pub fn initWithSize(name: []const u8, type_idx: TypeIndex, slot: u32, mutable: bool, size: u32) Local {
        return .{
            .name = name,
            .type_idx = type_idx,
            .slot = slot,
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
    /// Parameters (subset of locals where is_param = true).
    params: []const Local,
    /// All local variables (including parameters).
    locals: []const Local,
    /// Basic blocks.
    blocks: []const Block,
    /// Entry block index.
    entry: BlockIndex,
    /// All nodes in this function.
    nodes: []const Node,
    /// Source span.
    span: Span,
    /// Total stack frame size (computed from local sizes, aligned to 16 bytes).
    frame_size: u32,

    pub fn init(name: []const u8, type_idx: TypeIndex, return_type: TypeIndex, span: Span) Func {
        return .{
            .name = name,
            .type_idx = type_idx,
            .return_type = return_type,
            .params = &.{},
            .locals = &.{},
            .blocks = &.{},
            .entry = 0,
            .nodes = &.{},
            .span = span,
            .frame_size = 0,
        };
    }
};

// ============================================================================
// Global
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
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, type_reg: *TypeRegistry) IR {
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
    allocator: std.mem.Allocator,

    // Current function being built
    current_func: ?FuncBuilder,

    pub fn init(allocator: std.mem.Allocator, type_reg: *TypeRegistry) Builder {
        return .{
            .ir = IR.init(allocator, type_reg),
            .allocator = allocator,
            .current_func = null,
        };
    }

    /// Start building a new function.
    pub fn startFunc(self: *Builder, name: []const u8, type_idx: TypeIndex, return_type: TypeIndex, span: Span) void {
        self.current_func = FuncBuilder.init(self.allocator, name, type_idx, return_type, span);
    }

    /// Finish the current function and add to IR.
    pub fn endFunc(self: *Builder) !void {
        if (self.current_func) |*fb| {
            const func = try fb.build();

            // Add to funcs list
            var funcs = std.ArrayList(Func){ .items = @constCast(self.ir.funcs), .capacity = self.ir.funcs.len };
            try funcs.append(self.allocator, func);
            self.ir.funcs = try self.allocator.dupe(Func, funcs.items);

            self.current_func = null;
        }
    }

    /// Add a global variable.
    pub fn addGlobal(self: *Builder, g: Global) !void {
        var globals = std.ArrayList(Global){ .items = @constCast(self.ir.globals), .capacity = self.ir.globals.len };
        try globals.append(self.allocator, g);
        self.ir.globals = try self.allocator.dupe(Global, globals.items);
    }

    /// Add a struct definition.
    pub fn addStruct(self: *Builder, s: StructDef) !void {
        var structs = std.ArrayList(StructDef){ .items = @constCast(self.ir.structs), .capacity = self.ir.structs.len };
        try structs.append(self.allocator, s);
        self.ir.structs = try self.allocator.dupe(StructDef, structs.items);
    }

    /// Get the built IR.
    pub fn getIR(self: *Builder) IR {
        return self.ir;
    }
};

// ============================================================================
// Function Builder
// ============================================================================

/// Helper for building a single function.
pub const FuncBuilder = struct {
    name: []const u8,
    type_idx: TypeIndex,
    return_type: TypeIndex,
    span: Span,
    allocator: std.mem.Allocator,

    // Building state
    locals: std.ArrayList(Local),
    blocks: std.ArrayList(Block),
    nodes: std.ArrayList(Node),
    current_block: BlockIndex,
    local_map: std.StringHashMap(u32), // name -> local index

    pub fn init(allocator: std.mem.Allocator, name: []const u8, type_idx: TypeIndex, return_type: TypeIndex, span: Span) FuncBuilder {
        var fb = FuncBuilder{
            .name = name,
            .type_idx = type_idx,
            .return_type = return_type,
            .span = span,
            .allocator = allocator,
            .locals = std.ArrayList(Local){ .items = &.{}, .capacity = 0 },
            .blocks = std.ArrayList(Block){ .items = &.{}, .capacity = 0 },
            .nodes = std.ArrayList(Node){ .items = &.{}, .capacity = 0 },
            .current_block = 0,
            .local_map = std.StringHashMap(u32).init(allocator),
        };

        // Create entry block
        fb.blocks.append(allocator, Block.init(0)) catch {};

        return fb;
    }

    pub fn deinit(self: *FuncBuilder) void {
        self.locals.deinit(self.allocator);
        self.blocks.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        self.local_map.deinit();
    }

    /// Add a parameter.
    pub fn addParam(self: *FuncBuilder, name: []const u8, type_idx: TypeIndex) !u32 {
        const idx: u32 = @intCast(self.locals.items.len);
        const param_idx: u32 = idx; // params are first
        try self.locals.append(self.allocator, Local.initParam(name, type_idx, param_idx));
        try self.local_map.put(name, idx);
        return idx;
    }

    /// Add a local variable.
    pub fn addLocal(self: *FuncBuilder, name: []const u8, type_idx: TypeIndex, mutable: bool) !u32 {
        const idx: u32 = @intCast(self.locals.items.len);
        try self.locals.append(self.allocator, Local.init(name, type_idx, idx, mutable));
        try self.local_map.put(name, idx);
        return idx;
    }

    /// Add a local variable with explicit size.
    pub fn addLocalWithSize(self: *FuncBuilder, name: []const u8, type_idx: TypeIndex, mutable: bool, size: u32) !u32 {
        const idx: u32 = @intCast(self.locals.items.len);
        try self.locals.append(self.allocator, Local.initWithSize(name, type_idx, idx, mutable, size));
        try self.local_map.put(name, idx);
        return idx;
    }

    /// Look up a local by name.
    pub fn lookupLocal(self: *FuncBuilder, name: []const u8) ?u32 {
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

    /// Emit a node to the current block.
    pub fn emit(self: *FuncBuilder, node: Node) !NodeIndex {
        const idx: NodeIndex = @intCast(self.nodes.items.len);
        var n = node;
        n.block = self.current_block;
        try self.nodes.append(self.allocator, n);

        // Add to current block's node list
        var block = &self.blocks.items[self.current_block];
        var block_nodes = std.ArrayList(NodeIndex){ .items = @constCast(block.nodes), .capacity = block.nodes.len };
        try block_nodes.append(self.allocator, idx);
        block.nodes = try self.allocator.dupe(NodeIndex, block_nodes.items);

        return idx;
    }

    /// Emit a constant integer.
    pub fn emitConstInt(self: *FuncBuilder, value: i64, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.const_int, type_idx, span).withAux(value));
    }

    /// Emit a constant float.
    pub fn emitConstFloat(self: *FuncBuilder, value: f64, type_idx: TypeIndex, span: Span) !NodeIndex {
        _ = value; // TODO: store float in aux somehow
        return self.emit(Node.init(.const_float, type_idx, span));
    }

    /// Emit a constant string.
    pub fn emitConstString(self: *FuncBuilder, value: []const u8, span: Span) !NodeIndex {
        return self.emit(Node.init(.const_string, TypeRegistry.STRING, span).withAuxStr(value));
    }

    /// Emit a constant bool.
    pub fn emitConstBool(self: *FuncBuilder, value: bool, span: Span) !NodeIndex {
        return self.emit(Node.init(.const_bool, TypeRegistry.BOOL, span).withAux(if (value) 1 else 0));
    }

    /// Emit local variable load.
    pub fn emitLocalLoad(self: *FuncBuilder, local_idx: u32, type_idx: TypeIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.local, type_idx, span).withAux(@intCast(local_idx)));
    }

    /// Emit local variable store.
    pub fn emitLocalStore(self: *FuncBuilder, local_idx: u32, value: NodeIndex, type_idx: TypeIndex, span: Span) !NodeIndex {
        const args = try self.allocator.dupe(NodeIndex, &.{value});
        return self.emit(Node.init(.store, type_idx, span).withArgs(args).withAux(@intCast(local_idx)));
    }

    /// Emit binary operation.
    pub fn emitBinary(self: *FuncBuilder, op: Op, left: NodeIndex, right: NodeIndex, type_idx: TypeIndex, span: Span) !NodeIndex {
        const args = try self.allocator.dupe(NodeIndex, &.{ left, right });
        return self.emit(Node.init(op, type_idx, span).withArgs(args));
    }

    /// Emit unary operation.
    pub fn emitUnary(self: *FuncBuilder, op: Op, operand: NodeIndex, type_idx: TypeIndex, span: Span) !NodeIndex {
        const args = try self.allocator.dupe(NodeIndex, &.{operand});
        return self.emit(Node.init(op, type_idx, span).withArgs(args));
    }

    /// Emit function call.
    pub fn emitCall(self: *FuncBuilder, callee: NodeIndex, call_args: []const NodeIndex, return_type: TypeIndex, span: Span) !NodeIndex {
        var args = std.ArrayList(NodeIndex){ .items = &.{}, .capacity = 0 };
        try args.append(self.allocator, callee);
        for (call_args) |arg| {
            try args.append(self.allocator, arg);
        }
        return self.emit(Node.init(.call, return_type, span).withArgs(try self.allocator.dupe(NodeIndex, args.items)));
    }

    /// Emit return.
    pub fn emitReturn(self: *FuncBuilder, value: ?NodeIndex, span: Span) !NodeIndex {
        if (value) |v| {
            const args = try self.allocator.dupe(NodeIndex, &.{v});
            return self.emit(Node.init(.ret, TypeRegistry.VOID, span).withArgs(args));
        } else {
            return self.emit(Node.init(.ret, TypeRegistry.VOID, span));
        }
    }

    /// Emit unconditional jump.
    pub fn emitJump(self: *FuncBuilder, target: BlockIndex, span: Span) !NodeIndex {
        return self.emit(Node.init(.jump, TypeRegistry.VOID, span).withAux(@intCast(target)));
    }

    /// Emit conditional branch.
    pub fn emitBranch(self: *FuncBuilder, cond: NodeIndex, true_block: BlockIndex, false_block: BlockIndex, span: Span) !NodeIndex {
        const args = try self.allocator.dupe(NodeIndex, &.{cond});
        // Store both target blocks: aux = true_block, aux2 encoded in high bits
        const aux: i64 = @intCast(true_block);
        return self.emit(Node.init(.branch, TypeRegistry.VOID, span).withArgs(args).withAux(aux).withAuxStr(std.mem.asBytes(&false_block)));
    }

    /// Emit field access.
    pub fn emitField(self: *FuncBuilder, base: NodeIndex, field_idx: u32, type_idx: TypeIndex, span: Span) !NodeIndex {
        const args = try self.allocator.dupe(NodeIndex, &.{base});
        return self.emit(Node.init(.field, type_idx, span).withArgs(args).withAux(@intCast(field_idx)));
    }

    /// Emit array/slice index.
    pub fn emitIndex(self: *FuncBuilder, base: NodeIndex, index: NodeIndex, type_idx: TypeIndex, span: Span) !NodeIndex {
        const args = try self.allocator.dupe(NodeIndex, &.{ base, index });
        return self.emit(Node.init(.index, type_idx, span).withArgs(args));
    }

    /// Build the final function.
    /// Computes stack frame layout: assigns offsets to locals and calculates total frame size.
    pub fn build(self: *FuncBuilder) !Func {
        // Collect params from locals
        var params = std.ArrayList(Local){ .items = &.{}, .capacity = 0 };
        for (self.locals.items) |local| {
            if (local.is_param) {
                try params.append(self.allocator, local);
            }
        }

        // Compute stack frame layout (like Go's AllocFrame)
        // Assign sequential offsets to each local based on their sizes
        var frame_offset: i32 = 0;
        for (self.locals.items, 0..) |*local, i| {
            _ = i;
            // Round up to 8-byte alignment (standard for 64-bit values)
            frame_offset = roundUp(frame_offset, 8);
            // Assign offset (negative for x86/rbp-relative)
            local.offset = -frame_offset - @as(i32, @intCast(local.size));
            // Advance by variable size
            frame_offset += @as(i32, @intCast(local.size));
        }

        // Round total frame size to 16-byte alignment (ABI requirement)
        const frame_size: u32 = @intCast(roundUp(frame_offset, 16));

        return Func{
            .name = self.name,
            .type_idx = self.type_idx,
            .return_type = self.return_type,
            .params = try self.allocator.dupe(Local, params.items),
            .locals = try self.allocator.dupe(Local, self.locals.items),
            .blocks = try self.allocator.dupe(Block, self.blocks.items),
            .entry = 0,
            .nodes = try self.allocator.dupe(Node, self.nodes.items),
            .span = self.span,
            .frame_size = frame_size,
        };
    }

    /// Round up to alignment (must be power of 2)
    fn roundUp(offset: i32, alignment: i32) i32 {
        return (offset + alignment - 1) & ~(alignment - 1);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ir node creation" {
    const span = Span.init(Pos{ .offset = 0 }, Pos{ .offset = 1 });
    const node = Node.init(.const_int, TypeRegistry.INT, span).withAux(42);

    try std.testing.expectEqual(Op.const_int, node.op);
    try std.testing.expectEqual(TypeRegistry.INT, node.type_idx);
    try std.testing.expectEqual(@as(i64, 42), node.aux);
}

test "ir block creation" {
    const block = Block.init(0);
    try std.testing.expectEqual(@as(BlockIndex, 0), block.index);
    try std.testing.expectEqual(@as(usize, 0), block.nodes.len);
}

test "ir func builder" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const type_reg = try TypeRegistry.init(alloc);
    const span = Span.init(Pos{ .offset = 0 }, Pos{ .offset = 10 });

    var fb = FuncBuilder.init(alloc, "test", TypeRegistry.VOID, TypeRegistry.INT, span);

    // Add parameters
    const param_a = try fb.addParam("a", TypeRegistry.INT);
    const param_b = try fb.addParam("b", TypeRegistry.INT);

    try std.testing.expectEqual(@as(u32, 0), param_a);
    try std.testing.expectEqual(@as(u32, 1), param_b);

    // Emit some nodes
    const load_a = try fb.emitLocalLoad(param_a, TypeRegistry.INT, span);
    const load_b = try fb.emitLocalLoad(param_b, TypeRegistry.INT, span);
    const add = try fb.emitBinary(.add, load_a, load_b, TypeRegistry.INT, span);
    _ = try fb.emitReturn(add, span);

    const func = try fb.build();

    try std.testing.expectEqualStrings("test", func.name);
    try std.testing.expectEqual(@as(usize, 2), func.params.len);
    try std.testing.expectEqual(@as(usize, 4), func.nodes.len);
    try std.testing.expectEqual(@as(usize, 1), func.blocks.len);

    _ = type_reg;
}

test "ir builder" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var type_reg = try TypeRegistry.init(alloc);
    var builder = Builder.init(alloc, &type_reg);

    const span = Span.init(Pos{ .offset = 0 }, Pos{ .offset = 10 });

    // Add a global
    try builder.addGlobal(Global.init("PI", TypeRegistry.FLOAT, true, span));

    // Build a function
    builder.startFunc("add", TypeRegistry.VOID, TypeRegistry.INT, span);
    if (builder.current_func) |*fb| {
        _ = try fb.addParam("x", TypeRegistry.INT);
        _ = try fb.addParam("y", TypeRegistry.INT);
    }
    try builder.endFunc();

    const ir = builder.getIR();

    try std.testing.expectEqual(@as(usize, 1), ir.funcs.len);
    try std.testing.expectEqual(@as(usize, 1), ir.globals.len);
    try std.testing.expectEqualStrings("add", ir.funcs[0].name);
    try std.testing.expectEqualStrings("PI", ir.globals[0].name);
}

test "ir op properties" {
    try std.testing.expect(Op.ret.isTerminator());
    try std.testing.expect(Op.jump.isTerminator());
    try std.testing.expect(Op.branch.isTerminator());
    try std.testing.expect(!Op.add.isTerminator());

    try std.testing.expect(Op.call.hasSideEffects());
    try std.testing.expect(Op.store.hasSideEffects());
    try std.testing.expect(!Op.add.hasSideEffects());
}

test "ir control flow" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const type_reg = try TypeRegistry.init(alloc);
    const span = Span.init(Pos{ .offset = 0 }, Pos{ .offset = 10 });

    var fb = FuncBuilder.init(alloc, "test_if", TypeRegistry.VOID, TypeRegistry.INT, span);

    // Create blocks for if-then-else
    const then_block = try fb.newBlock("then");
    const else_block = try fb.newBlock("else");
    const merge_block = try fb.newBlock("merge");

    // Entry block: branch on condition
    const cond = try fb.emitConstBool(true, span);
    _ = try fb.emitBranch(cond, then_block, else_block, span);

    // Then block
    fb.setBlock(then_block);
    const then_val = try fb.emitConstInt(1, TypeRegistry.INT, span);
    _ = try fb.emitJump(merge_block, span);

    // Else block
    fb.setBlock(else_block);
    const else_val = try fb.emitConstInt(2, TypeRegistry.INT, span);
    _ = try fb.emitJump(merge_block, span);

    // Merge block
    fb.setBlock(merge_block);
    _ = try fb.emitReturn(then_val, span); // simplified: just return then_val

    _ = else_val;

    const func = try fb.build();

    try std.testing.expectEqual(@as(usize, 4), func.blocks.len); // entry + then + else + merge
    try std.testing.expectEqualStrings("then", func.blocks[1].label);
    try std.testing.expectEqualStrings("else", func.blocks[2].label);
    try std.testing.expectEqualStrings("merge", func.blocks[3].label);

    _ = type_reg;
}

// ============================================================================
// Frame Layout Tests - Catch stack corruption bugs at compile time
// ============================================================================

test "frame layout: single local has correct offset" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const span = Span.init(Pos{ .offset = 0 }, Pos{ .offset = 10 });
    var fb = FuncBuilder.init(alloc, "test", TypeRegistry.VOID, TypeRegistry.INT, span);

    // Add a single 8-byte local
    _ = try fb.addLocalWithSize("x", TypeRegistry.INT, true, 8);

    const func = try fb.build();

    // Single 8-byte local should be at offset -8
    try std.testing.expectEqual(@as(i32, -8), func.locals[0].offset);
    // Frame size should be 16 (aligned)
    try std.testing.expectEqual(@as(u32, 16), func.frame_size);
}

test "frame layout: two locals don't overlap" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const span = Span.init(Pos{ .offset = 0 }, Pos{ .offset = 10 });
    var fb = FuncBuilder.init(alloc, "test", TypeRegistry.VOID, TypeRegistry.INT, span);

    // Add two 8-byte locals
    _ = try fb.addLocalWithSize("a", TypeRegistry.INT, true, 8);
    _ = try fb.addLocalWithSize("b", TypeRegistry.INT, true, 8);

    const func = try fb.build();

    // Check offsets are different and don't overlap
    const a_start = func.locals[0].offset;
    const a_end = a_start + @as(i32, @intCast(func.locals[0].size));
    const b_start = func.locals[1].offset;
    const b_end = b_start + @as(i32, @intCast(func.locals[1].size));

    // Ranges should not overlap
    try std.testing.expect(a_end <= b_start or b_end <= a_start);

    // Frame size should accommodate both (16 bytes, aligned to 16)
    try std.testing.expectEqual(@as(u32, 16), func.frame_size);
}

test "frame layout: array and scalar don't overlap" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const span = Span.init(Pos{ .offset = 0 }, Pos{ .offset = 10 });
    var fb = FuncBuilder.init(alloc, "test", TypeRegistry.VOID, TypeRegistry.INT, span);

    // Add a 40-byte array (5 elements * 8 bytes) and an 8-byte scalar
    _ = try fb.addLocalWithSize("arr", TypeRegistry.INT, true, 40); // 5-element array
    _ = try fb.addLocalWithSize("i", TypeRegistry.INT, true, 8);    // scalar index

    const func = try fb.build();

    // Verify sizes are correct
    try std.testing.expectEqual(@as(u32, 40), func.locals[0].size);
    try std.testing.expectEqual(@as(u32, 8), func.locals[1].size);

    // Calculate ranges (negative offsets, so we work with absolutes)
    const arr_offset = func.locals[0].offset; // e.g., -40
    const arr_end = arr_offset + @as(i32, @intCast(func.locals[0].size)); // e.g., 0
    const i_offset = func.locals[1].offset;   // e.g., -48
    const i_end = i_offset + @as(i32, @intCast(func.locals[1].size));     // e.g., -40

    // Ranges should not overlap: one should end before the other starts
    const no_overlap = (arr_end <= i_offset) or (i_end <= arr_offset);
    try std.testing.expect(no_overlap);

    // Frame size should be at least 48 bytes (40 + 8), aligned to 16 = 48
    try std.testing.expect(func.frame_size >= 48);
    try std.testing.expectEqual(@as(u32, 0), func.frame_size % 16); // 16-byte aligned
}

test "frame layout: all locals fit within frame_size" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const span = Span.init(Pos{ .offset = 0 }, Pos{ .offset = 10 });
    var fb = FuncBuilder.init(alloc, "test", TypeRegistry.VOID, TypeRegistry.INT, span);

    // Add several locals of different sizes
    _ = try fb.addLocalWithSize("a", TypeRegistry.INT, true, 8);
    _ = try fb.addLocalWithSize("b", TypeRegistry.INT, true, 16);
    _ = try fb.addLocalWithSize("c", TypeRegistry.INT, true, 24);
    _ = try fb.addLocalWithSize("d", TypeRegistry.INT, true, 8);

    const func = try fb.build();

    // Total size = 8 + 16 + 24 + 8 = 56, aligned to 64
    try std.testing.expect(func.frame_size >= 56);

    // Every local's range must fit within [-(frame_size), 0]
    for (func.locals) |local| {
        const local_end = local.offset + @as(i32, @intCast(local.size));
        // Offset should be negative (below frame pointer)
        try std.testing.expect(local.offset < 0);
        // End should be <= 0
        try std.testing.expect(local_end <= 0);
        // Start should be >= -frame_size
        try std.testing.expect(local.offset >= -@as(i32, @intCast(func.frame_size)));
    }
}

test "frame layout: frame_size is 16-byte aligned" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const span = Span.init(Pos{ .offset = 0 }, Pos{ .offset = 10 });

    // Test with various sizes that don't naturally align to 16
    const test_sizes = [_]u32{ 1, 7, 9, 15, 17, 23, 31, 33 };

    for (test_sizes) |size| {
        var fb = FuncBuilder.init(alloc, "test", TypeRegistry.VOID, TypeRegistry.INT, span);
        _ = try fb.addLocalWithSize("x", TypeRegistry.INT, true, size);
        const func = try fb.build();

        // Frame size must be 16-byte aligned (ABI requirement)
        try std.testing.expectEqual(@as(u32, 0), func.frame_size % 16);
        // Frame size must be at least as large as the local
        try std.testing.expect(func.frame_size >= size);
    }
}

test "frame layout: large array (regression test for stack corruption)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const span = Span.init(Pos{ .offset = 0 }, Pos{ .offset = 10 });
    var fb = FuncBuilder.init(alloc, "test", TypeRegistry.VOID, TypeRegistry.INT, span);

    // Simulate: var arr = [10, 20, 30, 40, 50]; var i = 4;
    // This was causing stack corruption on x86_64
    _ = try fb.addLocalWithSize("arr", TypeRegistry.INT, true, 40); // 5 * 8 = 40 bytes
    _ = try fb.addLocalWithSize("i", TypeRegistry.INT, true, 8);

    const func = try fb.build();

    // Frame must be large enough for both
    try std.testing.expect(func.frame_size >= 48);

    // Verify arr[4] location doesn't overlap with i
    // arr[4] is at arr.offset + 32
    const arr_elem4_offset = func.locals[0].offset + 32;
    const i_offset = func.locals[1].offset;
    const i_end = i_offset + 8;

    // arr[4] should not overlap with i
    try std.testing.expect(arr_elem4_offset >= i_end or arr_elem4_offset + 8 <= i_offset);
}
