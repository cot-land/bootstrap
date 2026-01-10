///! SSA (Static Single Assignment) form for cot.
///!
///! Maps to Go's cmd/compile/internal/ssa/
///! - func.go (Func structure, value/block factories)
///! - block.go (Block, Edge with bidirectional indices)
///! - value.go (Value with use counting)
///! - dom.go (Lengauer-Tarjan dominance)
///! - copyelim.go (phi elimination)
///! - rewrite.go (unified pass framework)
///!
///! Key patterns from Go:
///! - Dense ID allocation for cache-friendly arrays
///! - Inline storage for common cases (3 args, 4 preds)
///! - Explicit use counting for O(1) DCE
///! - Cache invalidation when CFG changes
///! - SparseTree for O(1) dominance queries

const std = @import("std");
const types = @import("types.zig");
const ir = @import("ir.zig");
const debug = @import("debug.zig");

const TypeIndex = types.TypeIndex;
const Allocator = std.mem.Allocator;

// Scoped logger for SSA debugging
const log = debug.scoped(.ssa);

// ============================================================================
// IDs (dense allocation like Go)
// ============================================================================

pub const ValueID = u32;
pub const BlockID = u32;
pub const null_value: ValueID = std.math.maxInt(ValueID);
pub const null_block: BlockID = std.math.maxInt(BlockID);

/// Simple dense ID allocator (Go's idAlloc pattern).
/// IDs start at 0 and are used as array indices.
const IdAlloc = struct {
    next: u32 = 0,

    fn get(self: *IdAlloc) u32 {
        const id = self.next;
        self.next += 1;
        return id;
    }

    fn num(self: IdAlloc) u32 {
        return self.next;
    }
};

// ============================================================================
// Operations
// ============================================================================

/// SSA operations (more specific than IR ops).
pub const Op = enum(u8) {
    // Constants
    const_int,
    const_float,
    const_string,
    const_bool,
    const_nil,

    // Phi node (SSA join point)
    phi,

    // Copy (for register allocation)
    copy,

    // Arithmetic
    add,
    sub,
    mul,
    div,
    mod,
    neg,

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
    not,

    // Memory
    load,
    store,
    addr,
    alloc,

    // Struct/array
    field,
    index,

    // Slice construction
    // args[0] = base local index, args[1] = start value, args[2] = end value
    // aux_int = element size
    slice_make,

    // Slice indexing
    // args[0] = slice local index (raw), args[1] = index value (SSA ref)
    // aux_int = element size
    slice_index,

    // Function
    call,
    arg,

    // ARC
    retain,
    release,

    // Control (block terminators)
    ret,
    jump,
    branch,
    @"unreachable",
};

// ============================================================================
// Value (Go's value.go pattern)
// ============================================================================

/// An SSA value - each assigned exactly once.
/// Uses explicit use counting for DCE (Go pattern).
pub const Value = struct {
    id: ValueID,
    op: Op,
    type_idx: TypeIndex,
    block: BlockID,

    /// Inline storage for first 3 args (Go pattern - avoids allocation).
    args_storage: [3]ValueID = .{ null_value, null_value, null_value },
    /// Number of args actually used.
    args_len: u8 = 0,
    /// Overflow args (heap allocated if > 3).
    args_extra: []ValueID = &.{},

    /// Use count for dead code elimination.
    uses: u32 = 0,

    /// Auxiliary integer data (constants, field indices).
    aux_int: i64 = 0,
    /// Auxiliary string data (symbols, names).
    aux_str: []const u8 = "",

    /// Source position for debugging.
    pos: u32 = 0,

    /// Get all arguments.
    pub fn args(self: *const Value) []const ValueID {
        if (self.args_len <= 3) {
            return self.args_storage[0..self.args_len];
        }
        return self.args_extra;
    }

    /// Set arguments (uses inline storage when possible).
    pub fn setArgs(self: *Value, new_args: []const ValueID, allocator: Allocator) !void {
        self.args_len = @intCast(new_args.len);
        if (new_args.len <= 3) {
            for (new_args, 0..) |arg, i| {
                self.args_storage[i] = arg;
            }
        } else {
            self.args_extra = try allocator.dupe(ValueID, new_args);
        }
    }

    /// Add a single argument.
    pub fn addArg(self: *Value, arg: ValueID, allocator: Allocator) !void {
        const len = self.args_len;
        if (len < 3) {
            self.args_storage[len] = arg;
            self.args_len = len + 1;
        } else {
            // Need to grow extra storage
            var new_args = try allocator.alloc(ValueID, len + 1);
            if (len == 3) {
                @memcpy(new_args[0..3], &self.args_storage);
            } else {
                @memcpy(new_args[0..len], self.args_extra);
            }
            new_args[len] = arg;
            self.args_extra = new_args;
            self.args_len = len + 1;
        }
    }
};

// ============================================================================
// Edge (Go's bidirectional edge pattern)
// ============================================================================

/// CFG edge with bidirectional indexing.
/// Enables O(1) predecessor/successor removal.
pub const Edge = struct {
    /// Target block.
    block: BlockID,
    /// Index in the reverse edge list of target.
    /// For succs[i], this is the index in target.preds.
    /// For preds[i], this is the index in source.succs.
    reverse_idx: u32,
};

// ============================================================================
// Block (Go's block.go pattern)
// ============================================================================

/// Block kinds (terminators).
pub const BlockKind = enum(u8) {
    /// Single successor (unconditional jump).
    plain,
    /// Two successors based on condition.
    @"if",
    /// Return from function.
    ret,
    /// Unreachable.
    exit,
};

/// A basic block in SSA form.
pub const Block = struct {
    id: BlockID,
    kind: BlockKind = .plain,

    /// Inline storage for successors (most blocks have 1-2).
    succs_storage: [2]Edge = .{ .{ .block = null_block, .reverse_idx = 0 }, .{ .block = null_block, .reverse_idx = 0 } },
    succs_len: u8 = 0,
    succs_extra: []Edge = &.{},

    /// Inline storage for predecessors (most blocks have 1-4).
    preds_storage: [4]Edge = .{
        .{ .block = null_block, .reverse_idx = 0 },
        .{ .block = null_block, .reverse_idx = 0 },
        .{ .block = null_block, .reverse_idx = 0 },
        .{ .block = null_block, .reverse_idx = 0 },
    },
    preds_len: u8 = 0,
    preds_extra: []Edge = &.{},

    /// Values in this block.
    values: std.ArrayList(ValueID),

    /// Control value (branch condition for if blocks).
    control: ValueID = null_value,

    /// Aux data (loop depth, etc.).
    aux: i64 = 0,

    allocator: Allocator = undefined,

    pub fn init(id: BlockID, allocator: Allocator) Block {
        return .{
            .id = id,
            .allocator = allocator,
            .values = .{ .items = &.{}, .capacity = 0 },
        };
    }

    pub fn deinit(self: *Block) void {
        self.values.deinit(self.allocator);
    }

    /// Get successors.
    pub fn succs(self: *const Block) []const Edge {
        if (self.succs_len <= 2) {
            return self.succs_storage[0..self.succs_len];
        }
        return self.succs_extra;
    }

    /// Get predecessors.
    pub fn preds(self: *const Block) []const Edge {
        if (self.preds_len <= 4) {
            return self.preds_storage[0..self.preds_len];
        }
        return self.preds_extra;
    }

    /// Number of predecessors.
    pub fn numPreds(self: *const Block) u32 {
        return self.preds_len;
    }

    /// Number of successors.
    pub fn numSuccs(self: *const Block) u32 {
        return self.succs_len;
    }
};

// ============================================================================
// Func (Go's func.go pattern)
// ============================================================================

/// Local variable info for codegen (copied from IR).
pub const LocalInfo = struct {
    name: []const u8,
    size: u32,
    offset: i32,
};

/// An SSA function.
pub const Func = struct {
    name: []const u8,
    type_idx: TypeIndex,
    return_type: TypeIndex,
    allocator: Allocator,

    /// All blocks (indexed by BlockID).
    blocks: std.ArrayList(Block),
    /// All values (indexed by ValueID).
    values: std.ArrayList(Value),

    /// Entry block.
    entry: BlockID = 0,

    /// Number of parameters (for code generation).
    param_count: u32 = 0,

    /// Total stack frame size (propagated from IR Func).
    frame_size: u32 = 0,

    /// Local variable info (propagated from IR for codegen offset calculations).
    locals: []const LocalInfo = &.{},

    /// ID allocators.
    vid: IdAlloc = .{},
    bid: IdAlloc = .{},

    // Cached analyses (invalidated on CFG change)
    cached_postorder: ?[]BlockID = null,
    cached_idom: ?[]BlockID = null,
    cached_sdom: ?SparseTree = null,

    pub fn init(allocator: Allocator, name: []const u8, type_idx: TypeIndex, return_type: TypeIndex) Func {
        var f = Func{
            .name = name,
            .type_idx = type_idx,
            .return_type = return_type,
            .allocator = allocator,
            .blocks = .{ .items = &.{}, .capacity = 0 },
            .values = .{ .items = &.{}, .capacity = 0 },
        };

        // Create entry block
        f.entry = f.newBlock();
        return f;
    }

    pub fn deinit(self: *Func) void {
        for (self.blocks.items) |*b| {
            b.deinit();
        }
        self.blocks.deinit(self.allocator);
        self.values.deinit(self.allocator);
        if (self.cached_postorder) |po| {
            self.allocator.free(po);
        }
        if (self.cached_idom) |cached| {
            self.allocator.free(cached);
        }
    }

    /// Create a new block.
    pub fn newBlock(self: *Func) BlockID {
        const id = self.bid.get();
        self.blocks.append(self.allocator, Block.init(id, self.allocator)) catch unreachable;
        self.invalidateCFG();
        log.debug("newBlock: b{d} in {s}", .{ id, self.name });
        return id;
    }

    /// Create a new value.
    pub fn newValue(self: *Func, op: Op, type_idx: TypeIndex, block: BlockID) !ValueID {
        const id = self.vid.get();
        try self.values.append(self.allocator, .{
            .id = id,
            .op = op,
            .type_idx = type_idx,
            .block = block,
        });
        // Add to block's value list
        try self.blocks.items[block].values.append(self.allocator, id);
        log.debug("newValue: v{d} = {s} in b{d}", .{ id, @tagName(op), block });
        return id;
    }

    /// Get a value by ID.
    pub fn getValue(self: *Func, id: ValueID) *Value {
        return &self.values.items[id];
    }

    /// Get a block by ID.
    pub fn getBlock(self: *Func, id: BlockID) *Block {
        return &self.blocks.items[id];
    }

    /// Add edge from src to dst.
    pub fn addEdge(self: *Func, src: BlockID, dst: BlockID) void {
        var src_block = self.getBlock(src);
        var dst_block = self.getBlock(dst);

        const src_idx = src_block.succs_len;
        const dst_idx = dst_block.preds_len;

        // Add successor to src
        if (src_idx < 2) {
            src_block.succs_storage[src_idx] = .{ .block = dst, .reverse_idx = dst_idx };
        } else {
            // Would need to allocate - simplified for now
            log.warn("addEdge: b{d} has >2 successors, edge to b{d} dropped", .{ src, dst });
        }
        src_block.succs_len += 1;

        // Add predecessor to dst
        if (dst_idx < 4) {
            dst_block.preds_storage[dst_idx] = .{ .block = src, .reverse_idx = src_idx };
        } else {
            // Would need to allocate - simplified for now
            log.warn("addEdge: b{d} has >4 predecessors, edge from b{d} dropped", .{ dst, src });
        }
        dst_block.preds_len += 1;

        log.debug("addEdge: b{d} -> b{d}", .{ src, dst });
        self.invalidateCFG();
    }

    /// Invalidate cached CFG analyses (Go pattern).
    pub fn invalidateCFG(self: *Func) void {
        if (self.cached_postorder) |po| {
            self.allocator.free(po);
            self.cached_postorder = null;
        }
        if (self.cached_idom) |cached| {
            self.allocator.free(cached);
            self.cached_idom = null;
        }
        self.cached_sdom = null;
    }

    /// Get immediate dominators (compute if not cached).
    pub fn idom(self: *Func) []BlockID {
        if (self.cached_idom) |idom_cache| {
            return idom_cache;
        }
        self.cached_idom = self.computeDominators();
        return self.cached_idom.?;
    }

    /// Compute dominators using simplified algorithm.
    fn computeDominators(self: *Func) []BlockID {
        const n = self.blocks.items.len;
        var idom_arr = self.allocator.alloc(BlockID, n) catch unreachable;
        @memset(idom_arr, null_block);

        // Entry block dominates itself
        idom_arr[self.entry] = self.entry;

        // Simple iterative algorithm (not Lengauer-Tarjan for now)
        var changed = true;
        while (changed) {
            changed = false;
            for (self.blocks.items, 0..) |*b, idx| {
                if (idx == self.entry) continue;

                const preds_list = b.preds();
                if (preds_list.len == 0) continue;

                // Find first processed predecessor
                var new_idom: ?BlockID = null;
                for (preds_list) |pred| {
                    if (idom_arr[pred.block] != null_block) {
                        new_idom = pred.block;
                        break;
                    }
                }

                if (new_idom == null) continue;

                // Intersect with other predecessors
                for (preds_list) |pred| {
                    if (pred.block == new_idom.?) continue;
                    if (idom_arr[pred.block] != null_block) {
                        new_idom = self.intersect(idom_arr, pred.block, new_idom.?);
                    }
                }

                if (idom_arr[idx] != new_idom.?) {
                    idom_arr[idx] = new_idom.?;
                    changed = true;
                }
            }
        }

        return idom_arr;
    }

    fn intersect(_: *Func, idom_arr: []BlockID, b1: BlockID, b2: BlockID) BlockID {
        var finger1 = b1;
        var finger2 = b2;
        while (finger1 != finger2) {
            while (finger1 > finger2) {
                finger1 = idom_arr[finger1];
            }
            while (finger2 > finger1) {
                finger2 = idom_arr[finger2];
            }
        }
        return finger1;
    }

    /// Increment use count for a value.
    pub fn addUse(self: *Func, id: ValueID) void {
        self.values.items[id].uses += 1;
    }

    /// Decrement use count for a value.
    pub fn removeUse(self: *Func, id: ValueID) void {
        self.values.items[id].uses -= 1;
    }

    /// Number of values.
    pub fn numValues(self: *Func) u32 {
        return self.vid.num();
    }

    /// Number of blocks.
    pub fn numBlocks(self: *Func) u32 {
        return self.bid.num();
    }
};

// ============================================================================
// SparseTree (Go's sparsetree.go - O(1) dominance queries)
// ============================================================================

/// SparseTree enables O(1) ancestor/dominance checks.
/// Uses DFS numbering: a dominates b iff a.entry <= b.entry && b.exit <= a.exit.
pub const SparseTree = struct {
    nodes: []SparseTreeNode,

    pub const SparseTreeNode = struct {
        parent: BlockID,
        entry: u32,
        exit: u32,
    };

    /// Check if a dominates b (or a == b).
    pub fn isAncestorEq(self: SparseTree, a: BlockID, b: BlockID) bool {
        return self.nodes[a].entry <= self.nodes[b].entry and
            self.nodes[b].exit <= self.nodes[a].exit;
    }
};

// ============================================================================
// Passes
// ============================================================================

/// Dead code elimination.
/// Removes values with zero uses (Go's deadcode pattern).
pub fn deadcode(f: *Func) void {
    var changed = true;
    while (changed) {
        changed = false;
        for (f.values.items, 0..) |*v, idx| {
            if (v.uses == 0 and isRemovable(v.op)) {
                // Decrement uses of our args
                for (v.args()) |arg| {
                    f.removeUse(arg);
                }
                // Mark as dead (set op to unreachable)
                v.op = .@"unreachable";
                changed = true;
                _ = idx;
            }
        }
    }
}

fn isRemovable(op: Op) bool {
    return switch (op) {
        .ret, .jump, .branch, .store, .call => false,
        else => true,
    };
}

/// Phi elimination.
/// Converts trivial phis (all same arg) to copies (Go's phielim pattern).
pub fn phielim(f: *Func) void {
    var changed = true;
    while (changed) {
        changed = false;
        for (f.values.items) |*v| {
            if (v.op == .phi) {
                if (phielimValue(v)) {
                    changed = true;
                }
            }
        }
    }
}

fn phielimValue(v: *Value) bool {
    if (v.op != .phi) return false;

    const args_list = v.args();
    var same: ?ValueID = null;

    for (args_list) |arg| {
        if (arg == v.id) continue; // Ignore self-loops
        if (same) |s| {
            if (arg == s) continue; // Same value
            return false; // Different values - not trivial
        }
        same = arg;
    }

    if (same) |s| {
        // Convert phi to copy
        v.op = .copy;
        v.args_len = 1;
        v.args_storage[0] = s;
        return true;
    }

    return false;
}

/// Copy elimination.
/// Propagates copies to eliminate chains.
pub fn copyelim(f: *Func) void {
    for (f.values.items) |*v| {
        // For each arg, follow copy chains
        const args_list = v.args();
        for (args_list, 0..) |arg, i| {
            const resolved = followCopies(f, arg);
            if (resolved != arg) {
                if (v.args_len <= 3) {
                    v.args_storage[i] = resolved;
                } else {
                    v.args_extra[i] = resolved;
                }
            }
        }
    }
}

fn followCopies(f: *Func, id: ValueID) ValueID {
    var current = id;
    while (true) {
        const v = f.getValue(current);
        if (v.op != .copy) break;
        const args_list = v.args();
        if (args_list.len != 1) break;
        current = args_list[0];
    }
    return current;
}

// ============================================================================
// Tests
// ============================================================================

test "ssa func creation" {
    const allocator = std.testing.allocator;
    var f = Func.init(allocator, "test", 0, types.TypeRegistry.VOID);
    defer f.deinit();

    try std.testing.expectEqual(@as(BlockID, 0), f.entry);
    try std.testing.expectEqual(@as(u32, 1), f.numBlocks());
}

test "ssa value creation" {
    const allocator = std.testing.allocator;
    var f = Func.init(allocator, "test", 0, types.TypeRegistry.VOID);
    defer f.deinit();

    const v1 = try f.newValue(.const_int, types.TypeRegistry.INT, f.entry);
    const v2 = try f.newValue(.const_int, types.TypeRegistry.INT, f.entry);

    try std.testing.expectEqual(@as(ValueID, 0), v1);
    try std.testing.expectEqual(@as(ValueID, 1), v2);
    try std.testing.expectEqual(@as(u32, 2), f.numValues());
}

test "ssa inline arg storage" {
    const allocator = std.testing.allocator;
    var f = Func.init(allocator, "test", 0, types.TypeRegistry.VOID);
    defer f.deinit();

    const v1 = try f.newValue(.const_int, types.TypeRegistry.INT, f.entry);
    const v2 = try f.newValue(.const_int, types.TypeRegistry.INT, f.entry);
    const v3 = try f.newValue(.add, types.TypeRegistry.INT, f.entry);

    var v = f.getValue(v3);
    try v.setArgs(&.{ v1, v2 }, allocator);

    const args_list = v.args();
    try std.testing.expectEqual(@as(usize, 2), args_list.len);
    try std.testing.expectEqual(v1, args_list[0]);
    try std.testing.expectEqual(v2, args_list[1]);
}

test "ssa edge addition" {
    const allocator = std.testing.allocator;
    var f = Func.init(allocator, "test", 0, types.TypeRegistry.VOID);
    defer f.deinit();

    const b1 = f.entry;
    const b2 = f.newBlock();

    f.addEdge(b1, b2);

    const block1 = f.getBlock(b1);
    const block2 = f.getBlock(b2);

    try std.testing.expectEqual(@as(u32, 1), block1.numSuccs());
    try std.testing.expectEqual(@as(u32, 1), block2.numPreds());
}

test "ssa phi elimination" {
    const allocator = std.testing.allocator;
    var f = Func.init(allocator, "test", 0, types.TypeRegistry.VOID);
    defer f.deinit();

    const v1 = try f.newValue(.const_int, types.TypeRegistry.INT, f.entry);
    const phi = try f.newValue(.phi, types.TypeRegistry.INT, f.entry);

    // Trivial phi: phi(v1, v1) -> copy(v1)
    var phi_val = f.getValue(phi);
    try phi_val.setArgs(&.{ v1, v1 }, allocator);

    phielim(&f);

    try std.testing.expectEqual(Op.copy, f.getValue(phi).op);
}

test "ssa dominators" {
    const allocator = std.testing.allocator;
    var f = Func.init(allocator, "test", 0, types.TypeRegistry.VOID);
    defer f.deinit();

    const b1 = f.entry;
    const b2 = f.newBlock();
    const b3 = f.newBlock();

    f.addEdge(b1, b2);
    f.addEdge(b1, b3);

    const idom_arr = f.idom();

    // Entry dominates itself
    try std.testing.expectEqual(b1, idom_arr[b1]);
    // Entry dominates b2 and b3
    try std.testing.expectEqual(b1, idom_arr[b2]);
    try std.testing.expectEqual(b1, idom_arr[b3]);
}
