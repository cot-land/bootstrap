//! Liveness Analysis for SSA
//!
//! Computes per-value liveness information in a single backward pass.
//! Used by codegen to:
//! 1. Free registers when operands die (auto-free dead operands)
//! 2. Choose spill candidates (farthest-next-use heuristic)
//! 3. Avoid unnecessary caller-save spills (only spill live values)
//!
//! Algorithm: Single backward pass over all values
//! - Assign instruction indices in forward order
//! - Walk backward, tracking first (last in execution) use of each value
//! - Mark operand as "dying" if this is its last use
//!
//! Complexity: O(V) time, O(V) space where V = number of values
//!
//! Future: Add block-level liveness for better handling of control flow.
//! The current instruction-level approach works well for straight-line code
//! and simple branches but may be suboptimal for complex control flow.

const std = @import("std");
const ssa = @import("ssa.zig");
const Allocator = std.mem.Allocator;

/// Liveness information for a function.
/// All arrays are indexed by ValueID.
pub const LivenessInfo = struct {
    /// Instruction index of last use for each value.
    /// 0 means the value is never used (dead).
    last_use: []u32,

    /// Bitmask of operands that die at each value.
    /// Bit i = 1 means args()[i] dies at this instruction.
    /// Supports up to 8 operands per instruction.
    deaths: []u8,

    /// Instruction index for each value (when it's defined).
    /// Used to compute distance-to-next-use.
    inst_index: []u32,

    allocator: Allocator,

    pub fn deinit(self: *LivenessInfo) void {
        self.allocator.free(self.last_use);
        self.allocator.free(self.deaths);
        self.allocator.free(self.inst_index);
    }

    /// Check if operand i dies at this value.
    /// O(1) lookup.
    pub inline fn operandDies(self: *const LivenessInfo, value_id: ssa.ValueID, operand_idx: u8) bool {
        if (value_id >= self.deaths.len) return false;
        return (self.deaths[value_id] >> @intCast(operand_idx)) & 1 != 0;
    }

    /// Get distance from current instruction to next use of a value.
    /// Used for spill candidate selection (farthest-next-use heuristic).
    /// Returns 0 if value is dead or already past its last use.
    pub inline fn distanceToNextUse(self: *const LivenessInfo, value_id: ssa.ValueID, current_inst: u32) u32 {
        if (value_id >= self.last_use.len) return 0;
        const last = self.last_use[value_id];
        if (last == 0 or last <= current_inst) return 0;
        return last - current_inst;
    }

    /// Check if a value is live at a given instruction index.
    /// A value is live if: defined before current AND last_use >= current.
    pub inline fn isLiveAt(self: *const LivenessInfo, value_id: ssa.ValueID, current_inst: u32) bool {
        if (value_id >= self.last_use.len) return false;
        const defined_at = self.inst_index[value_id];
        const last = self.last_use[value_id];
        return defined_at <= current_inst and last >= current_inst;
    }

    /// Check if a value is used after a given instruction.
    /// Useful for determining if a value needs to survive a function call.
    pub inline fn isUsedAfter(self: *const LivenessInfo, value_id: ssa.ValueID, inst: u32) bool {
        if (value_id >= self.last_use.len) return false;
        return self.last_use[value_id] > inst;
    }
};

/// Compute liveness information for a function.
/// Single backward pass - O(V) time where V = number of values.
pub fn computeLiveness(allocator: Allocator, func: *const ssa.Func) !LivenessInfo {
    const num_values = func.numValues();

    var info = LivenessInfo{
        .last_use = try allocator.alloc(u32, num_values),
        .deaths = try allocator.alloc(u8, num_values),
        .inst_index = try allocator.alloc(u32, num_values),
        .allocator = allocator,
    };
    errdefer {
        allocator.free(info.last_use);
        allocator.free(info.deaths);
        allocator.free(info.inst_index);
    }

    // Initialize all to zero
    @memset(info.last_use, 0);
    @memset(info.deaths, 0);
    @memset(info.inst_index, 0);

    // Pass 1: Assign instruction indices (forward order)
    var inst_counter: u32 = 1; // Start at 1 so 0 means "never used"
    for (func.blocks.items) |*block| {
        for (block.values.items) |value_id| {
            if (value_id < num_values) {
                info.inst_index[value_id] = inst_counter;
            }
            inst_counter += 1;
        }
    }

    // Pass 2: Compute last uses (backward order)
    // We walk backward so the first time we see a use is actually the last use
    var block_idx = func.blocks.items.len;
    while (block_idx > 0) {
        block_idx -= 1;
        const block = &func.blocks.items[block_idx];

        // Also check block control value (branch condition)
        if (block.control != ssa.null_value and block.control < num_values) {
            if (info.last_use[block.control] == 0) {
                // Control value's last use is at the end of the block
                // Use a high instruction index to indicate it's used at block terminator
                const block_end_inst = if (block.values.items.len > 0)
                    info.inst_index[block.values.items[block.values.items.len - 1]] + 1
                else
                    inst_counter;
                info.last_use[block.control] = block_end_inst;
            }
        }

        var value_idx = block.values.items.len;
        while (value_idx > 0) {
            value_idx -= 1;
            const value_id = block.values.items[value_idx];
            if (value_id >= num_values) continue;

            const value = func.values.items[value_id];
            const current_inst = info.inst_index[value_id];

            // For each operand, check if this is its last use
            const args = value.args();
            for (args, 0..) |arg_id, i| {
                if (arg_id == ssa.null_value or arg_id >= num_values) continue;

                if (info.last_use[arg_id] == 0) {
                    // First time seeing this arg (in backward order) = last use
                    info.last_use[arg_id] = current_inst;
                    // Mark this operand as dying at this instruction
                    info.deaths[value_id] |= @as(u8, 1) << @intCast(i);
                }
            }
        }
    }

    return info;
}

// ============================================================================
// Tests
// ============================================================================

test "liveness - simple linear" {
    const allocator = std.testing.allocator;
    const types_mod = @import("types.zig");

    var func = ssa.Func.init(allocator, "test", 0, types_mod.TypeRegistry.INT);
    defer func.deinit();

    // v0 = const 1
    // v1 = const 2
    // v2 = add v0, v1
    // ret v2
    const v0 = try func.newValue(.const_int, types_mod.TypeRegistry.INT, func.entry);
    const v1 = try func.newValue(.const_int, types_mod.TypeRegistry.INT, func.entry);
    const v2 = try func.newValue(.add, types_mod.TypeRegistry.INT, func.entry);
    const v3 = try func.newValue(.ret, types_mod.TypeRegistry.VOID, func.entry);

    // Set args for add: v2 = add v0, v1
    var add_val = func.getValue(v2);
    try add_val.setArgs(&.{ v0, v1 }, allocator);

    // Set args for ret: ret v2
    var ret_val = func.getValue(v3);
    try ret_val.setArgs(&.{v2}, allocator);

    var info = try computeLiveness(allocator, &func);
    defer info.deinit();

    // v0's last use is at v2 (the add)
    try std.testing.expect(info.last_use[v0] > 0);
    // v0 dies at v2
    try std.testing.expect(info.operandDies(v2, 0));

    // v1's last use is at v2 (the add)
    try std.testing.expect(info.last_use[v1] > 0);
    // v1 dies at v2
    try std.testing.expect(info.operandDies(v2, 1));

    // v2's last use is at v3 (the ret)
    try std.testing.expect(info.last_use[v2] > 0);
    // v2 dies at v3
    try std.testing.expect(info.operandDies(v3, 0));
}

test "liveness - value used twice" {
    const allocator = std.testing.allocator;
    const types_mod = @import("types.zig");

    var func = ssa.Func.init(allocator, "test", 0, types_mod.TypeRegistry.INT);
    defer func.deinit();

    // v0 = const 1
    // v1 = add v0, v0  (v0 used twice)
    // ret v1
    const v0 = try func.newValue(.const_int, types_mod.TypeRegistry.INT, func.entry);
    const v1 = try func.newValue(.add, types_mod.TypeRegistry.INT, func.entry);
    const v2 = try func.newValue(.ret, types_mod.TypeRegistry.VOID, func.entry);

    var add_val = func.getValue(v1);
    try add_val.setArgs(&.{ v0, v0 }, allocator);

    var ret_val = func.getValue(v2);
    try ret_val.setArgs(&.{v1}, allocator);

    var info = try computeLiveness(allocator, &func);
    defer info.deinit();

    // v0 is used twice in the same instruction
    // Both operands reference v0, but only the second (in backward order = first operand)
    // should be marked as dying
    try std.testing.expect(info.last_use[v0] > 0);

    // At least one of the operands should be marked as dying
    const op0_dies = info.operandDies(v1, 0);
    const op1_dies = info.operandDies(v1, 1);
    try std.testing.expect(op0_dies or op1_dies);
}

test "liveness - value used in multiple instructions" {
    const allocator = std.testing.allocator;
    const types_mod = @import("types.zig");

    var func = ssa.Func.init(allocator, "test", 0, types_mod.TypeRegistry.INT);
    defer func.deinit();

    // v0 = const 1
    // v1 = const 2
    // v2 = add v0, v1
    // v3 = add v0, v2  (v0 used again - later than v2)
    // ret v3
    const v0 = try func.newValue(.const_int, types_mod.TypeRegistry.INT, func.entry);
    const v1 = try func.newValue(.const_int, types_mod.TypeRegistry.INT, func.entry);
    const v2 = try func.newValue(.add, types_mod.TypeRegistry.INT, func.entry);
    const v3 = try func.newValue(.add, types_mod.TypeRegistry.INT, func.entry);
    const v4 = try func.newValue(.ret, types_mod.TypeRegistry.VOID, func.entry);

    var val2 = func.getValue(v2);
    try val2.setArgs(&.{ v0, v1 }, allocator);

    var val3 = func.getValue(v3);
    try val3.setArgs(&.{ v0, v2 }, allocator);

    var val4 = func.getValue(v4);
    try val4.setArgs(&.{v3}, allocator);

    var info = try computeLiveness(allocator, &func);
    defer info.deinit();

    // v0's last use should be at v3 (not v2)
    const v0_last_use = info.last_use[v0];
    const v2_inst = info.inst_index[v2];
    const v3_inst = info.inst_index[v3];

    try std.testing.expect(v0_last_use == v3_inst); // v0 dies at v3, not v2

    // v0 should NOT die at v2 (it's used later)
    try std.testing.expect(!info.operandDies(v2, 0));

    // v0 SHOULD die at v3
    try std.testing.expect(info.operandDies(v3, 0));

    // v1 dies at v2 (only use)
    try std.testing.expect(info.operandDies(v2, 1));

    // v2 dies at v3 (only use)
    try std.testing.expect(info.operandDies(v3, 1));

    _ = v2_inst;
}

test "liveness - distance to next use" {
    const allocator = std.testing.allocator;
    const types_mod = @import("types.zig");

    var func = ssa.Func.init(allocator, "test", 0, types_mod.TypeRegistry.INT);
    defer func.deinit();

    // v0 = const 1  (inst 1)
    // v1 = const 2  (inst 2)
    // v2 = const 3  (inst 3)
    // v3 = add v0, v1  (inst 4) - v0 last use, v1 last use
    // v4 = add v2, v3  (inst 5) - v2 last use, v3 last use
    const v0 = try func.newValue(.const_int, types_mod.TypeRegistry.INT, func.entry);
    const v1 = try func.newValue(.const_int, types_mod.TypeRegistry.INT, func.entry);
    const v2 = try func.newValue(.const_int, types_mod.TypeRegistry.INT, func.entry);
    const v3 = try func.newValue(.add, types_mod.TypeRegistry.INT, func.entry);
    const v4 = try func.newValue(.add, types_mod.TypeRegistry.INT, func.entry);

    var val3 = func.getValue(v3);
    try val3.setArgs(&.{ v0, v1 }, allocator);

    var val4 = func.getValue(v4);
    try val4.setArgs(&.{ v2, v3 }, allocator);

    var info = try computeLiveness(allocator, &func);
    defer info.deinit();

    // At instruction 2 (v1 definition):
    // - v0 has distance 2 (used at inst 4)
    // - v1 has distance 2 (used at inst 4)
    // - v2 has distance 3 (used at inst 5)
    const at_inst_2: u32 = 2;
    const dist_v0 = info.distanceToNextUse(v0, at_inst_2);
    const dist_v1 = info.distanceToNextUse(v1, at_inst_2);
    const dist_v2 = info.distanceToNextUse(v2, at_inst_2);

    // v2 should have the farthest next use
    try std.testing.expect(dist_v2 > dist_v0);
    try std.testing.expect(dist_v2 > dist_v1);
}

test "liveness - unused value" {
    const allocator = std.testing.allocator;
    const types_mod = @import("types.zig");

    var func = ssa.Func.init(allocator, "test", 0, types_mod.TypeRegistry.INT);
    defer func.deinit();

    // v0 = const 1  (never used)
    // v1 = const 2
    // ret v1
    const v0 = try func.newValue(.const_int, types_mod.TypeRegistry.INT, func.entry);
    const v1 = try func.newValue(.const_int, types_mod.TypeRegistry.INT, func.entry);
    const v2 = try func.newValue(.ret, types_mod.TypeRegistry.VOID, func.entry);

    var ret_val = func.getValue(v2);
    try ret_val.setArgs(&.{v1}, allocator);

    var info = try computeLiveness(allocator, &func);
    defer info.deinit();

    // v0 is never used - last_use should be 0
    try std.testing.expectEqual(@as(u32, 0), info.last_use[v0]);

    // Distance to next use for unused value should be 0
    try std.testing.expectEqual(@as(u32, 0), info.distanceToNextUse(v0, 1));
}

test "liveness - isLiveAt" {
    const allocator = std.testing.allocator;
    const types_mod = @import("types.zig");

    var func = ssa.Func.init(allocator, "test", 0, types_mod.TypeRegistry.INT);
    defer func.deinit();

    // v0 = const 1  (inst 1)
    // v1 = const 2  (inst 2)
    // v2 = add v0, v1  (inst 3) - v0 and v1 die here
    // v3 = const 3  (inst 4)
    // v4 = add v2, v3  (inst 5)
    const v0 = try func.newValue(.const_int, types_mod.TypeRegistry.INT, func.entry);
    const v1 = try func.newValue(.const_int, types_mod.TypeRegistry.INT, func.entry);
    const v2 = try func.newValue(.add, types_mod.TypeRegistry.INT, func.entry);
    const v3 = try func.newValue(.const_int, types_mod.TypeRegistry.INT, func.entry);
    const v4 = try func.newValue(.add, types_mod.TypeRegistry.INT, func.entry);

    var val2 = func.getValue(v2);
    try val2.setArgs(&.{ v0, v1 }, allocator);

    var val4 = func.getValue(v4);
    try val4.setArgs(&.{ v2, v3 }, allocator);

    var info = try computeLiveness(allocator, &func);
    defer info.deinit();

    // v0 is live at inst 1, 2, 3 but not at 4, 5
    try std.testing.expect(info.isLiveAt(v0, 1));
    try std.testing.expect(info.isLiveAt(v0, 2));
    try std.testing.expect(info.isLiveAt(v0, 3));
    try std.testing.expect(!info.isLiveAt(v0, 4));
    try std.testing.expect(!info.isLiveAt(v0, 5));

    // v2 is live at inst 3, 4, 5 but not before
    try std.testing.expect(!info.isLiveAt(v2, 1));
    try std.testing.expect(!info.isLiveAt(v2, 2));
    try std.testing.expect(info.isLiveAt(v2, 3));
    try std.testing.expect(info.isLiveAt(v2, 4));
    try std.testing.expect(info.isLiveAt(v2, 5));
}
