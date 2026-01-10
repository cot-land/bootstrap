///! Register Allocator for Cot
///!
///! Implements a greedy register allocation algorithm inspired by Go's compiler.
///! Uses "distance to next use" to decide which value to evict when all registers
///! are full - this is the theoretically optimal page replacement algorithm.
///!
///! Key concepts:
///! - Each SSA value tracks a linked list of upcoming uses with distances
///! - When allocating, we pick free registers first
///! - When spilling, we evict the value with the farthest next use
///! - Spilled values go to stack slots and are reloaded when needed

const std = @import("std");
const Allocator = std.mem.Allocator;
const ssa = @import("ssa.zig");
const driver = @import("driver.zig");

// Forward reference to StorageManager from driver.zig
pub const StorageManager = driver.StorageManager;

// ============================================================================
// Register Definitions
// ============================================================================

/// x86_64 general-purpose registers
pub const X86Reg = enum(u5) {
    rax = 0,
    rcx = 1,
    rdx = 2,
    rbx = 3,
    rsp = 4, // Stack pointer - not allocatable
    rbp = 5, // Frame pointer - not allocatable
    rsi = 6,
    rdi = 7,
    r8 = 8,
    r9 = 9,
    r10 = 10,
    r11 = 11,
    r12 = 12,
    r13 = 13,
    r14 = 14,
    r15 = 15,

    pub fn mask(self: X86Reg) RegMask {
        return @as(RegMask, 1) << @intFromEnum(self);
    }
};

/// AArch64 general-purpose registers
pub const AArch64Reg = enum(u5) {
    x0 = 0,
    x1 = 1,
    x2 = 2,
    x3 = 3,
    x4 = 4,
    x5 = 5,
    x6 = 6,
    x7 = 7,
    x8 = 8,
    x9 = 9,
    x10 = 10,
    x11 = 11,
    x12 = 12,
    x13 = 13,
    x14 = 14,
    x15 = 15,
    x16 = 16, // IP0 - scratch
    x17 = 17, // IP1 - scratch
    x18 = 18, // Platform register - not allocatable
    x19 = 19,
    x20 = 20,
    x21 = 21,
    x22 = 22,
    x23 = 23,
    x24 = 24,
    x25 = 25,
    x26 = 26,
    x27 = 27,
    x28 = 28,
    x29 = 29, // Frame pointer - not allocatable
    x30 = 30, // Link register
    // x31 is sp/zr depending on context

    pub fn mask(self: AArch64Reg) RegMask {
        return @as(RegMask, 1) << @intFromEnum(self);
    }
};

/// Bitmask for register sets (up to 32 registers)
pub const RegMask = u32;

// ============================================================================
// Calling Conventions
// ============================================================================

/// Calling convention specification
pub const CallConv = struct {
    /// Registers used for passing arguments
    param_regs: RegMask,
    /// Registers used for return values
    return_regs: RegMask,
    /// Caller-saved registers (clobbered by calls)
    caller_saved: RegMask,
    /// Callee-saved registers (must be preserved across calls)
    callee_saved: RegMask,
    /// Registers available for allocation
    allocatable: RegMask,
};

/// System V AMD64 ABI (Linux, macOS)
pub const x86_64_sysv = CallConv{
    // rdi, rsi, rdx, rcx, r8, r9
    .param_regs = X86Reg.rdi.mask() | X86Reg.rsi.mask() | X86Reg.rdx.mask() |
        X86Reg.rcx.mask() | X86Reg.r8.mask() | X86Reg.r9.mask(),
    // rax, rdx (for 128-bit returns)
    .return_regs = X86Reg.rax.mask() | X86Reg.rdx.mask(),
    // rax, rcx, rdx, rsi, rdi, r8-r11
    .caller_saved = X86Reg.rax.mask() | X86Reg.rcx.mask() | X86Reg.rdx.mask() |
        X86Reg.rsi.mask() | X86Reg.rdi.mask() | X86Reg.r8.mask() |
        X86Reg.r9.mask() | X86Reg.r10.mask() | X86Reg.r11.mask(),
    // rbx, r12-r15
    .callee_saved = X86Reg.rbx.mask() | X86Reg.r12.mask() | X86Reg.r13.mask() |
        X86Reg.r14.mask() | X86Reg.r15.mask(),
    // All GP registers except rsp, rbp (14 registers: rax, rcx, rdx, rbx, rsi, rdi, r8-r15)
    .allocatable = 0xFFFF & ~(X86Reg.rsp.mask() | X86Reg.rbp.mask()),
};

/// AAPCS64 (ARM64)
pub const aarch64_aapcs = CallConv{
    // x0-x7
    .param_regs = AArch64Reg.x0.mask() | AArch64Reg.x1.mask() | AArch64Reg.x2.mask() |
        AArch64Reg.x3.mask() | AArch64Reg.x4.mask() | AArch64Reg.x5.mask() |
        AArch64Reg.x6.mask() | AArch64Reg.x7.mask(),
    // x0, x1 (for 128-bit returns)
    .return_regs = AArch64Reg.x0.mask() | AArch64Reg.x1.mask(),
    // x0-x18, x30
    .caller_saved = blk: {
        var mask: RegMask = 0;
        for (0..19) |i| {
            mask |= @as(RegMask, 1) << i;
        }
        mask |= AArch64Reg.x30.mask();
        break :blk mask;
    },
    // x19-x28
    .callee_saved = blk: {
        var mask: RegMask = 0;
        for (19..29) |i| {
            mask |= @as(RegMask, 1) << i;
        }
        break :blk mask;
    },
    // All GP registers x0-x30 except x18 (platform), x29 (fp)
    // x31 is sp/zr, not a GP register
    .allocatable = 0x7FFFFFFF & ~(AArch64Reg.x18.mask() | AArch64Reg.x29.mask()),
};

// ============================================================================
// Use Tracking
// ============================================================================

/// A single use of a value, part of a linked list
pub const Use = struct {
    /// Distance from current position to this use (in instruction units)
    /// Higher = farther away
    dist: i32,
    /// Next use in the list (sorted by distance, closest first)
    next: ?*Use,
};

/// Distance weights for different instruction types
pub const Distance = struct {
    /// Likely to be used (e.g., in a conditional that's likely taken)
    pub const likely: i32 = 1;
    /// Normal instruction
    pub const normal: i32 = 10;
    /// After a function call (value likely spilled anyway)
    pub const after_call: i32 = 100;
    /// Very far away (effectively infinite)
    pub const far: i32 = 1_000_000;
};

// ============================================================================
// Value State
// ============================================================================

/// State for a single SSA value during register allocation
pub const ValState = struct {
    /// Which registers currently hold this value (usually 0 or 1 bit set)
    regs: RegMask = 0,
    /// Linked list of upcoming uses, sorted by distance (closest first)
    uses: ?*Use = null,
    /// Stack slot offset if spilled (null if not spilled)
    spill_slot: ?i32 = null,
    /// True if this value can be rematerialized instead of reloaded
    rematerializeable: bool = false,
    /// For rematerialization: the original operation
    remat_op: ?ssa.Op = null,
    /// For rematerialization: auxiliary data
    remat_aux: i64 = 0,

    /// Check if value is currently in any register
    pub fn inReg(self: *const ValState) bool {
        return self.regs != 0;
    }

    /// Get the first register holding this value (assumes at least one)
    pub fn firstReg(self: *const ValState) u5 {
        return @truncate(@ctz(self.regs));
    }

    /// Distance to next use (far if no uses)
    pub fn nextUseDist(self: *const ValState) i32 {
        if (self.uses) |use| {
            return use.dist;
        }
        return Distance.far;
    }

    /// Pop the next use from the list
    pub fn popUse(self: *ValState) void {
        if (self.uses) |use| {
            self.uses = use.next;
        }
    }
};

// ============================================================================
// Register State
// ============================================================================

/// State for a single register
pub const RegState = struct {
    /// SSA value ID currently in this register (null if free)
    value: ?ssa.ValueID = null,
    /// True if this register is locked (can't be evicted)
    locked: bool = false,
};

// ============================================================================
// Spill Record
// ============================================================================

/// Records a spill operation to be emitted
pub const SpillRecord = struct {
    /// Value being spilled
    value_id: ssa.ValueID,
    /// Register being spilled from
    reg: u5,
    /// Stack slot to spill to
    slot: i32,
    /// Position in instruction stream where spill should be inserted
    pos: u32,
};

/// Records a reload operation to be emitted
pub const ReloadRecord = struct {
    /// Value being reloaded
    value_id: ssa.ValueID,
    /// Register to reload into
    reg: u5,
    /// Stack slot to reload from
    slot: i32,
    /// Position in instruction stream where reload should be inserted
    pos: u32,
};

// ============================================================================
// Register Allocator
// ============================================================================

/// Main register allocator
pub const RegAllocator = struct {
    allocator: Allocator,

    /// Calling convention to use
    call_conv: CallConv,

    /// State for each SSA value (indexed by ValueID)
    values: std.ArrayList(ValState),

    /// State for each register
    regs: [32]RegState,

    /// Which registers are currently in use
    used: RegMask,

    /// Arena for Use nodes (freed all at once at end)
    use_arena: std.heap.ArenaAllocator,

    /// Recorded spills (to be emitted later)
    spills: std.ArrayList(SpillRecord),

    /// Recorded reloads (to be emitted later)
    reloads: std.ArrayList(ReloadRecord),

    /// External storage manager for spill slot allocation (optional)
    /// If null, uses internal slot counter
    storage: ?*StorageManager,

    /// Fallback spill slot offset when no StorageManager (grows negative from rbp)
    next_spill_slot: i32,

    /// Current position in instruction stream
    current_pos: u32,

    /// Initialize with optional StorageManager integration
    pub fn init(allocator: Allocator, call_conv: CallConv, num_values: usize) !RegAllocator {
        return initWithStorage(allocator, call_conv, num_values, null);
    }

    /// Initialize with StorageManager for spill slot allocation
    pub fn initWithStorage(allocator: Allocator, call_conv: CallConv, num_values: usize, storage: ?*StorageManager) !RegAllocator {
        var values = std.ArrayList(ValState){ .items = &.{}, .capacity = 0 };
        try values.ensureTotalCapacity(allocator, num_values);
        for (0..num_values) |_| {
            try values.append(allocator, ValState{});
        }

        const spills = std.ArrayList(SpillRecord){ .items = &.{}, .capacity = 0 };
        const reloads = std.ArrayList(ReloadRecord){ .items = &.{}, .capacity = 0 };

        return RegAllocator{
            .allocator = allocator,
            .call_conv = call_conv,
            .values = values,
            .regs = [_]RegState{.{}} ** 32,
            .used = 0,
            .use_arena = std.heap.ArenaAllocator.init(allocator),
            .spills = spills,
            .reloads = reloads,
            .storage = storage,
            .next_spill_slot = -8, // Fallback: first slot at [rbp-8]
            .current_pos = 0,
        };
    }

    pub fn deinit(self: *RegAllocator) void {
        self.values.deinit(self.allocator);
        self.use_arena.deinit();
        self.spills.deinit(self.allocator);
        self.reloads.deinit(self.allocator);
    }

    /// Reset for a new function
    pub fn reset(self: *RegAllocator, num_values: usize) !void {
        self.values.clearRetainingCapacity();
        try self.values.ensureTotalCapacity(self.allocator, num_values);
        for (0..num_values) |_| {
            try self.values.append(self.allocator, ValState{});
        }
        self.regs = [_]RegState{.{}} ** 32;
        self.used = 0;
        _ = self.use_arena.reset(.retain_capacity);
        self.spills.clearRetainingCapacity();
        self.reloads.clearRetainingCapacity();
        self.next_spill_slot = -8;
        self.current_pos = 0;
        // Note: storage manager reset is handled externally
    }

    // ========================================================================
    // Use Tracking (called during backward scan)
    // ========================================================================

    /// Add a use of a value at the current distance
    pub fn addUse(self: *RegAllocator, value_id: ssa.ValueID, dist: i32) !void {
        if (value_id >= self.values.items.len) return;

        const arena_alloc = self.use_arena.allocator();
        const new_use = try arena_alloc.create(Use);
        new_use.* = .{
            .dist = dist,
            .next = self.values.items[value_id].uses,
        };
        self.values.items[value_id].uses = new_use;
    }

    /// Mark a value as rematerializeable (can be recomputed instead of reloaded)
    pub fn markRematerializeable(self: *RegAllocator, value_id: ssa.ValueID, op: ssa.Op, aux: i64) void {
        if (value_id >= self.values.items.len) return;
        self.values.items[value_id].rematerializeable = true;
        self.values.items[value_id].remat_op = op;
        self.values.items[value_id].remat_aux = aux;
    }

    // ========================================================================
    // Register Allocation
    // ========================================================================

    /// Allocate a register for a value, spilling if necessary
    /// Returns the register number (0-31)
    pub fn allocReg(self: *RegAllocator, value_id: ssa.ValueID, mask: RegMask) !u5 {
        const allocatable = mask & self.call_conv.allocatable;
        if (allocatable == 0) return error.NoAllocatableRegisters;

        // Check if already in a suitable register
        const val_state = &self.values.items[value_id];
        const existing = val_state.regs & allocatable;
        if (existing != 0) {
            return @truncate(@ctz(existing));
        }

        // Try to find a free register
        const free = allocatable & ~self.used;
        if (free != 0) {
            const reg: u5 = @truncate(@ctz(free));
            self.assignReg(value_id, reg);
            return reg;
        }

        // Need to spill - find register with farthest next use
        const reg = try self.findSpillCandidate(allocatable);
        try self.spillReg(reg);
        self.assignReg(value_id, reg);
        return reg;
    }

    /// Allocate a specific register, spilling current occupant if needed
    pub fn allocSpecificReg(self: *RegAllocator, value_id: ssa.ValueID, reg: u5) !void {
        const mask = @as(RegMask, 1) << reg;

        // Check if value is already in this register
        if (self.values.items[value_id].regs & mask != 0) {
            return;
        }

        // Check if register is free
        if (self.used & mask == 0) {
            self.assignReg(value_id, reg);
            return;
        }

        // Need to spill current occupant
        try self.spillReg(reg);
        self.assignReg(value_id, reg);
    }

    /// Ensure a value is in a register (load from spill slot if needed)
    pub fn ensureInReg(self: *RegAllocator, value_id: ssa.ValueID, mask: RegMask) !u5 {
        const val_state = &self.values.items[value_id];

        // Already in suitable register?
        const existing = val_state.regs & mask & self.call_conv.allocatable;
        if (existing != 0) {
            return @truncate(@ctz(existing));
        }

        // Need to allocate a register
        const reg = try self.allocReg(value_id, mask);

        // If spilled, emit reload
        if (val_state.spill_slot) |slot| {
            try self.reloads.append(self.allocator, .{
                .value_id = value_id,
                .reg = reg,
                .slot = slot,
                .pos = self.current_pos,
            });
        }

        return reg;
    }

    /// Free a register (mark value as no longer in it)
    pub fn freeReg(self: *RegAllocator, reg: u5) void {
        const mask = @as(RegMask, 1) << reg;
        if (self.regs[reg].value) |value_id| {
            self.values.items[value_id].regs &= ~mask;
        }
        self.regs[reg].value = null;
        self.used &= ~mask;
    }

    /// Lock a register (prevent it from being allocated/spilled)
    pub fn lockReg(self: *RegAllocator, reg: u5) void {
        self.regs[reg].locked = true;
    }

    /// Unlock a register
    pub fn unlockReg(self: *RegAllocator, reg: u5) void {
        self.regs[reg].locked = false;
    }

    /// Consume a use of a value (call after generating code that uses it)
    pub fn consumeUse(self: *RegAllocator, value_id: ssa.ValueID) void {
        if (value_id < self.values.items.len) {
            self.values.items[value_id].popUse();
        }
    }

    /// Advance position counter
    pub fn advancePos(self: *RegAllocator) void {
        self.current_pos += 1;
    }

    // ========================================================================
    // Internal Helpers
    // ========================================================================

    fn assignReg(self: *RegAllocator, value_id: ssa.ValueID, reg: u5) void {
        const mask = @as(RegMask, 1) << reg;
        self.values.items[value_id].regs |= mask;
        self.regs[reg].value = value_id;
        self.used |= mask;
    }

    fn findSpillCandidate(self: *RegAllocator, mask: RegMask) !u5 {
        var best_reg: ?u5 = null;
        var best_dist: i32 = -1;

        var remaining = mask & self.used;
        while (remaining != 0) {
            const reg: u5 = @truncate(@ctz(remaining));
            remaining &= remaining - 1; // Clear lowest bit

            // Skip locked registers
            if (self.regs[reg].locked) continue;

            if (self.regs[reg].value) |value_id| {
                const dist = self.values.items[value_id].nextUseDist();
                if (dist > best_dist) {
                    best_dist = dist;
                    best_reg = reg;
                }
            }
        }

        return best_reg orelse error.AllRegistersLocked;
    }

    fn spillReg(self: *RegAllocator, reg: u5) !void {
        const value_id = self.regs[reg].value orelse return;
        const val_state = &self.values.items[value_id];

        // If already spilled, just free the register
        if (val_state.spill_slot != null) {
            self.freeReg(reg);
            return;
        }

        // If rematerializeable, just mark as not in register
        if (val_state.rematerializeable) {
            self.freeReg(reg);
            return;
        }

        // Allocate spill slot via StorageManager or fallback
        const slot = if (self.storage) |sm|
            try sm.allocate(value_id)
        else blk: {
            const s = self.next_spill_slot;
            self.next_spill_slot -= 8;
            break :blk s;
        };
        val_state.spill_slot = slot;

        // Record spill
        try self.spills.append(self.allocator, .{
            .value_id = value_id,
            .reg = reg,
            .slot = slot,
            .pos = self.current_pos,
        });

        self.freeReg(reg);
    }

    // ========================================================================
    // Query Functions
    // ========================================================================

    /// Get the register(s) holding a value
    pub fn getRegs(self: *const RegAllocator, value_id: ssa.ValueID) RegMask {
        if (value_id >= self.values.items.len) return 0;
        return self.values.items[value_id].regs;
    }

    /// Check if a value is in any register
    pub fn isInReg(self: *const RegAllocator, value_id: ssa.ValueID) bool {
        return self.getRegs(value_id) != 0;
    }

    /// Get spill slot for a value (null if not spilled)
    pub fn getSpillSlot(self: *const RegAllocator, value_id: ssa.ValueID) ?i32 {
        if (value_id >= self.values.items.len) return null;
        return self.values.items[value_id].spill_slot;
    }

    /// Get total spill area size (for stack frame)
    pub fn getSpillAreaSize(self: *const RegAllocator) u32 {
        // next_spill_slot is negative, e.g., -24 means 24 bytes used
        return @intCast(-self.next_spill_slot - 8);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "RegMask operations" {
    const rax_mask = X86Reg.rax.mask();
    const rdx_mask = X86Reg.rdx.mask();

    try std.testing.expectEqual(@as(RegMask, 1), rax_mask);
    try std.testing.expectEqual(@as(RegMask, 4), rdx_mask);
    try std.testing.expectEqual(@as(RegMask, 5), rax_mask | rdx_mask);
}

test "CallConv x86_64" {
    const cc = x86_64_sysv;

    // rdi should be a param reg
    try std.testing.expect(cc.param_regs & X86Reg.rdi.mask() != 0);

    // rsp should not be allocatable
    try std.testing.expect(cc.allocatable & X86Reg.rsp.mask() == 0);

    // rbx should be callee-saved
    try std.testing.expect(cc.callee_saved & X86Reg.rbx.mask() != 0);
}

test "RegAllocator basic allocation" {
    const allocator = std.testing.allocator;
    var ra = try RegAllocator.init(allocator, x86_64_sysv, 10);
    defer ra.deinit();

    // Allocate a register for value 0
    const reg = try ra.allocReg(0, x86_64_sysv.allocatable);

    // Value should now be in that register
    try std.testing.expect(ra.isInReg(0));
    try std.testing.expectEqual(ra.regs[reg].value, 0);
}

test "RegAllocator spill on pressure" {
    const allocator = std.testing.allocator;
    var ra = try RegAllocator.init(allocator, x86_64_sysv, 20);
    defer ra.deinit();

    // Add uses for all values (higher distance = lower priority for keeping)
    for (0..16) |i| {
        try ra.addUse(@intCast(i), @intCast(i * 10));
    }

    // x86_64 has 14 allocatable registers (16 - rsp - rbp)
    // Allocate all 14 registers
    for (0..14) |i| {
        _ = try ra.allocReg(@intCast(i), x86_64_sysv.allocatable);
    }

    // Verify all 14 are allocated
    try std.testing.expectEqual(@as(u32, 14), @popCount(ra.used & x86_64_sysv.allocatable));

    // Allocating one more (value 14) should trigger a spill
    _ = try ra.allocReg(14, x86_64_sysv.allocatable);

    // Should have recorded a spill
    try std.testing.expect(ra.spills.items.len > 0);
}

test "ValState nextUseDist" {
    var state = ValState{};

    // No uses = far distance
    try std.testing.expectEqual(Distance.far, state.nextUseDist());
}

test "RegAllocator with StorageManager" {
    const allocator = std.testing.allocator;

    // Create a StorageManager
    var storage = StorageManager.init(allocator);
    defer storage.deinit();

    // Create RegAllocator with StorageManager
    var ra = try RegAllocator.initWithStorage(allocator, x86_64_sysv, 20, &storage);
    defer ra.deinit();

    // Add uses for all values (higher distance = lower priority for keeping)
    for (0..16) |i| {
        try ra.addUse(@intCast(i), @intCast(i * 10));
    }

    // x86_64 has 14 allocatable registers
    // Allocate all 14 registers
    for (0..14) |i| {
        _ = try ra.allocReg(@intCast(i), x86_64_sysv.allocatable);
    }

    // Verify all 14 are allocated
    try std.testing.expectEqual(@as(u32, 14), @popCount(ra.used & x86_64_sysv.allocatable));

    // Allocating one more should trigger a spill
    _ = try ra.allocReg(14, x86_64_sysv.allocatable);

    // Should have recorded a spill
    try std.testing.expect(ra.spills.items.len > 0);

    // The spill should have used StorageManager
    const spilled_value = ra.spills.items[0].value_id;
    try std.testing.expect(storage.has(spilled_value));
}

test "RegAllocator farthest-next-use eviction" {
    const allocator = std.testing.allocator;
    var ra = try RegAllocator.init(allocator, x86_64_sysv, 4);
    defer ra.deinit();

    // Value 0: next use at distance 10 (close)
    // Value 1: next use at distance 100 (far)
    // Value 2: next use at distance 50 (medium)
    try ra.addUse(0, 10);
    try ra.addUse(1, 100);
    try ra.addUse(2, 50);

    // Allocate all three into registers
    _ = try ra.allocReg(0, x86_64_sysv.allocatable);
    _ = try ra.allocReg(1, x86_64_sysv.allocatable);
    _ = try ra.allocReg(2, x86_64_sysv.allocatable);

    // Force all other registers to be "used" to trigger spill
    ra.used = x86_64_sysv.allocatable;

    // Allocate value 3 - should spill value 1 (farthest next use)
    try ra.addUse(3, 5);
    _ = try ra.allocReg(3, x86_64_sysv.allocatable);

    // Should have spilled value 1 (distance 100)
    try std.testing.expect(ra.spills.items.len > 0);
    try std.testing.expectEqual(@as(u32, 1), ra.spills.items[0].value_id);
}
