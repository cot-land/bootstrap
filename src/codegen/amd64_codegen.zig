//! x86_64 Code Generation with Integrated Register Allocation
//!
//! This module follows Zig's approach: register allocation happens DURING
//! codegen, not as a separate pass. This avoids the fundamental problem of
//! trying to allocate registers without knowing which values are live together.
//!
//! Key concepts (from Zig's CodeGen.zig):
//! - MCValue: where a value currently lives (register, stack, immediate)
//! - InstTracking: tracks home location (for spills) and current location
//! - RegisterManager: tracks which registers are free/used/locked
//! - Spilling happens on-demand when we need a register and none are free

const std = @import("std");
const Allocator = std.mem.Allocator;

const ssa = @import("../ssa.zig");
const types = @import("../types.zig");
const x86 = @import("x86_64.zig");
const be = @import("backend.zig");
const object = @import("object.zig");
const liveness = @import("../liveness.zig");

// ============================================================================
// ABI Classification (x86_64 SysV)
// ============================================================================

/// Classification for x86_64 SysV ABI calling convention
pub const ABIClass = enum {
    /// Fits in 1 register (≤8 bytes)
    single_reg,
    /// Fits in 2 registers (9-16 bytes) - rax + rdx
    double_reg,
    /// Passed via hidden pointer (>16 bytes)
    by_pointer,
    /// Slice type - always 2 registers (ptr + len)
    slice,
};

/// Classify a type for x86_64 SysV ABI
pub fn classifyType(type_reg: *const types.TypeRegistry, type_idx: types.TypeIndex) ABIClass {
    const t = type_reg.get(type_idx);
    const size = type_reg.sizeOf(type_idx);

    // Slices are special - always passed as ptr+len in 2 registers
    if (t == .slice) {
        return .slice;
    }

    // Size-based classification (x86_64 SysV ABI)
    if (size > 16) {
        return .by_pointer;
    } else if (size > 8) {
        return .double_reg;
    } else {
        return .single_reg;
    }
}

// ============================================================================
// MCValue - Machine Code Value (where a value lives)
// ============================================================================

/// Represents the location of a value in machine code.
/// Mirrors Zig's MCValue but simplified for our needs.
pub const MCValue = union(enum) {
    /// No runtime value (void, already consumed, etc.)
    none,
    /// Dead - value is no longer needed
    dead,
    /// Immediate constant that fits in an instruction
    immediate: i64,
    /// Value is in a register
    register: x86.Reg,
    /// Value is on stack at [rbp + offset]
    stack: i32,
    /// Value is a string literal at a symbol offset
    lea_symbol: struct {
        name: []const u8,
        len: usize,
    },

    pub fn isRegister(self: MCValue) bool {
        return self == .register;
    }

    pub fn getReg(self: MCValue) ?x86.Reg {
        return switch (self) {
            .register => |r| r,
            else => null,
        };
    }

    pub fn getStack(self: MCValue) ?i32 {
        return switch (self) {
            .stack => |s| s,
            else => null,
        };
    }
};

// ============================================================================
// InstTracking - Track where a value lives
// ============================================================================

/// Tracks both the "home" location (where to spill to) and current location.
/// When a value is spilled, we copy from current to home, then set current = home.
pub const InstTracking = struct {
    /// Home location - where the value can be reloaded from.
    /// This is either a stack slot or .none (meaning we need to allocate one on spill).
    home: MCValue,
    /// Current location - where the value is right now.
    /// Might be a register (fast) or same as home (spilled).
    current: MCValue,

    pub fn init(result: MCValue) InstTracking {
        return switch (result) {
            // Values that don't need registers keep their location as-is
            .none, .dead, .immediate, .stack, .lea_symbol => .{
                .home = result,
                .current = result,
            },
            // Values in registers: home is none (allocate on spill), current is register
            .register => .{
                .home = .none,
                .current = result,
            },
        };
    }

    pub fn getReg(self: InstTracking) ?x86.Reg {
        return self.current.getReg();
    }

    pub fn isInRegister(self: InstTracking) bool {
        return self.current.isRegister();
    }

    pub fn isSpilled(self: InstTracking) bool {
        return std.meta.eql(self.home, self.current);
    }
};

// ============================================================================
// RegisterManager - Track register allocation state
// ============================================================================

/// Registers available for allocation on x86_64.
/// We use callee-saved first (survive calls), then caller-saved.
pub const allocatable_regs = [_]x86.Reg{
    // Callee-saved (survive function calls)
    .rbx, .r12, .r13, .r14, .r15,
    // Caller-saved (clobbered by calls, but more available)
    .rax, .rcx, .rdx, .rsi, .rdi, .r8, .r9,
};

/// Scratch registers - never allocated, used for temporaries during codegen
pub const scratch0: x86.Reg = .r10;
pub const scratch1: x86.Reg = .r11;

/// Number of callee-saved registers (for call handling)
pub const num_callee_saved: usize = 5;

pub const RegisterManager = struct {
    /// For each allocatable register, which SSA value is in it (or null)
    registers: [allocatable_regs.len]?ssa.ValueID = .{null} ** allocatable_regs.len,

    /// Bitset of free registers (1 = free)
    free_regs: u16 = (1 << allocatable_regs.len) - 1,

    /// Bitset of locked registers (can't be allocated or spilled)
    locked_regs: u16 = 0,

    /// Find the index of a register in our allocatable set
    fn indexOf(reg: x86.Reg) ?u4 {
        for (allocatable_regs, 0..) |r, i| {
            if (r == reg) return @intCast(i);
        }
        return null;
    }

    /// Check if a register is free
    pub fn isFree(self: *const RegisterManager, reg: x86.Reg) bool {
        const idx = indexOf(reg) orelse return true; // Not tracked = free
        return (self.free_regs >> @intCast(idx)) & 1 == 1;
    }

    /// Check if a register is locked
    pub fn isLocked(self: *const RegisterManager, reg: x86.Reg) bool {
        const idx = indexOf(reg) orelse return false;
        return (self.locked_regs >> @intCast(idx)) & 1 == 1;
    }

    /// Lock a register (prevent allocation/spilling)
    pub fn lock(self: *RegisterManager, reg: x86.Reg) void {
        if (indexOf(reg)) |idx| {
            self.locked_regs |= @as(u16, 1) << @intCast(idx);
        }
    }

    /// Unlock a register
    pub fn unlock(self: *RegisterManager, reg: x86.Reg) void {
        if (indexOf(reg)) |idx| {
            self.locked_regs &= ~(@as(u16, 1) << @intCast(idx));
        }
    }

    /// Mark a register as used by a value
    pub fn markUsed(self: *RegisterManager, reg: x86.Reg, value_id: ssa.ValueID) void {
        if (indexOf(reg)) |idx| {
            self.registers[idx] = value_id;
            self.free_regs &= ~(@as(u16, 1) << @intCast(idx));
        }
    }

    /// Mark a register as free
    pub fn markFree(self: *RegisterManager, reg: x86.Reg) void {
        if (indexOf(reg)) |idx| {
            self.registers[idx] = null;
            self.free_regs |= @as(u16, 1) << @intCast(idx);
        }
    }

    /// Get which value is in a register
    pub fn getValueIn(self: *const RegisterManager, reg: x86.Reg) ?ssa.ValueID {
        const idx = indexOf(reg) orelse return null;
        return self.registers[idx];
    }

    /// Try to allocate a free register, returns null if none available
    pub fn tryAlloc(self: *RegisterManager, value_id: ?ssa.ValueID) ?x86.Reg {
        const available = self.free_regs & ~self.locked_regs;
        if (available == 0) return null;

        const idx: u4 = @intCast(@ctz(available));
        const reg = allocatable_regs[idx];

        if (value_id) |vid| {
            self.markUsed(reg, vid);
        }
        return reg;
    }

    /// Find a register to spill (the one we'll evict)
    /// Returns null if all registers are locked
    pub fn findSpillCandidate(self: *const RegisterManager) ?x86.Reg {
        const spillable = ~self.free_regs & ~self.locked_regs;
        if (spillable == 0) return null;

        // For now, just pick the first spillable register
        // TODO: Pick the one with farthest next use
        const idx: u4 = @intCast(@ctz(spillable));
        return allocatable_regs[idx];
    }
};

// ============================================================================
// CodeGen - Main code generator with integrated register allocation
// ============================================================================

pub const CodeGen = struct {
    allocator: Allocator,
    buf: *be.CodeBuffer,
    func: *ssa.Func,
    type_reg: *types.TypeRegistry,
    os: be.OS,

    /// Track where each SSA value lives
    tracking: std.AutoHashMap(ssa.ValueID, InstTracking),

    /// Register allocation state
    reg_manager: RegisterManager,

    /// String literal info (for rodata section)
    string_infos: []const be.StringInfo,

    /// Next available spill slot offset (grows negative from rbp)
    next_spill_offset: i32,

    /// Stack size for this function
    stack_size: u32,

    // Liveness analysis for smart spill decisions
    liveness_info: ?liveness.LivenessInfo = null,
    current_inst: u32 = 0,

    /// For sret (struct return): offset where hidden return pointer is saved
    /// Only valid when has_sret is true
    sret_offset: i32 = 0,

    /// Whether this function uses sret convention (return type > 16 bytes)
    has_sret: bool = false,

    pub fn init(
        allocator: Allocator,
        buf: *be.CodeBuffer,
        func: *ssa.Func,
        type_reg: *types.TypeRegistry,
        os: be.OS,
        string_infos: []const be.StringInfo,
    ) CodeGen {
        // Check if function uses sret (return type > 16 bytes)
        // Following Go/Zig pattern: sret uses hidden pointer in first param register
        const has_sret = classifyType(type_reg, func.return_type) == .by_pointer;

        // Calculate offsets based on whether sret is used
        // Layout: [locals | sret slot (if needed) | spill slots]
        // All offsets are negative from rbp
        const base_offset = -@as(i32, @intCast(func.frame_size));

        // sret slot is just below locals (8 bytes for pointer)
        const sret_slot: i32 = if (has_sret) base_offset - 8 else 0;

        // Spill slots start below sret slot (if present) or below locals
        const spill_start: i32 = if (has_sret) sret_slot - 8 else base_offset - 8;

        // Stack size: locals + sret slot (if any) + estimated spill space
        const sret_space: u32 = if (has_sret) 8 else 0;
        const stack_size = func.frame_size + sret_space + @as(u32, @intCast(func.values.items.len)) * 8;

        return .{
            .allocator = allocator,
            .buf = buf,
            .func = func,
            .type_reg = type_reg,
            .os = os,
            .tracking = std.AutoHashMap(ssa.ValueID, InstTracking).init(allocator),
            .reg_manager = .{},
            .string_infos = string_infos,
            .next_spill_offset = spill_start,
            .stack_size = stack_size,
            .has_sret = has_sret,
            .sret_offset = sret_slot,
        };
    }

    pub fn deinit(self: *CodeGen) void {
        self.tracking.deinit();
        if (self.liveness_info) |*info| {
            info.deinit();
        }
    }

    /// Compute liveness information for smarter spill decisions.
    /// Call this once before code generation begins.
    pub fn computeLiveness(self: *CodeGen) !void {
        self.liveness_info = try liveness.computeLiveness(self.allocator, self.func);
    }

    /// Advance the instruction counter. Call this for each value generated.
    pub fn advanceInst(self: *CodeGen) void {
        self.current_inst += 1;
    }

    // ========================================================================
    // Core allocation functions
    // ========================================================================

    /// Allocate a register for a value. May spill another value if needed.
    pub fn allocReg(self: *CodeGen, value_id: ?ssa.ValueID) !x86.Reg {
        // Try to get a free register
        if (self.reg_manager.tryAlloc(value_id)) |reg| {
            return reg;
        }

        // No free register - need to spill something
        const spill_reg = self.findBestSpillCandidate() orelse {
            return error.AllRegistersLocked;
        };

        try self.spillReg(spill_reg);

        // Now it's free
        if (value_id) |vid| {
            self.reg_manager.markUsed(spill_reg, vid);
        }
        return spill_reg;
    }

    /// Find the best register to spill using farthest-next-use heuristic.
    /// If liveness info is available, picks the register whose value is used
    /// farthest in the future. Otherwise falls back to first-available.
    fn findBestSpillCandidate(self: *CodeGen) ?x86.Reg {
        // If we have liveness info, use farthest-next-use heuristic
        if (self.liveness_info) |lv| {
            var best_reg: ?x86.Reg = null;
            var best_distance: u32 = 0;

            for (allocatable_regs, 0..) |reg, idx| {
                // Skip locked or free registers
                if (self.reg_manager.isLocked(reg) or self.reg_manager.isFree(reg)) continue;

                // Get the value in this register
                if (self.reg_manager.registers[idx]) |vid| {
                    const dist = lv.distanceToNextUse(vid, self.current_inst);
                    // Prefer registers with values that are used farther away
                    // Also prefer registers with dead values (dist == 0)
                    if (dist == 0) {
                        // Value is dead - best candidate!
                        return reg;
                    }
                    if (dist > best_distance) {
                        best_distance = dist;
                        best_reg = reg;
                    }
                }
            }

            if (best_reg) |reg| return reg;
        }

        // Fallback: use RegisterManager's simple first-available
        return self.reg_manager.findSpillCandidate();
    }

    /// Spill the value in a register to its home location
    fn spillReg(self: *CodeGen, reg: x86.Reg) !void {
        const value_id = self.reg_manager.getValueIn(reg) orelse return;
        const tracking = self.tracking.getPtr(value_id) orelse return;

        // Already spilled?
        if (tracking.isSpilled()) {
            self.reg_manager.markFree(reg);
            return;
        }

        // Allocate spill slot if needed
        if (tracking.home == .none) {
            tracking.home = .{ .stack = self.next_spill_offset };
            self.next_spill_offset -= 8;
        }

        // Generate spill code: mov [rbp+offset], reg
        const offset = tracking.home.getStack().?;
        try x86.movMemReg(self.buf, .rbp, offset, reg);

        // Update tracking
        tracking.current = tracking.home;
        self.reg_manager.markFree(reg);
    }

    /// Get the current location of a value
    pub fn getValue(self: *CodeGen, value_id: ssa.ValueID) MCValue {
        if (self.tracking.get(value_id)) |tracking| {
            return tracking.current;
        }
        return .none;
    }

    /// Ensure a value is in a register (reload if spilled)
    pub fn ensureInReg(self: *CodeGen, value_id: ssa.ValueID) !x86.Reg {
        const tracking = self.tracking.getPtr(value_id) orelse return error.ValueNotTracked;

        // Already in a register?
        if (tracking.current.getReg()) |reg| {
            return reg;
        }

        // Need to reload from home
        const reg = try self.allocReg(value_id);

        switch (tracking.current) {
            .stack => |offset| {
                try x86.movRegMem(self.buf, reg, .rbp, offset);
            },
            .immediate => |imm| {
                try x86.movRegImm64(self.buf, reg, imm);
            },
            else => return error.CannotReload,
        }

        tracking.current = .{ .register = reg };
        return reg;
    }

    /// Load a value into a specific register
    pub fn loadToReg(self: *CodeGen, dest: x86.Reg, mcv: MCValue) !void {
        switch (mcv) {
            .register => |src| {
                if (src != dest) {
                    try x86.movRegReg(self.buf, dest, src);
                }
            },
            .stack => |offset| {
                try x86.movRegMem(self.buf, dest, .rbp, offset);
            },
            .immediate => |imm| {
                try x86.movRegImm64(self.buf, dest, imm);
            },
            .lea_symbol => |sym| {
                try x86.leaRipSymbol(self.buf, dest, sym.name);
            },
            .none, .dead => {},
        }
    }

    /// Mark a value as dead (free its register if any)
    pub fn markDead(self: *CodeGen, value_id: ssa.ValueID) void {
        if (self.tracking.getPtr(value_id)) |tracking| {
            if (tracking.current.getReg()) |reg| {
                self.reg_manager.markFree(reg);
            }
            tracking.current = .dead;
        }
    }

    /// Set the result location for a value
    pub fn setResult(self: *CodeGen, value_id: ssa.ValueID, result: MCValue) !void {
        try self.tracking.put(value_id, InstTracking.init(result));
    }

    // ========================================================================
    // Function call handling
    // ========================================================================

    /// Spill caller-saved registers before a function call.
    /// If liveness info is available, only spills values that are used after this point.
    pub fn spillCallerSaved(self: *CodeGen) !void {
        // Caller-saved registers that might be in use
        const caller_saved = [_]x86.Reg{ .rax, .rcx, .rdx, .rsi, .rdi, .r8, .r9 };

        for (caller_saved) |reg| {
            if (self.reg_manager.isFree(reg)) continue;

            // Get the value ID in this register
            const vid = if (RegisterManager.indexOf(reg)) |idx|
                self.reg_manager.registers[idx]
            else
                null;

            // Skip spilling const_slice - they can be regenerated
            if (vid) |value_id| {
                if (value_id < self.func.values.items.len) {
                    const val = &self.func.values.items[value_id];
                    if (val.op == .const_slice or val.op == .const_int or val.op == .const_bool) {
                        // Constants can be regenerated, just free the register
                        self.reg_manager.markFree(reg);
                        continue;
                    }
                }
            }

            // Check if we should skip spilling this value
            if (self.liveness_info) |lv| {
                if (vid) |value_id| {
                    // If value is not used after this instruction, just free the register
                    if (!lv.isUsedAfter(value_id, self.current_inst)) {
                        self.reg_manager.markFree(reg);
                        continue;
                    }
                }
            }

            // Value is live after call - must spill
            try self.spillReg(reg);
        }
    }

    /// Check if an operand dies at this instruction AND is currently in a register.
    /// Returns true if we can freely clobber the register without saving.
    fn operandDiesInReg(self: *CodeGen, value_id: ssa.ValueID, operand_idx: u8, arg_id: ssa.ValueID) bool {
        if (self.liveness_info) |lv| {
            if (lv.operandDies(value_id, operand_idx)) {
                const mcv = self.getValue(arg_id);
                return mcv == .register;
            }
        }
        return false;
    }

    /// Free registers for operands that die at this instruction.
    /// Call this AFTER an operation completes to release dead values.
    fn freeDeadOperands(self: *CodeGen, value: *ssa.Value) void {
        if (self.liveness_info) |lv| {
            const args = value.args();
            for (args, 0..) |arg_id, i| {
                if (arg_id == ssa.null_value) continue;
                if (lv.operandDies(value.id, @intCast(i))) {
                    if (self.tracking.getPtr(arg_id)) |tracking| {
                        if (tracking.current.getReg()) |reg| {
                            self.reg_manager.markFree(reg);
                        }
                        tracking.current = .dead;
                    }
                }
            }
        }
    }

    // ========================================================================
    // Code generation for specific operations
    // ========================================================================

    /// Generate code for a constant integer
    pub fn genConstInt(self: *CodeGen, value: *ssa.Value) !void {
        // Small constants can stay as immediates
        const imm = value.aux_int;
        if (imm >= std.math.minInt(i32) and imm <= std.math.maxInt(i32)) {
            try self.setResult(value.id, .{ .immediate = imm });
        } else {
            // Large constant needs a register
            const reg = try self.allocReg(value.id);
            try x86.movRegImm64(self.buf, reg, imm);
            try self.setResult(value.id, .{ .register = reg });
        }
    }

    /// Generate code for a constant slice (string literal)
    pub fn genConstSlice(self: *CodeGen, value: *ssa.Value) !void {
        // const_slice: aux_int = string index in string_infos
        // Result is a slice (ptr, len) in rax/rdx (x86_64 two-value return convention)
        const string_idx: usize = @intCast(value.aux_int);

        // Spill rax and rdx if they contain other values (to avoid clobbering)
        try self.spillReg(.rax);
        try self.spillReg(.rdx);

        if (string_idx >= self.string_infos.len) {
            // Invalid string index - emit null slice
            try x86.movRegImm64(self.buf, .rax, 0);
            try x86.movRegImm64(self.buf, .rdx, 0);
            self.reg_manager.markUsed(.rax, value.id);
            try self.setResult(value.id, .{ .register = .rax });
            return;
        }

        const info = self.string_infos[string_idx];

        // Load string address into rax using LEA [rip + symbol]
        try x86.leaRipSymbol(self.buf, .rax, info.symbol_name);

        // Load length into rdx
        try x86.movRegImm64(self.buf, .rdx, @intCast(info.len));

        // Result is a fat pointer: rax = ptr, rdx = len
        self.reg_manager.markUsed(.rax, value.id);
        try self.setResult(value.id, .{ .register = .rax });
    }

    /// Generate code for an add operation
    /// Result always in rax (matches genStore expectation)
    pub fn genAdd(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();

        // Spill rax if it contains a live value that's NOT one of our operands.
        if (!self.reg_manager.isFree(.rax)) {
            const rax_value = self.reg_manager.getValueIn(.rax);
            if (rax_value != null and rax_value.? != args[0] and rax_value.? != args[1]) {
                // Check if value in rax is actually live
                if (self.liveness_info) |lv| {
                    if (lv.isUsedAfter(rax_value.?, self.current_inst)) {
                        try self.spillReg(.rax);
                    } else {
                        self.reg_manager.markFree(.rax);
                    }
                } else {
                    try self.spillReg(.rax);
                }
            }
        }

        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        // If right is in rax, we MUST save it before loading left into rax,
        // otherwise loading left will clobber right before we can use it.
        if (right_mcv == .register and right_mcv.register == .rax) {
            try x86.movRegReg(self.buf, scratch0, .rax);
            try self.loadToReg(.rax, left_mcv);
            try x86.addRegReg(self.buf, .rax, scratch0);
        } else {
            // Load left operand into rax
            try self.loadToReg(.rax, left_mcv);

            // Add right operand
            switch (right_mcv) {
                .register => |src| {
                    try x86.addRegReg(self.buf, .rax, src);
                },
                .immediate => |imm| {
                    if (imm >= std.math.minInt(i32) and imm <= std.math.maxInt(i32)) {
                        try x86.addRegImm32(self.buf, .rax, @intCast(imm));
                    } else {
                        try x86.movRegImm64(self.buf, scratch0, imm);
                        try x86.addRegReg(self.buf, .rax, scratch0);
                    }
                },
                .stack => |offset| {
                    try x86.movRegMem(self.buf, scratch0, .rbp, offset);
                    try x86.addRegReg(self.buf, .rax, scratch0);
                },
                else => {},
            }
        }

        self.freeDeadOperands(value);
        self.reg_manager.markUsed(.rax, value.id);
        try self.setResult(value.id, .{ .register = .rax });
    }

    /// Generate code for a subtract operation
    /// Result always in rax (matches genStore expectation)
    pub fn genSub(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();

        // Spill rax if it contains a live value that's NOT one of our operands
        if (!self.reg_manager.isFree(.rax)) {
            const rax_value = self.reg_manager.getValueIn(.rax);
            if (rax_value != null and rax_value.? != args[0] and rax_value.? != args[1]) {
                if (self.liveness_info) |lv| {
                    if (lv.isUsedAfter(rax_value.?, self.current_inst)) {
                        try self.spillReg(.rax);
                    } else {
                        self.reg_manager.markFree(.rax);
                    }
                } else {
                    try self.spillReg(.rax);
                }
            }
        }

        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        // If right is in rax, we MUST save it before loading left into rax
        if (right_mcv == .register and right_mcv.register == .rax) {
            try x86.movRegReg(self.buf, scratch0, .rax);
            try self.loadToReg(.rax, left_mcv);
            try x86.subRegReg(self.buf, .rax, scratch0);
        } else {
            try self.loadToReg(.rax, left_mcv);

            switch (right_mcv) {
                .register => |src| {
                    try x86.subRegReg(self.buf, .rax, src);
                },
                .immediate => |imm| {
                    if (imm >= std.math.minInt(i32) and imm <= std.math.maxInt(i32)) {
                        try x86.subRegImm32(self.buf, .rax, @intCast(imm));
                    } else {
                        try x86.movRegImm64(self.buf, scratch0, imm);
                        try x86.subRegReg(self.buf, .rax, scratch0);
                    }
                },
                .stack => |offset| {
                    try x86.movRegMem(self.buf, scratch0, .rbp, offset);
                    try x86.subRegReg(self.buf, .rax, scratch0);
                },
                else => {},
            }
        }

        self.freeDeadOperands(value);
        self.reg_manager.markUsed(.rax, value.id);
        try self.setResult(value.id, .{ .register = .rax });
    }

    /// Generate code for a multiply operation
    /// Result always in rax (matches genStore expectation)
    pub fn genMul(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();

        // Spill rax if it contains a live value that's NOT one of our operands
        if (!self.reg_manager.isFree(.rax)) {
            const rax_value = self.reg_manager.getValueIn(.rax);
            if (rax_value != null and rax_value.? != args[0] and rax_value.? != args[1]) {
                if (self.liveness_info) |lv| {
                    if (lv.isUsedAfter(rax_value.?, self.current_inst)) {
                        try self.spillReg(.rax);
                    } else {
                        self.reg_manager.markFree(.rax);
                    }
                } else {
                    try self.spillReg(.rax);
                }
            }
        }

        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        // If right is in rax, we MUST save it before loading left into rax
        if (right_mcv == .register and right_mcv.register == .rax) {
            try x86.movRegReg(self.buf, scratch0, .rax);
            try self.loadToReg(.rax, left_mcv);
            try x86.imulRegReg(self.buf, .rax, scratch0);
        } else {
            try self.loadToReg(.rax, left_mcv);

            switch (right_mcv) {
                .register => |src| {
                    try x86.imulRegReg(self.buf, .rax, src);
                },
                .stack => |offset| {
                    try x86.movRegMem(self.buf, scratch0, .rbp, offset);
                    try x86.imulRegReg(self.buf, .rax, scratch0);
                },
                .immediate => |imm| {
                    try x86.movRegImm64(self.buf, scratch0, imm);
                    try x86.imulRegReg(self.buf, .rax, scratch0);
                },
                else => {},
            }
        }

        self.freeDeadOperands(value);
        self.reg_manager.markUsed(.rax, value.id);
        try self.setResult(value.id, .{ .register = .rax });
    }

    /// Generate code for division
    /// x86_64 uses IDIV which divides RDX:RAX by operand, quotient in RAX
    pub fn genDiv(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        // Division uses rax for dividend and result
        // Lock rax and rdx since they're implicitly used
        self.reg_manager.lock(.rax);
        self.reg_manager.lock(.rdx);
        defer {
            self.reg_manager.unlock(.rax);
            self.reg_manager.unlock(.rdx);
        }

        // Make sure rax and rdx are free (spill only if live)
        if (!self.reg_manager.isFree(.rax)) {
            if (self.liveness_info) |lv| {
                if (self.reg_manager.getValueIn(.rax)) |vid| {
                    if (lv.isUsedAfter(vid, self.current_inst)) {
                        try self.spillReg(.rax);
                    } else {
                        self.reg_manager.markFree(.rax);
                    }
                }
            } else {
                try self.spillReg(.rax);
            }
        }
        if (!self.reg_manager.isFree(.rdx)) {
            if (self.liveness_info) |lv| {
                if (self.reg_manager.getValueIn(.rdx)) |vid| {
                    if (lv.isUsedAfter(vid, self.current_inst)) {
                        try self.spillReg(.rdx);
                    } else {
                        self.reg_manager.markFree(.rdx);
                    }
                }
            } else {
                try self.spillReg(.rdx);
            }
        }

        // Load dividend into rax
        try self.loadToReg(.rax, left_mcv);

        // Sign-extend rax into rdx:rax
        try x86.cqo(self.buf);

        // Load divisor into scratch register
        try self.loadToReg(scratch0, right_mcv);

        // IDIV: rax = rdx:rax / scratch0
        try x86.idivReg(self.buf, scratch0);

        self.freeDeadOperands(value);
        // Result is in rax - track it
        self.reg_manager.markUsed(.rax, value.id);
        try self.setResult(value.id, .{ .register = .rax });
    }

    /// Generate code for modulo
    /// Same as div but result is in RDX (remainder)
    pub fn genMod(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        // Lock rax and rdx
        self.reg_manager.lock(.rax);
        self.reg_manager.lock(.rdx);
        defer {
            self.reg_manager.unlock(.rax);
            self.reg_manager.unlock(.rdx);
        }

        // Make sure rax and rdx are free (spill only if live)
        if (!self.reg_manager.isFree(.rax)) {
            if (self.liveness_info) |lv| {
                if (self.reg_manager.getValueIn(.rax)) |vid| {
                    if (lv.isUsedAfter(vid, self.current_inst)) {
                        try self.spillReg(.rax);
                    } else {
                        self.reg_manager.markFree(.rax);
                    }
                }
            } else {
                try self.spillReg(.rax);
            }
        }
        if (!self.reg_manager.isFree(.rdx)) {
            if (self.liveness_info) |lv| {
                if (self.reg_manager.getValueIn(.rdx)) |vid| {
                    if (lv.isUsedAfter(vid, self.current_inst)) {
                        try self.spillReg(.rdx);
                    } else {
                        self.reg_manager.markFree(.rdx);
                    }
                }
            } else {
                try self.spillReg(.rdx);
            }
        }

        // Load dividend into rax
        try self.loadToReg(.rax, left_mcv);

        // Sign-extend rax into rdx:rax
        try x86.cqo(self.buf);

        // Load divisor into scratch register
        try self.loadToReg(scratch0, right_mcv);

        // IDIV: rdx = rdx:rax % scratch0
        try x86.idivReg(self.buf, scratch0);

        self.freeDeadOperands(value);
        // Result (remainder) is in rdx - track it
        self.reg_manager.markUsed(.rdx, value.id);
        try self.setResult(value.id, .{ .register = .rdx });
    }

    /// Generate code for negation
    pub fn genNeg(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        const src_mcv = self.getValue(args[0]);

        const dest = try self.allocReg(value.id);
        try self.loadToReg(dest, src_mcv);
        try x86.negReg(self.buf, dest);

        self.freeDeadOperands(value);
        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate code for a load from local variable
    pub fn genLoad(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const local_idx = args[0];
        if (local_idx >= self.func.locals.len) return;

        const local = self.func.locals[@intCast(local_idx)];
        const size = self.type_reg.sizeOf(value.type_idx);

        const dest = try self.allocReg(value.id);

        switch (size) {
            1 => {
                // Use sign-extending load for signed types (i8)
                if (self.type_reg.isSigned(value.type_idx)) {
                    try x86.movsxRegMem8(self.buf, dest, .rbp, local.offset);
                } else {
                    try x86.movzxRegMem8(self.buf, dest, .rbp, local.offset);
                }
            },
            else => try x86.movRegMem(self.buf, dest, .rbp, local.offset),
        }

        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate code for a store to local variable
    /// CRITICAL: Handle special 16-byte value types (slice, union, string)
    pub fn genStore(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        const local_idx = args[0];
        const src_id = args[1];
        if (local_idx >= self.func.locals.len) return;

        const local = self.func.locals[@intCast(local_idx)];
        const field_offset: i32 = @intCast(value.aux_int);
        const total_offset = local.offset + field_offset;

        const src_value = &self.func.values.items[src_id];

        // Check source op type for special 16-byte handling
        // These ops leave ptr in rax, len/payload in rdx
        if (src_value.op == .slice_local or src_value.op == .slice_value or
            src_value.op == .slice_make or src_value.op == .union_init or
            src_value.op == .const_slice or src_value.op == .str_concat)
        {
            // Store 16-byte value: ptr/tag at offset, len/payload at offset+8
            try x86.movMemReg(self.buf, .rbp, total_offset, .rax);
            try x86.movMemReg(self.buf, .rbp, total_offset + 8, .rdx);
            return;
        }

        // Standard value store
        const src_mcv = self.getValue(src_id);
        const size = self.type_reg.sizeOf(src_value.type_idx);
        // For ops that leave result in rax (call, field, slice_index, etc.)
        // NOTE: .index is NOT in this list because genIndex uses allocReg (not rax)
        const uses_rax = switch (src_value.op) {
            .add, .sub, .mul, .div, .call, .field, .slice_index,
            .union_payload, .map_new, .map_get, .map_has, .map_size,
            .list_new, .list_get, .list_len => true,
            else => false,
        };

        if (uses_rax) {
            switch (size) {
                1 => try x86.movMem8Reg(self.buf, .rbp, total_offset, .rax),
                else => try x86.movMemReg(self.buf, .rbp, total_offset, .rax),
            }
            return;
        }

        switch (src_mcv) {
            .register => |reg| {
                switch (size) {
                    1 => try x86.movMem8Reg(self.buf, .rbp, total_offset, reg),
                    else => try x86.movMemReg(self.buf, .rbp, total_offset, reg),
                }
            },
            .immediate => |imm| {
                try x86.movRegImm64(self.buf, scratch0, imm);
                switch (size) {
                    1 => try x86.movMem8Reg(self.buf, .rbp, total_offset, scratch0),
                    else => try x86.movMemReg(self.buf, .rbp, total_offset, scratch0),
                }
            },
            .stack => |offset| {
                try x86.movRegMem(self.buf, scratch0, .rbp, offset);
                switch (size) {
                    1 => try x86.movMem8Reg(self.buf, .rbp, total_offset, scratch0),
                    else => try x86.movMemReg(self.buf, .rbp, total_offset, scratch0),
                }
            },
            else => {},
        }
    }

    /// Generate code for a comparison operation
    pub fn genComparison(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();

        // Check if we're comparing slices (need runtime call)
        const left_val = &self.func.values.items[args[0]];
        const left_type = self.type_reg.get(left_val.type_idx);
        if (left_type == .slice) {
            try self.genSliceComparison(value);
            return;
        }

        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        // Load operands to scratch registers for comparison
        try self.loadToReg(scratch0, left_mcv);
        try self.loadToReg(scratch1, right_mcv);

        // Compare
        try x86.cmpRegReg(self.buf, scratch0, scratch1);

        // Allocate result register
        const dest = try self.allocReg(value.id);

        // Set result based on condition
        const cc: x86.CondCode = switch (value.op) {
            .eq => .e,
            .ne => .ne,
            .lt => .l,
            .le => .le,
            .gt => .g,
            .ge => .ge,
            else => unreachable,
        };
        try x86.setcc(self.buf, cc, dest);
        try x86.movzxReg8(self.buf, dest, dest);

        self.freeDeadOperands(value);
        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate slice/string comparison by calling cot_str_eq runtime function
    fn genSliceComparison(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();

        // Spill caller-saved registers
        try self.spillCallerSaved();

        // Load left slice (ptr, len) to rdi, rsi
        const left_val = &self.func.values.items[args[0]];
        try self.loadSliceToRegs(left_val, .rdi, .rsi);

        // Load right slice (ptr, len) to rdx, rcx
        const right_val = &self.func.values.items[args[1]];
        try self.loadSliceToRegs(right_val, .rdx, .rcx);

        // Call cot_str_eq(ptr1, len1, ptr2, len2) -> returns 1 if equal, 0 if not
        const func_name = if (self.os == .macos) "_cot_str_eq" else "cot_str_eq";
        try x86.callSymbol(self.buf, func_name);

        // Result is in rax (1 = equal, 0 = not equal)
        // For .ne, we need to invert: xor rax, 1
        if (value.op == .ne) {
            try x86.xorRegImm32(self.buf, .rax, 1);
        }

        self.reg_manager.markUsed(.rax, value.id);
        try self.setResult(value.id, .{ .register = .rax });
    }

    /// Load a slice value's (ptr, len) into two registers
    fn loadSliceToRegs(self: *CodeGen, val: *ssa.Value, ptr_reg: x86.Reg, len_reg: x86.Reg) !void {
        // Check if it's a const_slice (string literal)
        if (val.op == .const_slice) {
            // Regenerate the const_slice to get ptr and len
            const string_idx: usize = @intCast(val.aux_int);
            if (string_idx < self.string_infos.len) {
                const info = self.string_infos[string_idx];
                try x86.leaRipSymbol(self.buf, ptr_reg, info.symbol_name);
                try x86.movRegImm64(self.buf, len_reg, @intCast(info.len));
            } else {
                try x86.movRegImm64(self.buf, ptr_reg, 0);
                try x86.movRegImm64(self.buf, len_reg, 0);
            }
            return;
        }

        // Check if it's a str_concat result (stored on stack)
        if (val.op == .str_concat) {
            // Result was saved to stack after the call
            const mcv = self.getValue(val.id);
            if (mcv == .stack) {
                const offset = mcv.stack;
                try x86.movRegMem(self.buf, ptr_reg, .rbp, offset);
                try x86.movRegMem(self.buf, len_reg, .rbp, offset + 8);
                return;
            }
        }

        // Check if it's a load from a local (slice stored on stack)
        if (val.op == .load) {
            const val_args = val.args();
            if (val_args.len > 0 and val_args[0] < self.func.locals.len) {
                const local_idx: u32 = @intCast(val_args[0]);
                const local = self.func.locals[local_idx];
                // Slice on stack: ptr at offset, len at offset+8
                try x86.movRegMem(self.buf, ptr_reg, .rbp, local.offset);
                try x86.movRegMem(self.buf, len_reg, .rbp, local.offset + 8);
                return;
            }
        }

        // Fallback: try to get from tracking (may only have ptr)
        const mcv = self.getValue(val.id);
        switch (mcv) {
            .register => |reg| {
                if (reg != ptr_reg) {
                    try x86.movRegReg(self.buf, ptr_reg, reg);
                }
                // Assume len is 0 as fallback - this shouldn't happen for proper slices
                try x86.movRegImm64(self.buf, len_reg, 0);
            },
            .stack => |offset| {
                try x86.movRegMem(self.buf, ptr_reg, .rbp, offset);
                try x86.movRegMem(self.buf, len_reg, .rbp, offset + 8);
            },
            else => {
                try x86.movRegImm64(self.buf, ptr_reg, 0);
                try x86.movRegImm64(self.buf, len_reg, 0);
            },
        }
    }

    /// Generate code for field access: load from struct local + field offset
    /// CRITICAL: Two code paths!
    /// 1. args[0] < locals.len: Direct local field access
    /// 2. args[0] >= locals.len: SSA value reference (address in register from prior .addr)
    pub fn genField(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const maybe_local_or_ssa = args[0];
        const field_offset: i32 = @intCast(value.aux_int);
        const size = self.type_reg.sizeOf(value.type_idx);
        const dest = try self.allocReg(value.id);

        if (maybe_local_or_ssa < self.func.locals.len) {
            // CASE 1: Direct local field access
            const local = self.func.locals[@intCast(maybe_local_or_ssa)];
            const total_offset = local.offset + field_offset;

            switch (size) {
                1 => try x86.movzxRegMem8(self.buf, dest, .rbp, total_offset),
                else => try x86.movRegMem(self.buf, dest, .rbp, total_offset),
            }
        } else {
            // CASE 2: SSA value reference - address was computed by prior .addr op
            // The address should be in rax from the prior value
            switch (size) {
                1 => try x86.movzxRegMem8(self.buf, dest, .rax, field_offset),
                else => try x86.movRegMem(self.buf, dest, .rax, field_offset),
            }
        }

        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate code for logical NOT: XOR with 1 to flip boolean
    pub fn genNot(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        const src_mcv = self.getValue(args[0]);

        const dest = try self.allocReg(value.id);
        try self.loadToReg(dest, src_mcv);

        // XOR with 1 to flip the boolean
        try x86.xorRegImm32(self.buf, dest, 1);

        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate code for logical AND
    pub fn genAnd(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();

        // Allocate dest FIRST, then get MCValues (allocReg may spill operand regs)
        const dest = try self.allocReg(value.id);
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        try self.loadToReg(dest, left_mcv);
        try self.loadToReg(scratch1, right_mcv);
        try x86.andRegReg(self.buf, dest, scratch1);

        self.freeDeadOperands(value);
        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate code for logical OR
    pub fn genOr(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();

        // Allocate dest FIRST, then get MCValues (allocReg may spill operand regs)
        const dest = try self.allocReg(value.id);
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        try self.loadToReg(dest, left_mcv);
        try self.loadToReg(scratch1, right_mcv);
        try x86.orRegReg(self.buf, dest, scratch1);

        self.freeDeadOperands(value);
        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate code for conditional select: args[0]=cond, args[1]=true_val, args[2]=false_val
    pub fn genSelect(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 3) return;

        // Allocate dest FIRST, then get MCValues (allocReg may spill operand regs)
        const dest = try self.allocReg(value.id);
        const cond_mcv = self.getValue(args[0]);
        const true_mcv = self.getValue(args[1]);
        const false_mcv = self.getValue(args[2]);

        // Load false value as default
        try self.loadToReg(dest, false_mcv);

        // Load true value to scratch
        try self.loadToReg(scratch1, true_mcv);

        // Load and test condition
        try self.loadToReg(scratch0, cond_mcv);
        try x86.testRegReg(self.buf, scratch0, scratch0);

        // CMOVNE: if cond != 0, dest = true_val
        try x86.cmovneRegReg(self.buf, dest, scratch1);

        self.freeDeadOperands(value);
        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate code for array indexing: base + index * elem_size
    pub fn genIndex(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        const local_idx = args[0];
        if (local_idx >= self.func.locals.len) return;

        const local = self.func.locals[@intCast(local_idx)];
        const elem_size: i64 = if (value.aux_int != 0) value.aux_int else 8;

        // Allocate dest FIRST, then get MCValues (allocReg may spill operand regs)
        const dest = try self.allocReg(value.id);
        const idx_mcv = self.getValue(args[1]);

        // Load index into scratch0
        try self.loadToReg(scratch0, idx_mcv);

        // Calculate offset: index * elem_size
        if (elem_size > 1 and elem_size <= 0x7FFFFFFF) {
            try x86.imulRegRegImm(self.buf, scratch0, scratch0, @intCast(elem_size));
        }

        // Load base address (rbp + local.offset) into scratch1
        try x86.leaRegMem(self.buf, scratch1, .rbp, local.offset);

        // Add index offset to get final address
        try x86.addRegReg(self.buf, scratch0, scratch1);

        // Load value from [scratch0]
        try x86.movRegMem(self.buf, dest, scratch0, 0);

        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate code for address-of: LEA to get address of local
    pub fn genAddr(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const local_idx = args[0];
        if (local_idx >= self.func.locals.len) return;

        const local = self.func.locals[@intCast(local_idx)];
        const dest = try self.allocReg(value.id);

        // LEA dest, [rbp + offset]
        try x86.leaRegMem(self.buf, dest, .rbp, local.offset);

        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate code for ptr_load: load through a pointer
    /// args[0] = pointer SSA value
    pub fn genPtrLoad(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        // Get the pointer value
        const ptr_mcv = self.getValue(args[0]);

        // Load pointer into a register
        const ptr_reg = try self.allocReg(0xFFFF);
        try self.loadToReg(ptr_reg, ptr_mcv);

        // Load through the pointer
        const dest = try self.allocReg(value.id);
        const size = self.type_reg.sizeOf(value.type_idx);

        switch (size) {
            1 => {
                if (self.type_reg.isSigned(value.type_idx)) {
                    try x86.movsxRegMem8(self.buf, dest, ptr_reg, 0);
                } else {
                    try x86.movzxRegMem8(self.buf, dest, ptr_reg, 0);
                }
            },
            // For 16-bit and 32-bit, just use 64-bit load (upper bits cleared)
            else => try x86.movRegMem(self.buf, dest, ptr_reg, 0),
        }

        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate code for ptr_store: store through a pointer
    /// args[0] = pointer SSA value, args[1] = value to store
    pub fn genPtrStore(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        // Get the pointer value
        const ptr_mcv = self.getValue(args[0]);
        const val_mcv = self.getValue(args[1]);

        // Load pointer into a register
        const ptr_reg = try self.allocReg(0xFFFF);
        try self.loadToReg(ptr_reg, ptr_mcv);

        // Load value into a register
        const val_reg = try self.allocReg(0xFFFE);
        try self.loadToReg(val_reg, val_mcv);

        // Store through the pointer
        const size = self.type_reg.sizeOf(value.type_idx);

        switch (size) {
            1 => try x86.movMem8Reg(self.buf, ptr_reg, 0, val_reg),
            // For 16-bit and 32-bit, use 64-bit store
            else => try x86.movMemReg(self.buf, ptr_reg, 0, val_reg),
        }
    }

    /// Generate code for slice_make: create (ptr, len) pair
    pub fn genSliceMake(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 3) return;

        const local_idx = args[0];
        if (local_idx >= self.func.locals.len) return;

        const local = self.func.locals[@intCast(local_idx)];
        const elem_size: i64 = if (value.aux_int != 0) value.aux_int else 8;
        const local_size = local.size;

        const start_mcv = self.getValue(args[1]);
        const end_mcv = self.getValue(args[2]);

        // Check if source is a string/slice (16 bytes = ptr+len) or array (inline data)
        if (local_size == 16) {
            // String/slice: load the ptr from local into rax
            try x86.movRegMem(self.buf, .rax, .rbp, local.offset);
        } else {
            // Array: base address is the stack location itself
            try x86.leaRegMem(self.buf, .rax, .rbp, local.offset);
        }

        // Get start value into r9
        try self.loadToReg(.r9, start_mcv);

        // Calculate ptr = base + start * elem_size
        // r10 = start * elem_size
        if (elem_size > 1 and elem_size <= 0x7FFFFFFF) {
            try x86.imulRegRegImm(self.buf, .r10, .r9, @intCast(elem_size));
        } else {
            try x86.movRegReg(self.buf, .r10, .r9);
        }
        // rax = rax + r10
        try x86.addRegReg(self.buf, .rax, .r10);

        // Get end value and calculate len = end - start into rdx
        try self.loadToReg(.rdx, end_mcv);
        // rdx = end - start
        try x86.subRegReg(self.buf, .rdx, .r9);

        // Result is in rax (ptr) and rdx (len)
        self.reg_manager.markUsed(.rax, value.id);
        try self.setResult(value.id, .{ .register = .rax });
    }

    /// Generate code for slice_index: index into slice (ptr, len) pair
    /// CRITICAL: Handle byte-size loads for string indexing (elem_size == 1)
    pub fn genSliceIndex(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        const local_idx = args[0];
        if (local_idx >= self.func.locals.len) return;

        const local = self.func.locals[@intCast(local_idx)];
        const elem_size: i64 = if (value.aux_int != 0) value.aux_int else 8;

        // Get index MCValue FIRST (before any potential spills from loadToReg)
        const idx_mcv = self.getValue(args[1]);

        // Load slice ptr (first 8 bytes at local.offset) into rax
        try x86.movRegMem(self.buf, .rax, .rbp, local.offset);

        // Load index value into r9 using MCValue tracking
        try self.loadToReg(.r9, idx_mcv);

        // Calculate offset: index * elem_size
        if (elem_size > 1 and elem_size <= 0x7FFFFFFF) {
            try x86.imulRegRegImm(self.buf, .r9, .r9, @intCast(elem_size));
        }

        // Add to get final address: rax = rax + r9
        try x86.addRegReg(self.buf, .rax, .r9);

        // Load value based on element size
        if (elem_size == 1) {
            // Byte load: movzx rax, byte [rax]
            try x86.movzxRegMem8(self.buf, .rax, .rax, 0);
        } else {
            // 64-bit load: mov rax, [rax]
            try x86.movRegMem(self.buf, .rax, .rax, 0);
        }

        // Result in rax
        self.reg_manager.markUsed(.rax, value.id);
        try self.setResult(value.id, .{ .register = .rax });
    }

    /// Generate code for union_tag: load tag from union (first 8 bytes)
    /// CRITICAL: args[0] can be a local index OR an SSA value reference
    pub fn genUnionTag(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const maybe_local_or_ssa = args[0];

        // If args[0] is a load op, get the local index from it
        if (maybe_local_or_ssa < self.func.values.items.len) {
            const union_val = &self.func.values.items[maybe_local_or_ssa];
            if (union_val.op == .load) {
                // The load's local index is in args[0], not aux_int
                const load_args = union_val.args();
                if (load_args.len == 0) return;
                const local_idx: usize = @intCast(load_args[0]);
                if (local_idx < self.func.locals.len) {
                    const local = self.func.locals[local_idx];
                    // Load tag into rax (use fixed register for simpler tracking)
                    try x86.movRegMem(self.buf, .rax, .rbp, local.offset);
                    self.reg_manager.markUsed(.rax, value.id);
                    try self.setResult(value.id, .{ .register = .rax });
                    return;
                }
            }
        }

        // Fallback: treat as direct local index (legacy behavior)
        if (maybe_local_or_ssa < self.func.locals.len) {
            const local = self.func.locals[@intCast(maybe_local_or_ssa)];
            try x86.movRegMem(self.buf, .rax, .rbp, local.offset);
            self.reg_manager.markUsed(.rax, value.id);
            try self.setResult(value.id, .{ .register = .rax });
        }
    }

    /// Generate code for union_payload: load payload from union (at offset 8)
    /// CRITICAL: args[0] can be a local index OR an SSA value reference
    pub fn genUnionPayload(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const maybe_local_or_ssa = args[0];

        // If args[0] is a load op, get the local index from it
        if (maybe_local_or_ssa < self.func.values.items.len) {
            const union_val = &self.func.values.items[maybe_local_or_ssa];
            if (union_val.op == .load) {
                // The load's local index is in args[0], not aux_int
                const load_args = union_val.args();
                if (load_args.len == 0) return;
                const local_idx: usize = @intCast(load_args[0]);
                if (local_idx < self.func.locals.len) {
                    const local = self.func.locals[local_idx];
                    // Load payload from local.offset + 8 into rax
                    try x86.movRegMem(self.buf, .rax, .rbp, local.offset + 8);
                    self.reg_manager.markUsed(.rax, value.id);
                    try self.setResult(value.id, .{ .register = .rax });
                    return;
                }
            }
        }

        // Fallback: treat as direct local index (legacy behavior)
        if (maybe_local_or_ssa < self.func.locals.len) {
            const local = self.func.locals[@intCast(maybe_local_or_ssa)];
            try x86.movRegMem(self.buf, .rax, .rbp, local.offset + 8);
            self.reg_manager.markUsed(.rax, value.id);
            try self.setResult(value.id, .{ .register = .rax });
        }
    }

    /// Generate code for union_init: create tagged union value
    /// aux_int = variant index (tag), args[0] = payload value (if any)
    /// Result: rax = tag, rdx = payload (for 16-byte store)
    pub fn genUnionInit(self: *CodeGen, value: *ssa.Value) !void {
        const variant_idx: i64 = value.aux_int;
        const args = value.args();

        // If there's a payload, check if it comes from a computation (in rax)
        if (args.len > 0) {
            const payload_val = &self.func.values.items[args[0]];
            if (payload_val.op == .const_int) {
                // Payload is constant - load tag first, then payload
                try x86.movRegImm64(self.buf, .rax, variant_idx);
                try x86.movRegImm64(self.buf, .rdx, payload_val.aux_int);
            } else {
                // Payload comes from computation (in rax) - save it, load tag, swap
                try x86.movRegReg(self.buf, .rdx, .rax); // save payload to rdx
                try x86.movRegImm64(self.buf, .rax, variant_idx); // load tag to rax
            }
        } else {
            // No payload - just set tag
            try x86.movRegImm64(self.buf, .rax, variant_idx);
            try x86.xorRegReg(self.buf, .rdx, .rdx); // zero payload
        }

        // Result: rax = tag, rdx = payload
        self.reg_manager.markUsed(.rax, value.id);
        try self.setResult(value.id, .{ .register = .rax });
    }

    /// Generate code for list_get: runtime call cot_list_get(handle, index)
    /// Uses inline op type lookup (archive pattern) for reliable operand loading
    pub fn genListGet(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        try self.spillCallerSaved();

        // Load handle into rdi via MCValue
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.rdi, handle_mcv);

        // Load index into rsi via MCValue
        const idx_mcv = self.getValue(args[1]);
        try self.loadToReg(.rsi, idx_mcv);

        try self.emitRuntimeCall("cot_list_get");

        // Result in rax
        self.reg_manager.markUsed(.rax, value.id);
        try self.setResult(value.id, .{ .register = .rax });
    }

    /// Generate code for map_get: args[0]=handle, args[1]=key
    /// x86_64 calling convention: rdi=handle, rsi=key_ptr, rdx=key_len
    pub fn genMapGet(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        // Spill caller-saved registers
        try self.spillCallerSaved();

        // Load key FIRST to avoid clobbering
        const key_val = &self.func.values.items[args[1]];
        const key_type = self.type_reg.get(key_val.type_idx);
        if (key_type == .slice) {
            // String key: load directly based on op type
            if (key_val.op == .const_slice) {
                // Regenerate const_slice into rsi/rdx
                const string_idx: usize = @intCast(key_val.aux_int);
                if (string_idx < self.string_infos.len) {
                    const info = self.string_infos[string_idx];
                    try x86.leaRipSymbol(self.buf, .rsi, info.symbol_name);
                    try x86.movRegImm64(self.buf, .rdx, @intCast(info.len));
                }
            } else {
                // Load slice from stack: ptr to rsi, len to rdx
                const key_val_args = key_val.args();
                if (key_val_args.len > 0 and key_val_args[0] < self.func.locals.len) {
                    const local_idx: u32 = @intCast(key_val_args[0]);
                    const local = self.func.locals[local_idx];
                    try x86.movRegMem(self.buf, .rsi, .rbp, local.offset);
                    try x86.movRegMem(self.buf, .rdx, .rbp, local.offset + 8);
                }
            }
        } else {
            const key_mcv = self.getValue(args[1]);
            try self.loadToReg(.rsi, key_mcv);
        }

        // Load handle LAST to avoid clobber
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.rdi, handle_mcv);

        try self.emitRuntimeCall("cot_map_get");

        self.reg_manager.markUsed(.rax, value.id);
        try self.setResult(value.id, .{ .register = .rax });
    }

    fn emitRuntimeCall(self: *CodeGen, name: []const u8) !void {
        const sym_name = if (self.os == .macos)
            try std.fmt.allocPrint(self.allocator, "_{s}", .{name})
        else
            name;
        try x86.callSymbol(self.buf, sym_name);
    }

    /// Generate code for arg: load function parameter from local slot
    /// Parameters are spilled to local slots in the prologue
    pub fn genArg(self: *CodeGen, value: *ssa.Value) !void {
        const param_idx: u32 = @intCast(value.aux_int);
        if (param_idx >= self.func.locals.len) return;

        const local = self.func.locals[param_idx];
        const dest = try self.allocReg(value.id);

        // Load from the parameter's local slot
        try x86.movRegMem(self.buf, dest, .rbp, local.offset);

        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate code for map_new: create new map via runtime call
    pub fn genMapNew(self: *CodeGen, value: *ssa.Value) !void {
        try self.spillCallerSaved();
        try self.emitRuntimeCall("cot_map_new");
        self.reg_manager.markUsed(.rax, value.id);
        try self.setResult(value.id, .{ .register = .rax });
    }

    /// Generate code for map_set: args[0]=handle, args[1]=key, args[2]=value
    /// x86_64 calling convention: rdi=handle, rsi=key_ptr, rdx=key_len, rcx=value
    pub fn genMapSet(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 3) return;

        try self.spillCallerSaved();

        // Load key FIRST to avoid clobbering
        const key_val = &self.func.values.items[args[1]];
        const key_type = self.type_reg.get(key_val.type_idx);
        if (key_type == .slice) {
            // String key: load directly based on op type
            if (key_val.op == .const_slice) {
                // Regenerate const_slice into rsi/rdx
                const string_idx: usize = @intCast(key_val.aux_int);
                if (string_idx < self.string_infos.len) {
                    const info = self.string_infos[string_idx];
                    try x86.leaRipSymbol(self.buf, .rsi, info.symbol_name);
                    try x86.movRegImm64(self.buf, .rdx, @intCast(info.len));
                }
            } else {
                // Load slice from stack: ptr to rsi, len to rdx
                const key_val_args = key_val.args();
                if (key_val_args.len > 0 and key_val_args[0] < self.func.locals.len) {
                    const local_idx: u32 = @intCast(key_val_args[0]);
                    const local = self.func.locals[local_idx];
                    try x86.movRegMem(self.buf, .rsi, .rbp, local.offset);
                    try x86.movRegMem(self.buf, .rdx, .rbp, local.offset + 8);
                }
            }
        } else {
            const key_mcv = self.getValue(args[1]);
            try self.loadToReg(.rsi, key_mcv);
        }

        // Load value into rcx (4th arg for string key case)
        // For string keys: args = [handle, key_ptr, key_len, value]
        // For int keys: args = [handle, key, key, value] (key repeated for uniformity)
        const val_arg_idx: usize = if (args.len >= 4) 3 else 2;
        const val_mcv = self.getValue(args[val_arg_idx]);
        try self.loadToReg(.rcx, val_mcv);

        // Load handle LAST to avoid clobber
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.rdi, handle_mcv);

        try self.emitRuntimeCall("cot_map_set");
    }

    /// Generate code for map_has: args[0]=handle, args[1]=key
    /// x86_64 calling convention: rdi=handle, rsi=key_ptr, rdx=key_len
    pub fn genMapHas(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        try self.spillCallerSaved();

        // Load key FIRST to avoid clobbering handle
        const key_val = &self.func.values.items[args[1]];
        const key_type = self.type_reg.get(key_val.type_idx);
        if (key_type == .slice) {
            // String key: load directly based on op type
            if (key_val.op == .const_slice) {
                // Regenerate const_slice into rsi/rdx
                const string_idx: usize = @intCast(key_val.aux_int);
                if (string_idx < self.string_infos.len) {
                    const info = self.string_infos[string_idx];
                    try x86.leaRipSymbol(self.buf, .rsi, info.symbol_name);
                    try x86.movRegImm64(self.buf, .rdx, @intCast(info.len));
                }
            } else {
                // Load slice from stack: ptr to rsi, len to rdx
                const key_val_args = key_val.args();
                if (key_val_args.len > 0 and key_val_args[0] < self.func.locals.len) {
                    const local_idx: u32 = @intCast(key_val_args[0]);
                    const local = self.func.locals[local_idx];
                    try x86.movRegMem(self.buf, .rsi, .rbp, local.offset);
                    try x86.movRegMem(self.buf, .rdx, .rbp, local.offset + 8);
                }
            }
        } else {
            const key_mcv = self.getValue(args[1]);
            try self.loadToReg(.rsi, key_mcv);
        }

        // Load handle LAST to avoid clobber
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.rdi, handle_mcv);

        try self.emitRuntimeCall("cot_map_has");
        self.reg_manager.markUsed(.rax, value.id);
        try self.setResult(value.id, .{ .register = .rax });
    }

    /// Generate code for map_size: args[0]=handle
    pub fn genMapSize(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        try self.spillCallerSaved();

        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.rdi, handle_mcv);

        try self.emitRuntimeCall("cot_map_size");
        self.reg_manager.markUsed(.rax, value.id);
        try self.setResult(value.id, .{ .register = .rax });
    }

    /// Generate code for map_free: args[0]=handle
    pub fn genMapFree(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        try self.spillCallerSaved();

        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.rdi, handle_mcv);

        try self.emitRuntimeCall("cot_map_free");
    }

    /// Generate code for list_new: call cot_list_new(elem_size) runtime function
    pub fn genListNew(self: *CodeGen, value: *ssa.Value) !void {
        try self.spillCallerSaved();

        // Get element size from list type
        var elem_size: i64 = 8; // default to 8 bytes
        const list_type = self.type_reg.get(value.type_idx);
        if (list_type == .list_type) {
            elem_size = @intCast(self.type_reg.sizeOf(list_type.list_type.elem));
        }

        // Pass elem_size in rdi (first argument)
        try x86.movRegImm64(self.buf, .rdi, elem_size);
        try self.emitRuntimeCall("cot_list_new");

        // rax now has list handle
        self.reg_manager.markUsed(.rax, value.id);
        try self.setResult(value.id, .{ .register = .rax });
    }

    /// Generate code for list_push: args[0]=handle, args[1]=value
    /// Uses MCValue for all operands
    pub fn genListPush(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        try self.spillCallerSaved();

        // Load handle into rdi via MCValue
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.rdi, handle_mcv);

        // Load value into rsi via MCValue
        const val_mcv = self.getValue(args[1]);
        try self.loadToReg(.rsi, val_mcv);

        try self.emitRuntimeCall("cot_list_push");
    }

    /// Generate code for list_set: args[0]=handle, args[1]=index, args[2]=value
    /// Uses MCValue for all operands
    /// x86_64 calling convention: rdi=handle, rsi=index, rdx=value
    pub fn genListSet(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 3) return;

        try self.spillCallerSaved();

        // Load handle into rdi via MCValue
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.rdi, handle_mcv);

        // Load index into rsi via MCValue
        const index_mcv = self.getValue(args[1]);
        try self.loadToReg(.rsi, index_mcv);

        // Load value into rdx via MCValue
        const val_mcv = self.getValue(args[2]);
        try self.loadToReg(.rdx, val_mcv);

        try self.emitRuntimeCall("cot_list_set");
    }

    /// Generate code for list_len: args[0]=handle
    pub fn genListLen(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        try self.spillCallerSaved();

        // Load handle into rdi via MCValue
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.rdi, handle_mcv);

        try self.emitRuntimeCall("cot_list_len");

        self.reg_manager.markUsed(.rax, value.id);
        try self.setResult(value.id, .{ .register = .rax });
    }

    /// Generate code for list_free: args[0]=handle
    pub fn genListFree(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        try self.spillCallerSaved();

        // Load handle into rdi via MCValue
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.rdi, handle_mcv);

        try self.emitRuntimeCall("cot_list_free");
    }

    /// Generate code for str_concat: args[0]=left string, args[1]=right string
    /// Calls cot_str_concat(ptr1, len1, ptr2, len2) -> returns (ptr, len) in rax, rdx
    pub fn genStrConcat(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        // Spill caller-saved registers
        try self.spillCallerSaved();

        // Load left string (ptr, len) to rdi, rsi
        const left_val = &self.func.values.items[args[0]];
        try self.loadSliceToRegs(left_val, .rdi, .rsi);

        // Load right string (ptr, len) to rdx, rcx
        const right_val = &self.func.values.items[args[1]];
        try self.loadSliceToRegs(right_val, .rdx, .rcx);

        // Call cot_str_concat(ptr1, len1, ptr2, len2)
        const func_name = if (self.os == .macos) "_cot_str_concat" else "cot_str_concat";
        try x86.callSymbol(self.buf, func_name);

        // Result is in rax (ptr), rdx (len) - it's a slice
        // Save to a temp slot so other ops don't clobber it
        const temp_offset = self.next_spill_offset;
        self.next_spill_offset -= 16; // 16 bytes for ptr+len
        try x86.movMemReg(self.buf, .rbp, temp_offset, .rax);
        try x86.movMemReg(self.buf, .rbp, temp_offset + 8, .rdx);

        // Track result as stack location
        try self.setResult(value.id, .{ .stack = temp_offset });
    }

    /// Generate code for alloc: allocate space on stack (returns address)
    /// aux_int = size to allocate, or uses local slot
    pub fn genAlloc(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        const dest = try self.allocReg(value.id);

        if (args.len > 0) {
            // args[0] is local index to get address of
            const local_idx = args[0];
            if (local_idx < self.func.locals.len) {
                const local = self.func.locals[@intCast(local_idx)];
                try x86.leaRegMem(self.buf, dest, .rbp, local.offset);
            }
        } else {
            // aux_int might specify size, allocate on stack
            // For now, just return current stack pointer as address
            try x86.movRegReg(self.buf, dest, .rsp);
        }

        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate code for ptr_field: load through pointer + field offset
    /// args[0] = local holding pointer, aux_int = field offset
    pub fn genPtrField(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const local_idx = args[0];
        if (local_idx >= self.func.locals.len) return;

        const local = self.func.locals[@intCast(local_idx)];
        const field_offset: i32 = @intCast(value.aux_int);

        const dest = try self.allocReg(value.id);

        // Load pointer from local
        try x86.movRegMem(self.buf, scratch0, .rbp, local.offset);

        // Load from ptr + field_offset
        try x86.movRegMem(self.buf, dest, scratch0, field_offset);

        try self.setResult(value.id, .{ .register = dest });
    }

    pub fn genPtrFieldStore(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        const local_idx = args[0];
        if (local_idx >= self.func.locals.len) return;

        const local = self.func.locals[@intCast(local_idx)];
        const field_offset: i32 = @intCast(value.aux_int);

        // Load pointer from local
        try x86.movRegMem(self.buf, scratch0, .rbp, local.offset);

        // Load the value to store
        const val_mcv = self.getValue(args[1]);
        try self.loadToReg(scratch1, val_mcv);

        // Store value at ptr + field_offset
        const size = self.type_reg.sizeOf(value.type_idx);
        if (size == 1) {
            try x86.movMem8Reg(self.buf, scratch0, field_offset, scratch1);
        } else {
            // Use 64-bit store for sizes >= 2
            try x86.movMemReg(self.buf, scratch0, field_offset, scratch1);
        }
    }

    /// Generate code for a function call (x86_64 SysV ABI)
    ///
    /// Return handling follows Go/Zig patterns:
    /// - ≤8 bytes: returned in rax (single_reg)
    /// - 9-16 bytes: returned in rax+rdx (double_reg) - handled by genStore
    /// - >16 bytes: hidden pointer in rdi, callee writes to it (by_pointer/sret)
    pub fn genCall(self: *CodeGen, value: *ssa.Value) !void {
        // Spill caller-saved registers
        try self.spillCallerSaved();

        // Classify return type using x86_64 SysV ABI rules
        const ret_class = classifyType(self.type_reg, value.type_idx);

        // x86_64 SysV ABI: rdi, rsi, rdx, rcx, r8, r9 for arguments
        const arg_regs = [_]x86.Reg{ .rdi, .rsi, .rdx, .rcx, .r8, .r9 };
        const args = value.args();

        // For sret (>16 byte returns), we need to:
        // 1. Allocate stack space for the result
        // 2. Pass pointer to that space in rdi (hidden first parameter)
        // 3. Shift all actual arguments right by 1 register
        var result_offset: i32 = 0;
        var reg_idx: usize = 0;

        if (ret_class == .by_pointer) {
            // Allocate stack space for large struct result
            // Use a fixed location relative to frame size to avoid dynamic allocation issues
            const ret_size = self.type_reg.sizeOf(value.type_idx);
            result_offset = self.next_spill_offset;
            self.next_spill_offset -= @intCast(alignTo(ret_size, 8));
            // Load effective address of result space into rdi (hidden pointer)
            try x86.leaRegMem(self.buf, .rdi, .rbp, result_offset);
            // All other arguments shift right by 1
            reg_idx = 1;
        }

        // Load arguments into registers
        for (args) |arg_id| {
            if (reg_idx >= arg_regs.len) break;

            const arg_val = &self.func.values.items[arg_id];
            const arg_type = self.type_reg.get(arg_val.type_idx);

            if (arg_type == .slice) {
                // Slice argument: pass ptr in reg[i], len in reg[i+1]
                if (reg_idx + 1 >= arg_regs.len) break;
                try self.loadSliceToRegs(arg_val, arg_regs[reg_idx], arg_regs[reg_idx + 1]);
                reg_idx += 2;
            } else {
                // Scalar argument
                const arg_mcv = self.getValue(arg_id);
                try self.loadToReg(arg_regs[reg_idx], arg_mcv);
                reg_idx += 1;
            }
        }

        // Call the function
        const sym_name = if (self.os == .macos)
            try std.fmt.allocPrint(self.allocator, "_{s}", .{value.aux_str})
        else
            value.aux_str;
        try x86.callSymbol(self.buf, sym_name);

        // Handle result based on ABI class
        switch (ret_class) {
            .by_pointer => {
                // sret: result was written to stack space via hidden pointer
                // rax contains the pointer (same as what we passed)
                try self.setResult(value.id, .{ .stack = result_offset });
            },
            .double_reg, .slice => {
                // 16-byte struct or slice returned in rax+rdx
                // Mark rax as containing the result - genStore handles the full 16-byte copy
                self.reg_manager.markUsed(.rax, value.id);
                try self.setResult(value.id, .{ .register = .rax });
            },
            .single_reg => {
                // Small return in rax
                self.reg_manager.markUsed(.rax, value.id);
                try self.setResult(value.id, .{ .register = .rax });
            },
        }
    }

    /// Generate code for return (x86_64 SysV ABI)
    ///
    /// Return handling based on Go/Zig patterns:
    /// - ≤8 bytes: return in rax (single_reg)
    /// - 9-16 bytes: return in rax+rdx (double_reg)
    /// - >16 bytes: copy to hidden pointer location, return pointer in rax (by_pointer/sret)
    pub fn genReturn(self: *CodeGen, block: *ssa.Block) !void {
        if (block.control != ssa.null_value) {
            const ret_val = &self.func.values.items[block.control];
            const ret_class = classifyType(self.type_reg, ret_val.type_idx);
            const ret_mcv = self.getValue(block.control);

            switch (ret_class) {
                .by_pointer => {
                    // sret: copy struct to hidden pointer location, return pointer in rax
                    // Hidden pointer was saved to sret_offset in genPrologue
                    if (ret_mcv == .stack) {
                        const ret_size = self.type_reg.sizeOf(ret_val.type_idx);
                        // Load the hidden pointer
                        try x86.movRegMem(self.buf, .rdi, .rbp, self.sret_offset);

                        // Copy ret_size bytes from source to destination (8-byte chunks)
                        var offset: i32 = 0;
                        while (offset < @as(i32, @intCast(ret_size))) : (offset += 8) {
                            try x86.movRegMem(self.buf, .rax, .rbp, ret_mcv.stack + offset);
                            try x86.movMemReg(self.buf, .rdi, offset, .rax);
                        }

                        // Return the pointer in rax (x86_64 SysV requires this)
                        try x86.movRegMem(self.buf, .rax, .rbp, self.sret_offset);
                    } else {
                        try self.loadToReg(.rax, ret_mcv);
                    }
                },
                .double_reg => {
                    // 16-byte struct: return in rax+rdx
                    if (ret_mcv == .stack) {
                        try x86.movRegMem(self.buf, .rax, .rbp, ret_mcv.stack);
                        try x86.movRegMem(self.buf, .rdx, .rbp, ret_mcv.stack + 8);
                    } else {
                        try self.loadToReg(.rax, ret_mcv);
                    }
                },
                .slice => {
                    // Slice: ptr in rax, len in rdx
                    if (ret_mcv == .stack) {
                        try x86.movRegMem(self.buf, .rax, .rbp, ret_mcv.stack);
                        try x86.movRegMem(self.buf, .rdx, .rbp, ret_mcv.stack + 8);
                    } else {
                        try self.loadToReg(.rax, ret_mcv);
                    }
                },
                .single_reg => {
                    try self.loadToReg(.rax, ret_mcv);
                },
            }
        }

        // Epilogue
        try x86.movRegReg(self.buf, .rsp, .rbp);
        try x86.popReg(self.buf, .rbp);
        try x86.ret(self.buf);
    }

    // ========================================================================
    // Main generation entry point
    // ========================================================================

    /// Generate code for a single SSA value
    pub fn genValue(self: *CodeGen, value: *ssa.Value) !void {
        switch (value.op) {
            .const_int => try self.genConstInt(value),
            .const_bool => {
                const imm: i64 = if (value.aux_int != 0) 1 else 0;
                try self.setResult(value.id, .{ .immediate = imm });
            },
            .const_nil => {
                // nil is represented as 0
                try self.setResult(value.id, .{ .immediate = 0 });
            },
            .const_slice => try self.genConstSlice(value),
            .add => try self.genAdd(value),
            .sub => try self.genSub(value),
            .mul => try self.genMul(value),
            .div => try self.genDiv(value),
            .mod => try self.genMod(value),
            .neg => try self.genNeg(value),
            .load => try self.genLoad(value),
            .store => try self.genStore(value),
            .eq, .ne, .lt, .le, .gt, .ge => try self.genComparison(value),
            .call => try self.genCall(value),
            .field_local, .field_value, .field => try self.genField(value),
            .not => try self.genNot(value),
            .@"and" => try self.genAnd(value),
            .@"or" => try self.genOr(value),
            .select => try self.genSelect(value),
            .index_local, .index_value, .index => try self.genIndex(value),
            .addr => try self.genAddr(value),
            .ptr_load => try self.genPtrLoad(value),
            .ptr_store => try self.genPtrStore(value),
            .slice_local, .slice_value, .slice_make => try self.genSliceMake(value),
            .slice_index => try self.genSliceIndex(value),
            .union_tag => try self.genUnionTag(value),
            .union_payload => try self.genUnionPayload(value),
            .list_get => try self.genListGet(value),
            .map_get => try self.genMapGet(value),
            // Block terminators handled in genBlockEnd
            .ret, .jump, .branch => {},
            // Union init generates values in rax/rdx for 16-byte store
            .union_init => try self.genUnionInit(value),
            // Operations handled elsewhere or not yet implemented
            .phi, .copy => {}, // Handled by register allocator
            .const_float => {}, // TODO: implement (floating point not yet supported)
            .alloc => try self.genAlloc(value),
            .ptr_field => try self.genPtrField(value),
            .ptr_field_store => try self.genPtrFieldStore(value),
            .map_new => try self.genMapNew(value),
            .map_set => try self.genMapSet(value),
            .map_has => try self.genMapHas(value),
            .map_size => try self.genMapSize(value),
            .map_free => try self.genMapFree(value),
            .list_new => try self.genListNew(value),
            .list_push => try self.genListPush(value),
            .list_set => try self.genListSet(value),
            .list_len => try self.genListLen(value),
            .list_free => try self.genListFree(value),
            .str_concat => try self.genStrConcat(value),
            .arg => try self.genArg(value),
            .retain, .release, .@"unreachable" => {}, // TODO: implement
        }
    }

    /// Generate code for a block terminator
    pub fn genBlockEnd(self: *CodeGen, block: *ssa.Block) !void {
        switch (block.kind) {
            .ret => try self.genReturn(block),
            .plain => {
                // Jump handled by driver
            },
            .@"if" => {
                // Branch handled by driver
            },
            .exit => {},
        }
    }

    /// Generate prologue for a function
    ///
    /// Following x86_64 SysV ABI (Go/Zig pattern):
    /// - For sret (>16 byte return): hidden pointer arrives in RDI, save it to sret_offset
    /// - All other params shift right by 1 when sret is used
    pub fn genPrologue(self: *CodeGen) !void {
        // push rbp
        try x86.pushReg(self.buf, .rbp);
        // mov rbp, rsp
        try x86.movRegReg(self.buf, .rbp, .rsp);

        // Allocate stack space (aligned to 16)
        const stack_size = alignTo(self.stack_size, 16);
        if (stack_size > 0) {
            try x86.subRegImm32(self.buf, .rsp, @intCast(stack_size));
        }

        // x86_64 SysV ABI: rdi, rsi, rdx, rcx, r8, r9 for arguments
        const param_regs = [_]x86.Reg{ .rdi, .rsi, .rdx, .rcx, .r8, .r9 };
        const num_params = self.func.param_count;

        var reg_idx: usize = 0;

        // Handle sret (struct return via hidden pointer)
        // The hidden pointer comes in RDI, save it to sret_offset
        // All actual parameters shift right by 1 register
        if (self.has_sret) {
            try x86.movMemReg(self.buf, .rbp, self.sret_offset, .rdi);
            reg_idx = 1; // Skip RDI for actual parameters
        }

        // Spill parameters to local slots
        for (0..num_params) |param_idx| {
            if (param_idx >= self.func.locals.len or reg_idx >= param_regs.len) break;

            const local = self.func.locals[param_idx];
            const local_offset = local.offset;
            const param_type = self.type_reg.get(local.type_idx);

            if (param_type == .slice) {
                // Slice parameter: 2 registers (ptr + len)
                if (reg_idx + 1 < param_regs.len) {
                    // Store ptr at offset, len at offset+8
                    try x86.movMemReg(self.buf, .rbp, local_offset, param_regs[reg_idx]);
                    try x86.movMemReg(self.buf, .rbp, local_offset + 8, param_regs[reg_idx + 1]);
                    reg_idx += 2;
                } else {
                    // Not enough registers, just store ptr
                    try x86.movMemReg(self.buf, .rbp, local_offset, param_regs[reg_idx]);
                    reg_idx += 1;
                }
            } else {
                // Use appropriate-sized store based on parameter type
                const param_size = self.type_reg.sizeOf(local.type_idx);
                switch (param_size) {
                    1 => try x86.movMem8Reg(self.buf, .rbp, local_offset, param_regs[reg_idx]),
                    else => try x86.movMemReg(self.buf, .rbp, local_offset, param_regs[reg_idx]),
                }
                reg_idx += 1;
            }
        }
    }
};

// ============================================================================
// Helpers
// ============================================================================

fn alignTo(value: u32, alignment: u32) u32 {
    return (value + alignment - 1) & ~(alignment - 1);
}

// ============================================================================
// Tests
// ============================================================================

test "MCValue basics" {
    const imm = MCValue{ .immediate = 42 };
    try std.testing.expect(!imm.isRegister());
    try std.testing.expectEqual(@as(?x86.Reg, null), imm.getReg());

    const reg = MCValue{ .register = .rax };
    try std.testing.expect(reg.isRegister());
    try std.testing.expectEqual(@as(?x86.Reg, .rax), reg.getReg());
}

test "RegisterManager allocation" {
    var rm = RegisterManager{};

    // All should be free initially
    try std.testing.expect(rm.isFree(.rbx));
    try std.testing.expect(rm.isFree(.r12));

    // Allocate one
    const reg = rm.tryAlloc(0);
    try std.testing.expect(reg != null);
    try std.testing.expect(!rm.isFree(reg.?));

    // Free it
    rm.markFree(reg.?);
    try std.testing.expect(rm.isFree(reg.?));
}

test "RegisterManager locking" {
    var rm = RegisterManager{};

    rm.lock(.rbx);
    try std.testing.expect(rm.isLocked(.rbx));

    // Locked register shouldn't be allocated
    const reg = rm.tryAlloc(0);
    try std.testing.expect(reg != null);
    try std.testing.expect(reg.? != .rbx);

    rm.unlock(.rbx);
    try std.testing.expect(!rm.isLocked(.rbx));
}

test "InstTracking init" {
    const reg_tracking = InstTracking.init(.{ .register = .rax });
    try std.testing.expect(reg_tracking.home == .none);
    try std.testing.expectEqual(@as(?x86.Reg, .rax), reg_tracking.current.getReg());

    const stack_tracking = InstTracking.init(.{ .stack = -16 });
    try std.testing.expectEqual(@as(?i32, -16), stack_tracking.home.getStack());
    try std.testing.expectEqual(@as(?i32, -16), stack_tracking.current.getStack());
}
