//! ARM64 Code Generation with Integrated Register Allocation
//!
//! This module follows Zig's approach: register allocation happens DURING
//! codegen, not as a separate pass.
//!
//! ARM64 calling convention (AAPCS64):
//! - x0-x7: arguments and return values
//! - x8: indirect result location
//! - x9-x15: caller-saved temporaries
//! - x16-x17: intra-procedure call scratch (IP0, IP1)
//! - x18: platform register (reserved)
//! - x19-x28: callee-saved
//! - x29: frame pointer (fp)
//! - x30: link register (lr)
//! - sp: stack pointer

const std = @import("std");
const Allocator = std.mem.Allocator;

const ssa = @import("../ssa.zig");
const types = @import("../types.zig");
const aarch64 = @import("aarch64.zig");
const be = @import("backend.zig");
const liveness = @import("../liveness.zig");

// ============================================================================
// MCValue - Machine Code Value (where a value lives)
// ============================================================================

// ============================================================================
// ABI Type Classification (ARM64 AAPCS64)
// ============================================================================

/// How a type is passed/returned according to ARM64 ABI.
/// This is the single source of truth for calling convention decisions.
pub const ABIClass = enum {
    /// Types ≤ 8 bytes: passed in 1 register (x0-x7)
    single_reg,
    /// Types 9-16 bytes: passed in 2 consecutive registers
    double_reg,
    /// Types > 16 bytes: passed by pointer (callee allocates for returns)
    by_pointer,
    /// Slices: always 2 registers (ptr + len), regardless of size
    slice,
};

/// Classify a type for ARM64 ABI purposes.
/// This function encapsulates all the calling convention decisions.
pub fn classifyType(type_reg: *const types.TypeRegistry, type_idx: types.TypeIndex) ABIClass {
    const t = type_reg.get(type_idx);
    const size = type_reg.sizeOf(type_idx);

    // Slices are special - always passed as ptr+len in 2 registers
    if (t == .slice) {
        return .slice;
    }

    // Size-based classification (ARM64 AAPCS64)
    if (size > 16) {
        return .by_pointer;
    } else if (size > 8) {
        return .double_reg;
    } else {
        return .single_reg;
    }
}

/// Returns number of registers needed to pass a type.
pub fn regsNeeded(class: ABIClass) usize {
    return switch (class) {
        .single_reg => 1,
        .double_reg, .slice => 2,
        .by_pointer => 1, // pointer uses 1 reg
    };
}

pub const MCValue = union(enum) {
    none,
    dead,
    immediate: i64,
    register: aarch64.Reg,
    stack: u32, // offset from sp (positive), may exceed u12 for large frames
    lea_symbol: struct {
        name: []const u8,
        len: usize,
    },

    pub fn isRegister(self: MCValue) bool {
        return self == .register;
    }

    pub fn getReg(self: MCValue) ?aarch64.Reg {
        return switch (self) {
            .register => |r| r,
            else => null,
        };
    }

    pub fn getStack(self: MCValue) ?u32 {
        return switch (self) {
            .stack => |s| s,
            else => null,
        };
    }
};

// ============================================================================
// InstTracking - Track where a value lives
// ============================================================================

pub const InstTracking = struct {
    home: MCValue,
    current: MCValue,

    pub fn init(result: MCValue) InstTracking {
        return switch (result) {
            .none, .dead, .immediate, .stack, .lea_symbol => .{
                .home = result,
                .current = result,
            },
            .register => .{
                .home = .none,
                .current = result,
            },
        };
    }

    pub fn getReg(self: InstTracking) ?aarch64.Reg {
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

/// Registers available for allocation on ARM64.
/// Caller-saved first (cheaper - no save/restore), then callee-saved.
/// The register allocator picks from the front, so caller-saved are preferred.
pub const allocatable_regs = [_]aarch64.Reg{
    // Caller-saved (clobbered by calls - no save/restore needed)
    .x9, .x10, .x11, .x12, .x13, .x14, .x15,
    .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7,
    // Callee-saved (survive function calls - require save/restore)
    // NOTE: Using these requires saving them in prologue/epilogue!
    // For now, we avoid them by putting them last in the list.
    .x19, .x20, .x21, .x22, .x23, .x24, .x25, .x26, .x27, .x28,
};

/// Scratch registers - never allocated, used for temporaries
pub const scratch0: aarch64.Reg = .x16; // IP0
pub const scratch1: aarch64.Reg = .x17; // IP1

/// Number of callee-saved registers
pub const num_callee_saved: usize = 10;

pub const RegisterManager = struct {
    registers: [allocatable_regs.len]?ssa.ValueID = .{null} ** allocatable_regs.len,
    free_regs: u32 = (1 << allocatable_regs.len) - 1,
    locked_regs: u32 = 0,

    fn indexOf(reg: aarch64.Reg) ?u5 {
        for (allocatable_regs, 0..) |r, i| {
            if (r == reg) return @intCast(i);
        }
        return null;
    }

    pub fn isFree(self: *const RegisterManager, reg: aarch64.Reg) bool {
        const idx = indexOf(reg) orelse return true;
        return (self.free_regs >> @intCast(idx)) & 1 == 1;
    }

    pub fn isLocked(self: *const RegisterManager, reg: aarch64.Reg) bool {
        const idx = indexOf(reg) orelse return false;
        return (self.locked_regs >> @intCast(idx)) & 1 == 1;
    }

    pub fn lock(self: *RegisterManager, reg: aarch64.Reg) void {
        if (indexOf(reg)) |idx| {
            self.locked_regs |= @as(u32, 1) << @intCast(idx);
        }
    }

    pub fn unlock(self: *RegisterManager, reg: aarch64.Reg) void {
        if (indexOf(reg)) |idx| {
            self.locked_regs &= ~(@as(u32, 1) << @intCast(idx));
        }
    }

    pub fn markUsed(self: *RegisterManager, reg: aarch64.Reg, value_id: ssa.ValueID) void {
        if (indexOf(reg)) |idx| {
            self.registers[idx] = value_id;
            self.free_regs &= ~(@as(u32, 1) << @intCast(idx));
        }
    }

    pub fn markFree(self: *RegisterManager, reg: aarch64.Reg) void {
        if (indexOf(reg)) |idx| {
            self.registers[idx] = null;
            self.free_regs |= @as(u32, 1) << @intCast(idx);
        }
    }

    pub fn getValueIn(self: *const RegisterManager, reg: aarch64.Reg) ?ssa.ValueID {
        const idx = indexOf(reg) orelse return null;
        return self.registers[idx];
    }

    pub fn tryAlloc(self: *RegisterManager, value_id: ?ssa.ValueID) ?aarch64.Reg {
        const available = self.free_regs & ~self.locked_regs;
        if (available == 0) return null;

        const idx: u5 = @intCast(@ctz(available));
        const reg = allocatable_regs[idx];

        if (value_id) |vid| {
            self.markUsed(reg, vid);
        }
        return reg;
    }

    pub fn findSpillCandidate(self: *const RegisterManager) ?aarch64.Reg {
        const spillable = ~self.free_regs & ~self.locked_regs;
        if (spillable == 0) return null;
        const idx: u5 = @intCast(@ctz(spillable));
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
    tracking: std.AutoHashMap(ssa.ValueID, InstTracking),
    reg_manager: RegisterManager,
    string_infos: []const be.StringInfo,
    next_spill_offset: u32,
    stack_size: u32,

    // Liveness analysis for smart spill decisions
    liveness_info: ?liveness.LivenessInfo = null,
    current_inst: u32 = 0,

    // Track which callee-saved registers are used (Go/Zig pattern)
    // Bit 0 = x19, bit 1 = x20, ..., bit 9 = x28
    callee_saved_used: u16 = 0,

    pub fn init(
        allocator: Allocator,
        buf: *be.CodeBuffer,
        func: *ssa.Func,
        type_reg: *types.TypeRegistry,
        os: be.OS,
        string_infos: []const be.StringInfo,
        stack_size: u32,
    ) CodeGen {
        return .{
            .allocator = allocator,
            .buf = buf,
            .func = func,
            .type_reg = type_reg,
            .os = os,
            .tracking = std.AutoHashMap(ssa.ValueID, InstTracking).init(allocator),
            .reg_manager = .{},
            .string_infos = string_infos,
            // Spill slots start after fp/lr (16 bytes) + callee-saved area (80 bytes)
            // Layout: [sp+0]=fp, [sp+8]=lr, [sp+16..sp+95]=callee-saved, [sp+96..]=spills
            .next_spill_offset = 96,
            .stack_size = stack_size,
        };
    }

    /// Mark a callee-saved register as used (for save/restore tracking)
    fn markCalleeSavedUsed(self: *CodeGen, reg: aarch64.Reg) void {
        const callee_saved_start: usize = 15; // Index of x19 in allocatable_regs (after 15 caller-saved)
        for (allocatable_regs[callee_saved_start..], 0..) |cs_reg, i| {
            if (cs_reg == reg) {
                self.callee_saved_used |= @as(u16, 1) << @intCast(i);
                return;
            }
        }
    }

    /// Count how many callee-saved registers are used
    pub fn countCalleeSavedUsed(self: *const CodeGen) u32 {
        return @popCount(self.callee_saved_used);
    }

    /// Get the stack space needed for callee-saved registers (8 bytes each, 16-byte aligned)
    pub fn getCalleeSavedStackSpace(self: *const CodeGen) u32 {
        const count = self.countCalleeSavedUsed();
        // Round up to even for 16-byte alignment (stp saves pairs)
        const pairs = (count + 1) / 2;
        return pairs * 16;
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

    /// Get the actual spill space used during code generation.
    /// This is the difference between current spill offset and initial (16 for fp/lr).
    pub fn getSpillSize(self: *const CodeGen) u32 {
        const initial_spill_offset: u32 = 16;
        return if (self.next_spill_offset > initial_spill_offset)
            self.next_spill_offset - initial_spill_offset
        else
            0;
    }

    // ========================================================================
    // Core allocation functions
    // ========================================================================

    pub fn allocReg(self: *CodeGen, value_id: ?ssa.ValueID) !aarch64.Reg {
        if (self.reg_manager.tryAlloc(value_id)) |reg| {
            // Track callee-saved usage for prologue/epilogue generation
            self.markCalleeSavedUsed(reg);
            return reg;
        }

        const spill_reg = self.findBestSpillCandidate() orelse {
            return error.AllRegistersLocked;
        };

        try self.spillReg(spill_reg);

        if (value_id) |vid| {
            self.reg_manager.markUsed(spill_reg, vid);
        }
        // Track callee-saved usage for prologue/epilogue generation
        self.markCalleeSavedUsed(spill_reg);
        return spill_reg;
    }

    /// Find the best register to spill using farthest-next-use heuristic.
    /// If liveness info is available, picks the register whose value is used
    /// farthest in the future. Otherwise falls back to first-available.
    fn findBestSpillCandidate(self: *CodeGen) ?aarch64.Reg {
        // If we have liveness info, use farthest-next-use heuristic
        if (self.liveness_info) |lv| {
            var best_reg: ?aarch64.Reg = null;
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

    fn spillReg(self: *CodeGen, reg: aarch64.Reg) !void {
        const value_id = self.reg_manager.getValueIn(reg) orelse return;
        const tracking = self.tracking.getPtr(value_id) orelse return;

        if (tracking.isSpilled()) {
            self.reg_manager.markFree(reg);
            return;
        }

        if (tracking.home == .none) {
            tracking.home = .{ .stack = self.next_spill_offset };
            self.next_spill_offset +|= 8; // saturating add for u12
        }

        // ARM64: str reg, [sp, #offset]
        const offset = tracking.home.getStack().?;
        try self.strSpOffset(reg, offset);

        tracking.current = tracking.home;
        self.reg_manager.markFree(reg);
    }

    pub fn getValue(self: *CodeGen, value_id: ssa.ValueID) MCValue {
        if (self.tracking.get(value_id)) |tracking| {
            return tracking.current;
        }
        return .none;
    }

    pub fn loadToReg(self: *CodeGen, dest: aarch64.Reg, mcv: MCValue) !void {
        switch (mcv) {
            .register => |src| {
                if (src != dest) {
                    try aarch64.movRegReg(self.buf, dest, src);
                }
            },
            .stack => |offset| {
                try self.ldrSpOffset(dest, offset);
            },
            .immediate => |imm| {
                try aarch64.movRegImm64(self.buf, dest, imm);
            },
            .lea_symbol => |sym| {
                try aarch64.loadSymbolAddr(self.buf, dest, sym.name);
            },
            .none, .dead => {},
        }
    }

    /// Load from [sp + offset] handling large offsets
    /// For offsets > 4095, uses scratch register x16
    fn ldrSpOffset(self: *CodeGen, dest: aarch64.Reg, offset: u32) !void {
        if (offset <= 4095) {
            try aarch64.ldrRegImm(self.buf, dest, .sp, @intCast(offset));
        } else {
            // Large offset: add x16, sp, #offset then ldr dest, [x16]
            try aarch64.movRegImm64(self.buf, .x16, offset);
            try aarch64.addRegReg(self.buf, .x16, .sp, .x16);
            try aarch64.ldrRegImm(self.buf, dest, .x16, 0);
        }
    }

    /// Store to [sp + offset] handling large offsets
    /// For offsets > 4095, uses scratch register x16
    fn strSpOffset(self: *CodeGen, src: aarch64.Reg, offset: u32) !void {
        if (offset <= 4095) {
            try aarch64.strRegImm(self.buf, src, .sp, @intCast(offset));
        } else {
            // Large offset: add x16, sp, #offset then str src, [x16]
            try aarch64.movRegImm64(self.buf, .x16, offset);
            try aarch64.addRegReg(self.buf, .x16, .sp, .x16);
            try aarch64.strRegImm(self.buf, src, .x16, 0);
        }
    }

    /// Load byte from [sp + offset] handling large offsets
    fn ldrbSpOffset(self: *CodeGen, dest: aarch64.Reg, offset: u32) !void {
        if (offset <= 4095) {
            try aarch64.ldrbRegImm(self.buf, dest, .sp, @intCast(offset));
        } else {
            try aarch64.movRegImm64(self.buf, .x16, offset);
            try aarch64.addRegReg(self.buf, .x16, .sp, .x16);
            try aarch64.ldrbRegImm(self.buf, dest, .x16, 0);
        }
    }

    /// Load signed byte from [sp + offset] handling large offsets
    fn ldrsbSpOffset(self: *CodeGen, dest: aarch64.Reg, offset: u32) !void {
        if (offset <= 4095) {
            try aarch64.ldrsbRegImm(self.buf, dest, .sp, @intCast(offset));
        } else {
            try aarch64.movRegImm64(self.buf, .x16, offset);
            try aarch64.addRegReg(self.buf, .x16, .sp, .x16);
            try aarch64.ldrsbRegImm(self.buf, dest, .x16, 0);
        }
    }

    /// Store byte to [sp + offset] handling large offsets
    fn strbSpOffset(self: *CodeGen, src: aarch64.Reg, offset: u32) !void {
        if (offset <= 4095) {
            try aarch64.strbRegImm(self.buf, src, .sp, @intCast(offset));
        } else {
            try aarch64.movRegImm64(self.buf, .x16, offset);
            try aarch64.addRegReg(self.buf, .x16, .sp, .x16);
            try aarch64.strbRegImm(self.buf, src, .x16, 0);
        }
    }

    /// Store 32-bit word to [sp + offset] handling large offsets
    fn strwSpOffset(self: *CodeGen, src: aarch64.Reg, offset: u32) !void {
        if (offset <= 4095) {
            try aarch64.strwRegImm(self.buf, src, .sp, @intCast(offset));
        } else {
            try aarch64.movRegImm64(self.buf, .x16, offset);
            try aarch64.addRegReg(self.buf, .x16, .sp, .x16);
            try aarch64.strwRegImm(self.buf, src, .x16, 0);
        }
    }

    /// Store 16-bit halfword to [sp + offset] handling large offsets
    fn strhSpOffset(self: *CodeGen, src: aarch64.Reg, offset: u32) !void {
        if (offset <= 4095) {
            try aarch64.strhRegImm(self.buf, src, .sp, @intCast(offset));
        } else {
            try aarch64.movRegImm64(self.buf, .x16, offset);
            try aarch64.addRegReg(self.buf, .x16, .sp, .x16);
            try aarch64.strhRegImm(self.buf, src, .x16, 0);
        }
    }

    /// Load 32-bit word from [sp + offset] handling large offsets
    fn ldrwSpOffset(self: *CodeGen, dest: aarch64.Reg, offset: u32) !void {
        if (offset <= 4095) {
            try aarch64.ldrwRegImm(self.buf, dest, .sp, @intCast(offset));
        } else {
            try aarch64.movRegImm64(self.buf, .x16, offset);
            try aarch64.addRegReg(self.buf, .x16, .sp, .x16);
            try aarch64.ldrwRegImm(self.buf, dest, .x16, 0);
        }
    }

    /// Load 16-bit halfword from [sp + offset] handling large offsets
    fn ldrhSpOffset(self: *CodeGen, dest: aarch64.Reg, offset: u32) !void {
        if (offset <= 4095) {
            try aarch64.ldrhRegImm(self.buf, dest, .sp, @intCast(offset));
        } else {
            try aarch64.movRegImm64(self.buf, .x16, offset);
            try aarch64.addRegReg(self.buf, .x16, .sp, .x16);
            try aarch64.ldrhRegImm(self.buf, dest, .x16, 0);
        }
    }

    /// Compute dest = sp + offset, handling large offsets
    fn addSpOffset(self: *CodeGen, dest: aarch64.Reg, offset: u32) !void {
        if (offset <= 4095) {
            try aarch64.addRegImm12(self.buf, dest, .sp, @intCast(offset));
        } else {
            try aarch64.movRegImm64(self.buf, .x16, offset);
            try aarch64.addRegReg(self.buf, dest, .sp, .x16);
        }
    }

    pub fn markDead(self: *CodeGen, value_id: ssa.ValueID) void {
        if (self.tracking.getPtr(value_id)) |tracking| {
            if (tracking.current.getReg()) |reg| {
                self.reg_manager.markFree(reg);
            }
            tracking.current = .dead;
        }
    }

    pub fn setResult(self: *CodeGen, value_id: ssa.ValueID, result: MCValue) !void {
        try self.tracking.put(value_id, InstTracking.init(result));
    }

    /// Spill caller-saved registers before a function call.
    /// If liveness info is available, only spills values that are used after this point.
    pub fn spillCallerSaved(self: *CodeGen) !void {
        const caller_saved = [_]aarch64.Reg{
            .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7,
            .x9, .x10, .x11, .x12, .x13, .x14, .x15,
        };

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

    // ========================================================================
    // Liveness-based register freeing
    // ========================================================================

    /// Check if an operand dies at this instruction and can be clobbered.
    /// Returns true if the operand is in a register and dies here.
    fn operandDiesInReg(self: *CodeGen, value_id: ssa.ValueID, operand_idx: u8, arg_id: ssa.ValueID) bool {
        if (self.liveness_info) |lv| {
            if (lv.operandDies(value_id, operand_idx)) {
                const mcv = self.getValue(arg_id);
                return mcv == .register;
            }
        }
        return false;
    }

    /// Free registers holding operands that die at this instruction.
    /// Call this AFTER the operation completes.
    fn freeDeadOperands(self: *CodeGen, value: *ssa.Value) void {
        if (self.liveness_info) |lv| {
            const args = value.args();
            for (args, 0..) |arg_id, i| {
                if (arg_id == ssa.null_value) continue;
                if (lv.operandDies(value.id, @intCast(i))) {
                    // This operand dies here - free its register if it has one
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

    pub fn genConstInt(self: *CodeGen, value: *ssa.Value) !void {
        const imm = value.aux_int;
        // Small constants can be immediates
        if (imm >= 0 and imm <= 65535) {
            try self.setResult(value.id, .{ .immediate = imm });
        } else {
            const reg = try self.allocReg(value.id);
            try aarch64.movRegImm64(self.buf, reg, imm);
            try self.setResult(value.id, .{ .register = reg });
        }
    }

    pub fn genConstSlice(self: *CodeGen, value: *ssa.Value) !void {
        // const_slice: aux_int = string index in string_infos
        // Track as lea_symbol so multiple const_slices can coexist
        // The actual load happens when the value is used
        const string_idx: usize = @intCast(value.aux_int);

        if (string_idx >= self.string_infos.len) {
            // Invalid string index - use immediate 0
            try self.setResult(value.id, .{ .immediate = 0 });
            return;
        }

        const info = self.string_infos[string_idx];

        // Track as lea_symbol so select and other ops can properly load both ptr and len
        try self.setResult(value.id, .{ .lea_symbol = .{
            .name = info.symbol_name,
            .len = info.len,
        } });
    }

    pub fn genAdd(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        // If right is in x0, we MUST save it before loading left into x0,
        // otherwise loading left will clobber right before we can use it.
        if (right_mcv == .register and right_mcv.register == .x0) {
            try aarch64.movRegReg(self.buf, .x9, .x0);
            try self.loadToReg(.x0, left_mcv);
            try aarch64.addRegReg(self.buf, .x0, .x0, .x9);
        } else {
            // Load left operand into x0
            try self.loadToReg(.x0, left_mcv);

            // Add right operand
            switch (right_mcv) {
                .register => |src| {
                    try aarch64.addRegReg(self.buf, .x0, .x0, src);
                },
                .immediate => |imm| {
                    if (imm >= 0 and imm <= 4095) {
                        try aarch64.addRegImm12(self.buf, .x0, .x0, @intCast(imm));
                    } else {
                        try aarch64.movRegImm64(self.buf, .x9, imm);
                        try aarch64.addRegReg(self.buf, .x0, .x0, .x9);
                    }
                },
                .stack => |offset| {
                    try self.ldrSpOffset(.x9, offset);
                    try aarch64.addRegReg(self.buf, .x0, .x0, .x9);
                },
                else => {},
            }
        }

        // Free dead operands after the operation
        self.freeDeadOperands(value);

        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    pub fn genSub(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        // If right is in x0, we MUST save it before loading left into x0
        if (right_mcv == .register and right_mcv.register == .x0) {
            try aarch64.movRegReg(self.buf, .x9, .x0);
            try self.loadToReg(.x0, left_mcv);
            try aarch64.subRegReg(self.buf, .x0, .x0, .x9);
        } else {
            try self.loadToReg(.x0, left_mcv);

            switch (right_mcv) {
                .register => |src| {
                    try aarch64.subRegReg(self.buf, .x0, .x0, src);
                },
                .immediate => |imm| {
                    if (imm >= 0 and imm <= 4095) {
                        try aarch64.subRegImm12(self.buf, .x0, .x0, @intCast(imm));
                    } else {
                        try aarch64.movRegImm64(self.buf, .x9, imm);
                        try aarch64.subRegReg(self.buf, .x0, .x0, .x9);
                    }
                },
                .stack => |offset| {
                    try self.ldrSpOffset(.x9, offset);
                    try aarch64.subRegReg(self.buf, .x0, .x0, .x9);
                },
                else => {},
            }
        }

        self.freeDeadOperands(value);
        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    pub fn genMul(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        // If right is in x0, we MUST save it before loading left into x0
        if (right_mcv == .register and right_mcv.register == .x0) {
            try aarch64.movRegReg(self.buf, .x9, .x0);
            try self.loadToReg(.x0, left_mcv);
            try aarch64.mulRegReg(self.buf, .x0, .x0, .x9);
        } else {
            try self.loadToReg(.x0, left_mcv);

            switch (right_mcv) {
                .register => |src| {
                    try aarch64.mulRegReg(self.buf, .x0, .x0, src);
                },
                .stack => |offset| {
                    try self.ldrSpOffset(.x9, offset);
                    try aarch64.mulRegReg(self.buf, .x0, .x0, .x9);
                },
                .immediate => |imm| {
                    try aarch64.movRegImm64(self.buf, .x9, imm);
                    try aarch64.mulRegReg(self.buf, .x0, .x0, .x9);
                },
                else => {},
            }
        }

        self.freeDeadOperands(value);
        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    pub fn genDiv(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        // If right is in x0, we MUST save it before loading left into x0
        if (right_mcv == .register and right_mcv.register == .x0) {
            try aarch64.movRegReg(self.buf, .x9, .x0);
            try self.loadToReg(.x0, left_mcv);
        } else {
            try self.loadToReg(.x0, left_mcv);
            try self.loadToReg(.x9, right_mcv);
        }

        // ARM64 SDIV: x0 = x0 / x9
        try aarch64.sdivRegReg(self.buf, .x0, .x0, .x9);

        self.freeDeadOperands(value);
        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    pub fn genMod(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        const dest = try self.allocReg(value.id);
        try self.loadToReg(dest, left_mcv);
        try self.loadToReg(scratch0, right_mcv);

        // ARM64 modulo: a % b = a - (a / b) * b
        try aarch64.sdivRegReg(self.buf, scratch1, dest, scratch0);
        try aarch64.mulRegReg(self.buf, scratch1, scratch1, scratch0);
        try aarch64.subRegReg(self.buf, dest, dest, scratch1);

        self.freeDeadOperands(value);
        try self.setResult(value.id, .{ .register = dest });
    }

    pub fn genNeg(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        const src_mcv = self.getValue(args[0]);

        const dest = try self.allocReg(value.id);
        try self.loadToReg(dest, src_mcv);
        try aarch64.negReg(self.buf, dest, dest);
        self.freeDeadOperands(value);

        try self.setResult(value.id, .{ .register = dest });
    }

    pub fn genLoad(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const local_idx = args[0];
        if (local_idx >= self.func.locals.len) return;

        const local = self.func.locals[@intCast(local_idx)];
        const size = self.type_reg.sizeOf(value.type_idx);
        // Convert rbp-relative offset to sp-relative
        const sp_offset = convertOffset(local.offset, self.stack_size);

        // For large values (>8 bytes), don't load into a register - just record stack location
        // The consumer (e.g., genListPush) will access the value from the stack
        if (size > 8) {
            try self.setResult(value.id, .{ .stack = sp_offset });
            return;
        }

        const dest = try self.allocReg(value.id);

        switch (size) {
            1 => {
                // Use sign-extending load for signed types (i8)
                if (self.type_reg.isSigned(value.type_idx)) {
                    try self.ldrsbSpOffset(dest, sp_offset);
                } else {
                    try self.ldrbSpOffset(dest, sp_offset);
                }
            },
            else => try self.ldrSpOffset(dest, sp_offset),
        }

        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate code for store to local variable
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
        const sp_offset = convertOffset(total_offset, self.stack_size);

        const src_value = &self.func.values.items[src_id];

        // Check source op type for special 16-byte handling
        // These ops leave ptr in x0, len/payload in x1 (for small unions)
        // For large unions, union_init puts result on stack
        if (src_value.op == .slice_local or src_value.op == .slice_value or
            src_value.op == .slice_make or src_value.op == .str_concat)
        {
            // Store 16-byte value: ptr/tag at offset, len/payload at offset+8
            try self.strSpOffset(.x0, sp_offset);
            const sp_offset_plus8 = convertOffset(total_offset + 8, self.stack_size);
            try self.strSpOffset(.x1, sp_offset_plus8);
            return;
        }

        // Handle const_slice - now tracked as lea_symbol, need to load then store
        if (src_value.op == .const_slice) {
            const src_mcv = self.getValue(src_id);
            switch (src_mcv) {
                .lea_symbol => |sym| {
                    // Load symbol address to x0
                    try aarch64.loadSymbolAddr(self.buf, .x0, sym.name);
                    // Load length to x1
                    try aarch64.movRegImm64(self.buf, .x1, @intCast(sym.len));
                    // Store both
                    try self.strSpOffset(.x0, sp_offset);
                    const sp_offset_plus8 = convertOffset(total_offset + 8, self.stack_size);
                    try self.strSpOffset(.x1, sp_offset_plus8);
                },
                .stack => |offset| {
                    // Slice on stack (from call or select) - copy both parts
                    try self.ldrSpOffset(.x0, offset);
                    try self.ldrSpOffset(.x1, offset + 8);
                    try self.strSpOffset(.x0, sp_offset);
                    const sp_offset_plus8 = convertOffset(total_offset + 8, self.stack_size);
                    try self.strSpOffset(.x1, sp_offset_plus8);
                },
                else => {
                    // Fallback - shouldn't happen but handle it
                    try self.loadToReg(.x0, src_mcv);
                    try self.strSpOffset(.x0, sp_offset);
                },
            }
            return;
        }

        // Handle union_init - check if it's on stack (large union) or registers (small union)
        if (src_value.op == .union_init) {
            const src_mcv = self.getValue(src_id);
            const union_size = self.type_reg.sizeOf(src_value.type_idx);

            if (src_mcv == .stack) {
                // Large union on stack - copy to destination
                var copied: u32 = 0;
                while (copied < union_size) {
                    const src_off = src_mcv.stack + copied;
                    const dst_off = convertOffset(total_offset + @as(i32, @intCast(copied)), self.stack_size);
                    try self.ldrSpOffset(scratch0, src_off);
                    try self.strSpOffset(scratch0, dst_off);
                    copied += 8;
                }
                return;
            } else {
                // Small union in registers (x0=tag, x1=payload)
                try self.strSpOffset(.x0, sp_offset);
                const sp_offset_plus8 = convertOffset(total_offset + 8, self.stack_size);
                try self.strSpOffset(.x1, sp_offset_plus8);
                return;
            }
        }

        // Handle call results
        if (src_value.op == .call) {
            const ret_type = self.type_reg.get(src_value.type_idx);
            const ret_size = self.type_reg.sizeOf(src_value.type_idx);

            if (ret_type == .struct_type) {
                // Struct return: result is at stack offset, copy to destination
                const src_mcv = self.getValue(src_id);
                if (src_mcv == .stack) {
                    const src_stack_offset = src_mcv.stack;
                    var copied: u32 = 0;
                    while (copied < ret_size) {
                        // Load from result location
                        try self.ldrSpOffset(scratch0, src_stack_offset + copied);
                        // Store to destination local
                        const dst_offset = convertOffset(total_offset + @as(i32, @intCast(copied)), self.stack_size);
                        try self.strSpOffset(scratch0, dst_offset);
                        copied += 8;
                    }
                    return;
                }
            }
        }

        // Handle list_get results with large elements (already copied to stack)
        if (src_value.op == .list_get) {
            const elem_size = self.type_reg.sizeOf(src_value.type_idx);
            if (elem_size > 8) {
                // list_get copied the element to a stack slot
                const src_mcv = self.getValue(src_id);
                if (src_mcv == .stack) {
                    const src_stack_offset = src_mcv.stack;
                    var copied: u32 = 0;
                    while (copied < elem_size) {
                        // Load from spill location
                        try self.ldrSpOffset(scratch0, src_stack_offset + copied);
                        // Store to destination local
                        const dst_offset = convertOffset(total_offset + @as(i32, @intCast(copied)), self.stack_size);
                        try self.strSpOffset(scratch0, dst_offset);
                        copied += 8;
                    }
                    return;
                }
            }
        }

        // Standard value store - use MCValue-based approach (Go/Zig pattern)
        // Key principle: use DESTINATION type for store size, not source type
        // This ensures u8 variables get 1-byte stores even when assigned from int literals
        const dest_type_idx = if (field_offset == 0)
            local.type_idx // Simple scalar store - use local's type
        else
            // Struct field store - look up field type at offset
            self.type_reg.getFieldTypeAtOffset(local.type_idx, @intCast(field_offset)) orelse local.type_idx;
        const size = self.type_reg.sizeOf(dest_type_idx);
        const src_mcv = self.getValue(src_id);

        switch (src_mcv) {
            .register => |reg| {
                // Value is in a register - store it with correct width
                switch (size) {
                    1 => try self.strbSpOffset(reg, sp_offset),
                    2 => try self.strhSpOffset(reg, sp_offset),
                    4 => try self.strwSpOffset(reg, sp_offset),
                    else => try self.strSpOffset(reg, sp_offset),
                }
            },
            .immediate => |imm| {
                // Value is an immediate - load to scratch then store
                try aarch64.movRegImm64(self.buf, scratch0, imm);
                switch (size) {
                    1 => try self.strbSpOffset(scratch0, sp_offset),
                    2 => try self.strhSpOffset(scratch0, sp_offset),
                    4 => try self.strwSpOffset(scratch0, sp_offset),
                    else => try self.strSpOffset(scratch0, sp_offset),
                }
            },
            .stack => |src_stack_offset| {
                // Value is on stack - copy it (size-aware, like Go's decomposition)
                if (size > 8) {
                    // Large value: copy all bytes (8 bytes at a time)
                    var copied: u32 = 0;
                    while (copied < size) {
                        const src_off = src_stack_offset + copied;
                        const dst_off = convertOffset(total_offset + @as(i32, @intCast(copied)), self.stack_size);
                        try self.ldrSpOffset(scratch0, src_off);
                        try self.strSpOffset(scratch0, dst_off);
                        copied += 8;
                    }
                } else {
                    // Small value: single load/store with correct width
                    try self.ldrSpOffset(scratch0, src_stack_offset);
                    switch (size) {
                        1 => try self.strbSpOffset(scratch0, sp_offset),
                        2 => try self.strhSpOffset(scratch0, sp_offset),
                        4 => try self.strwSpOffset(scratch0, sp_offset),
                        else => try self.strSpOffset(scratch0, sp_offset),
                    }
                }
            },
            .none => {
                // No tracked value - operation may have left result in x0
                // This is the fallback for ops that don't set MCValue
                switch (size) {
                    1 => try self.strbSpOffset(.x0, sp_offset),
                    2 => try self.strhSpOffset(.x0, sp_offset),
                    4 => try self.strwSpOffset(.x0, sp_offset),
                    else => try self.strSpOffset(.x0, sp_offset),
                }
            },
            else => {},
        }
    }

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

        try self.loadToReg(scratch0, left_mcv);
        try self.loadToReg(scratch1, right_mcv);

        // CMP
        try aarch64.cmpRegReg(self.buf, scratch0, scratch1);

        const dest = try self.allocReg(value.id);

        // CSET dest, condition
        const cond: aarch64.Cond = switch (value.op) {
            .eq => .eq,
            .ne => .ne,
            .lt => .lt,
            .le => .le,
            .gt => .gt,
            .ge => .ge,
            else => unreachable,
        };
        try aarch64.cset(self.buf, dest, cond);

        self.freeDeadOperands(value);
        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate slice/string comparison by calling cot_str_eq runtime function
    fn genSliceComparison(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();

        // Spill caller-saved registers
        try self.spillCallerSaved();

        // Load left slice (ptr, len) - may be from local or from const_slice result
        const left_val = &self.func.values.items[args[0]];
        try self.loadSliceToRegs(left_val, .x0, .x1);

        // Load right slice (ptr, len)
        const right_val = &self.func.values.items[args[1]];
        try self.loadSliceToRegs(right_val, .x2, .x3);

        // Call cot_str_eq(ptr1, len1, ptr2, len2) -> returns 1 if equal, 0 if not
        const func_name = if (self.os == .macos) "_cot_str_eq" else "cot_str_eq";
        try self.buf.addRelocation(.pc_rel_32, func_name, 0);
        try aarch64.bl(self.buf, 0);

        // Result is in x0 (1 = equal, 0 = not equal)
        // For .ne, we need to invert: cmp x0, #0; cset x0, eq
        if (value.op == .ne) {
            try aarch64.cmpRegImm12(self.buf, .x0, 0);
            try aarch64.cset(self.buf, .x0, .eq);
        }

        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    /// Load a slice value's (ptr, len) into two registers
    fn loadSliceToRegs(self: *CodeGen, val: *ssa.Value, ptr_reg: aarch64.Reg, len_reg: aarch64.Reg) !void {
        // Check if it's a const_slice (already has ptr in x0, len in x1 pattern)
        if (val.op == .const_slice) {
            // Regenerate the const_slice to get ptr and len
            const string_idx: usize = @intCast(val.aux_int);
            if (string_idx < self.string_infos.len) {
                const info = self.string_infos[string_idx];
                try aarch64.loadSymbolAddr(self.buf, ptr_reg, info.symbol_name);
                try aarch64.movRegImm64(self.buf, len_reg, @intCast(info.len));
            } else {
                try aarch64.movRegImm64(self.buf, ptr_reg, 0);
                try aarch64.movRegImm64(self.buf, len_reg, 0);
            }
            return;
        }

        // Check if it's a str_concat result (stored on stack)
        if (val.op == .str_concat) {
            // Result was saved to stack after the call
            const mcv = self.getValue(val.id);
            if (mcv == .stack) {
                const offset = mcv.stack;
                try self.ldrSpOffset(ptr_reg, offset);
                try self.ldrSpOffset(len_reg, offset + 8);
                return;
            }
        }

        // Check if it's a load from a local (slice stored on stack)
        if (val.op == .load) {
            const val_args = val.args();
            if (val_args.len > 0 and val_args[0] < self.func.locals.len) {
                const local_idx: u32 = @intCast(val_args[0]);
                const local = self.func.locals[local_idx];
                const sp_offset = convertOffset(local.offset, self.stack_size);
                // Slice on stack: ptr at offset, len at offset+8
                try self.ldrSpOffset(ptr_reg, sp_offset);
                try self.ldrSpOffset(len_reg, sp_offset + 8);
                return;
            }
        }

        // Fallback: try to get from tracking (may only have ptr)
        const mcv = self.getValue(val.id);
        switch (mcv) {
            .register => |reg| {
                if (reg != ptr_reg) {
                    try aarch64.movRegReg(self.buf, ptr_reg, reg);
                }
                // Assume len is in next register (x1 if ptr is x0)
                // This is a rough heuristic for const_slice results
                try aarch64.movRegImm64(self.buf, len_reg, 0);
            },
            .stack => |offset| {
                try self.ldrSpOffset(ptr_reg, offset);
                try self.ldrSpOffset(len_reg, offset + 8);
            },
            else => {
                try aarch64.movRegImm64(self.buf, ptr_reg, 0);
                try aarch64.movRegImm64(self.buf, len_reg, 0);
            },
        }
    }

    pub fn genCall(self: *CodeGen, value: *ssa.Value) !void {
        try self.spillCallerSaved();

        const arg_regs = [_]aarch64.Reg{ .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7 };
        const args = value.args();

        // Classify return type using ABI rules
        const ret_class = classifyType(self.type_reg, value.type_idx);

        // If large return (by_pointer), allocate temp space and set x8
        var large_result_offset: u32 = 0;
        if (ret_class == .by_pointer) {
            const ret_size = self.type_reg.sizeOf(value.type_idx);
            large_result_offset = self.next_spill_offset;
            try self.addSpOffset(.x8, large_result_offset);
            self.next_spill_offset += @intCast(alignTo(ret_size, 8));
        }

        // First pass: calculate how many registers each argument needs and compute total
        // We need to know the target register index for each argument
        var arg_positions: [8]struct { start_reg: usize, count: usize } = undefined;
        var total_regs: usize = 0;
        for (args, 0..) |arg_id, i| {
            if (i >= 8) break;
            const arg_val = &self.func.values.items[arg_id];
            const arg_class = classifyType(self.type_reg, arg_val.type_idx);
            const needed = regsNeeded(arg_class);
            if (total_regs + needed > arg_regs.len) {
                arg_positions[i] = .{ .start_reg = 0, .count = 0 }; // Skip this arg
            } else {
                arg_positions[i] = .{ .start_reg = total_regs, .count = needed };
                total_regs += needed;
            }
        }

        // Second pass: check if any later argument is in x0 but should go to a later register.
        // If so, we need to save x0 before loading earlier arguments into it.
        // This handles the case where genField put a value in x0 but it's used as arg1, arg2, etc.
        var saved_x0: bool = false;
        const saved_x0_offset = self.next_spill_offset;
        for (args, 0..) |arg_id, i| {
            if (i >= 8 or arg_positions[i].count == 0) continue;
            if (arg_positions[i].start_reg == 0) continue; // arg0 goes to x0, no conflict

            const arg_mcv = self.getValue(arg_id);
            if (arg_mcv == .register and arg_mcv.register == .x0) {
                // This argument is in x0 but should go to a later register
                // Save x0 to stack before we clobber it with arg0
                if (!saved_x0) {
                    try self.strSpOffset(.x0, saved_x0_offset);
                    self.next_spill_offset += 8;
                    saved_x0 = true;
                }
                // Update the tracking so getValue will return stack location
                try self.setResult(arg_id, .{ .stack = saved_x0_offset });
            }
        }

        // Third pass: load arguments in forward order (now safe since x0 conflicts are resolved)
        var reg_idx: usize = 0;
        for (args) |arg_id| {
            const arg_val = &self.func.values.items[arg_id];
            const arg_class = classifyType(self.type_reg, arg_val.type_idx);
            const needed = regsNeeded(arg_class);

            if (reg_idx + needed > arg_regs.len) break;

            switch (arg_class) {
                .by_pointer => {
                    // Large type: pass pointer to storage location
                    const arg_mcv = self.getValue(arg_id);
                    if (arg_mcv == .stack) {
                        // Value is on spill stack - pass pointer to that location
                        try self.addSpOffset(arg_regs[reg_idx], arg_mcv.stack);
                    } else {
                        // Fallback: try to pass pointer to local
                        const arg_val_args = arg_val.args();
                        if (arg_val_args.len > 0 and arg_val_args[0] < self.func.locals.len) {
                            const local_idx: u32 = @intCast(arg_val_args[0]);
                            const local = self.func.locals[local_idx];
                            const sp_offset = convertOffset(local.offset, self.stack_size);
                            try self.addSpOffset(arg_regs[reg_idx], sp_offset);
                        }
                    }
                    reg_idx += 1;
                },
                .double_reg => {
                    // Medium type: pass in 2 registers
                    const arg_mcv = self.getValue(arg_id);
                    if (arg_mcv == .stack) {
                        try self.ldrSpOffset(arg_regs[reg_idx], arg_mcv.stack);
                        try self.ldrSpOffset(arg_regs[reg_idx + 1], arg_mcv.stack + 8);
                    } else {
                        try self.loadToReg(arg_regs[reg_idx], arg_mcv);
                    }
                    reg_idx += 2;
                },
                .slice => {
                    // Slice: always 2 registers (ptr + len)
                    try self.loadSliceToRegs(arg_val, arg_regs[reg_idx], arg_regs[reg_idx + 1]);
                    reg_idx += 2;
                },
                .single_reg => {
                    // Small type: single register
                    const arg_mcv = self.getValue(arg_id);
                    try self.loadToReg(arg_regs[reg_idx], arg_mcv);
                    reg_idx += 1;
                },
            }
        }

        // BL symbol
        const sym_name = if (self.os == .macos)
            try std.fmt.allocPrint(self.allocator, "_{s}", .{value.aux_str})
        else
            value.aux_str;
        try aarch64.callSymbol(self.buf, sym_name);

        // Handle result based on ABI class
        switch (ret_class) {
            .by_pointer => {
                try self.setResult(value.id, .{ .stack = large_result_offset });
            },
            .double_reg => {
                // Medium struct returned in x0+x1 - spill to stack
                const ret_size = self.type_reg.sizeOf(value.type_idx);
                const result_offset = self.next_spill_offset;
                try self.strSpOffset(.x0, result_offset);
                try self.strSpOffset(.x1, result_offset + 8);
                self.next_spill_offset += @intCast(alignTo(ret_size, 8));
                try self.setResult(value.id, .{ .stack = result_offset });
            },
            .single_reg => {
                self.reg_manager.markUsed(.x0, value.id);
                try self.setResult(value.id, .{ .register = .x0 });
            },
            .slice => {
                // Slice returned in x0+x1 - spill to stack so both parts are tracked
                const result_offset = self.next_spill_offset;
                try self.strSpOffset(.x0, result_offset);
                try self.strSpOffset(.x1, result_offset + 8);
                self.next_spill_offset += 16;
                try self.setResult(value.id, .{ .stack = result_offset });
            },
        }
    }

    /// Generate field access from local variable.
    /// args[0] = local index (raw), aux_int = field offset
    pub fn genFieldLocal(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const local_idx = args[0];
        if (local_idx >= self.func.locals.len) return;

        const field_offset: i32 = @intCast(value.aux_int);
        const size = self.type_reg.sizeOf(value.type_idx);
        const local = self.func.locals[@intCast(local_idx)];
        const sp_offset = convertOffset(local.offset + field_offset, self.stack_size);

        // For slice/string fields (16 bytes), record stack location instead of loading
        if (size == 16) {
            try self.setResult(value.id, .{ .stack = sp_offset });
            return;
        }

        // Always use x0 for field results (genStore expects this)
        const dest: aarch64.Reg = .x0;

        // Use correct load width based on type size
        switch (size) {
            1 => try self.ldrbSpOffset(dest, sp_offset),
            2 => try self.ldrhSpOffset(dest, sp_offset),
            4 => try self.ldrwSpOffset(dest, sp_offset),
            else => try self.ldrSpOffset(dest, sp_offset),
        }

        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate field access from SSA value (e.g., function call result).
    /// args[0] = SSA value ref (base address), aux_int = field offset
    pub fn genFieldValue(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const field_offset: i32 = @intCast(value.aux_int);
        const size = self.type_reg.sizeOf(value.type_idx);

        // Get the base value's location
        const base_mcv = self.getValue(args[0]);

        // Always use x0 for field results
        const dest: aarch64.Reg = .x0;

        switch (base_mcv) {
            .register => |reg| {
                // Base address is in a register
                const field_scaled: u12 = @intCast(@divExact(@as(u32, @intCast(field_offset)), 8));
                if (size == 1) {
                    try aarch64.ldrbRegImm(self.buf, dest, reg, @intCast(field_offset));
                } else {
                    try aarch64.ldrRegImm(self.buf, dest, reg, field_scaled);
                }
            },
            .stack => |stack_offset| {
                // Base is on stack - load address first, then load field
                try self.ldrSpOffset(.x8, stack_offset);
                const field_scaled: u12 = @intCast(@divExact(@as(u32, @intCast(field_offset)), 8));
                if (size == 1) {
                    try aarch64.ldrbRegImm(self.buf, dest, .x8, @intCast(field_offset));
                } else {
                    try aarch64.ldrRegImm(self.buf, dest, .x8, field_scaled);
                }
            },
            else => {
                // Fallback - assume address in x0
                const field_scaled: u12 = @intCast(@divExact(@as(u32, @intCast(field_offset)), 8));
                if (size == 1) {
                    try aarch64.ldrbRegImm(self.buf, dest, .x0, @intCast(field_offset));
                } else {
                    try aarch64.ldrRegImm(self.buf, dest, .x0, field_scaled);
                }
            },
        }

        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = dest });
    }

    pub fn genNot(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        const src_mcv = self.getValue(args[0]);

        const dest = try self.allocReg(value.id);
        try self.loadToReg(dest, src_mcv);

        // XOR with 1 to flip the boolean
        try aarch64.movRegImm64(self.buf, scratch1, 1);
        try aarch64.eorRegReg(self.buf, dest, dest, scratch1);

        try self.setResult(value.id, .{ .register = dest });
    }

    pub fn genAnd(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();

        const dest = try self.allocReg(value.id);
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        try self.loadToReg(dest, left_mcv);
        try self.loadToReg(scratch1, right_mcv);
        try aarch64.andRegReg(self.buf, dest, dest, scratch1);

        self.freeDeadOperands(value);
        try self.setResult(value.id, .{ .register = dest });
    }

    pub fn genOr(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();

        const dest = try self.allocReg(value.id);
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        try self.loadToReg(dest, left_mcv);
        try self.loadToReg(scratch1, right_mcv);
        try aarch64.orrRegReg(self.buf, dest, dest, scratch1);

        self.freeDeadOperands(value);
        try self.setResult(value.id, .{ .register = dest });
    }

    pub fn genSelect(self: *CodeGen, value: *ssa.Value) !void {
        // select: args[0] = condition, args[1] = true_val, args[2] = false_val
        const args = value.args();
        if (args.len < 3) return;

        const ret_type = self.type_reg.get(value.type_idx);
        const is_slice = (ret_type == .slice);

        if (is_slice) {
            // Slice select: need to handle both ptr and len
            // Use x9 for condition to avoid clobbering x16/x17 which we use for true values
            const cond_mcv = self.getValue(args[0]);
            const true_mcv = self.getValue(args[1]);
            const false_mcv = self.getValue(args[2]);

            // Load condition to x9 (not scratch0=x16, which we need for true ptr)
            try self.loadToReg(.x9, cond_mcv);

            // Allocate stack space for result
            const result_offset = self.next_spill_offset;
            self.next_spill_offset += 16;

            // Load true ptr (x16) and len (x17)
            switch (true_mcv) {
                .stack => |offset| {
                    // Offset is already sp-relative (from spill slots)
                    try self.ldrSpOffset(.x16, offset);
                    try self.ldrSpOffset(.x17, offset + 8);
                },
                .lea_symbol => |sym| {
                    try aarch64.loadSymbolAddr(self.buf, .x16, sym.name);
                    try aarch64.movRegImm64(self.buf, .x17, @intCast(sym.len));
                },
                else => {
                    try self.loadToReg(.x16, true_mcv);
                    try aarch64.movRegImm64(self.buf, .x17, 0);
                },
            }

            // Load false ptr (x10) and len (x11)
            switch (false_mcv) {
                .stack => |offset| {
                    // Offset is already sp-relative (from spill slots)
                    try self.ldrSpOffset(.x10, offset);
                    try self.ldrSpOffset(.x11, offset + 8);
                },
                .lea_symbol => |sym| {
                    try aarch64.loadSymbolAddr(self.buf, .x10, sym.name);
                    try aarch64.movRegImm64(self.buf, .x11, @intCast(sym.len));
                },
                else => {
                    try self.loadToReg(.x10, false_mcv);
                    try aarch64.movRegImm64(self.buf, .x11, 0);
                },
            }

            // CMP x9, #0
            try aarch64.cmpRegImm12(self.buf, .x9, 0);
            // CSEL for ptr: x16 = (cond != 0) ? x16 : x10
            try aarch64.csel(self.buf, .x16, .x16, .x10, .ne);
            // CSEL for len: x17 = (cond != 0) ? x17 : x11
            try aarch64.csel(self.buf, .x17, .x17, .x11, .ne);

            // Store result to stack
            try self.strSpOffset(.x16, result_offset);
            try self.strSpOffset(.x17, result_offset + 8);

            self.freeDeadOperands(value);
            try self.setResult(value.id, .{ .stack = result_offset });
        } else {
            // Regular single-value select
            // Allocate dest FIRST, then get MCValues (allocReg may spill operand regs)
            const dest = try self.allocReg(value.id);
            const cond_mcv = self.getValue(args[0]);
            const true_mcv = self.getValue(args[1]);
            const false_mcv = self.getValue(args[2]);

            // Load condition and check if non-zero
            try self.loadToReg(scratch0, cond_mcv);
            try self.loadToReg(dest, true_mcv);
            try self.loadToReg(scratch1, false_mcv);

            // CMP scratch0, #0
            try aarch64.cmpRegImm12(self.buf, scratch0, 0);
            // CSEL dest, dest, scratch1, NE (if cond != 0, keep true_val, else use false_val)
            try aarch64.csel(self.buf, dest, dest, scratch1, .ne);

            self.freeDeadOperands(value);
            try self.setResult(value.id, .{ .register = dest });
        }
    }

    /// Generate index into local array/slice.
    /// args[0] = local index (raw), args[1] = index value (SSA ref), aux_int = element size
    pub fn genIndexLocal(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        const local_idx = args[0];
        if (local_idx >= self.func.locals.len) return;

        const elem_size: i64 = if (value.aux_int != 0) value.aux_int else 8;
        const idx_mcv = self.getValue(args[1]);

        // Load index into x9
        try self.loadToReg(.x9, idx_mcv);

        // Calculate offset: index * elem_size -> x9
        if (elem_size > 1) {
            try aarch64.movRegImm64(self.buf, .x10, elem_size);
            try aarch64.mulRegReg(self.buf, .x9, .x9, .x10);
        }

        const local = self.func.locals[@intCast(local_idx)];
        const base_sp = convertOffset(local.offset, self.stack_size);

        // Add base offset: x9 = x9 + base_sp
        try aarch64.movRegImm64(self.buf, .x10, base_sp);
        try aarch64.addRegReg(self.buf, .x9, .x9, .x10);

        // Load from [sp + x9] -> x0
        try aarch64.ldrRegReg(self.buf, .x0, .sp, .x9);

        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    /// Generate index into SSA value (chained access like container.content[i]).
    /// args[0] = SSA value ref (base slice/array), args[1] = index value (SSA ref), aux_int = element size
    pub fn genIndexValue(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        const elem_size: i64 = if (value.aux_int != 0) value.aux_int else 8;
        const idx_mcv = self.getValue(args[1]);

        // Load index into x9
        try self.loadToReg(.x9, idx_mcv);

        // Calculate offset: index * elem_size -> x9
        if (elem_size > 1) {
            try aarch64.movRegImm64(self.buf, .x10, elem_size);
            try aarch64.mulRegReg(self.buf, .x9, .x9, .x10);
        }

        // Get the base value's location (should be a slice with ptr+len)
        const base_mcv = self.getValue(args[0]);

        switch (base_mcv) {
            .stack => |stack_offset| {
                // Slice is on stack: ptr at stack_offset, len at stack_offset+8
                // Load ptr into x8
                try self.ldrSpOffset(.x8, stack_offset);
                // Add index offset: x8 = x8 + x9
                try aarch64.addRegReg(self.buf, .x8, .x8, .x9);
                // Load from [x8] -> x0
                if (elem_size == 1) {
                    try aarch64.ldrbRegImm(self.buf, .x0, .x8, 0);
                } else {
                    try aarch64.ldrRegImm(self.buf, .x0, .x8, 0);
                }
            },
            .register => |reg| {
                // Base ptr is in a register
                // Add index offset: x8 = reg + x9
                try aarch64.addRegReg(self.buf, .x8, reg, .x9);
                if (elem_size == 1) {
                    try aarch64.ldrbRegImm(self.buf, .x0, .x8, 0);
                } else {
                    try aarch64.ldrRegImm(self.buf, .x0, .x8, 0);
                }
            },
            else => {
                // Fallback - shouldn't happen
                try aarch64.movRegImm64(self.buf, .x0, 0);
            },
        }

        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    pub fn genAddr(self: *CodeGen, value: *ssa.Value) !void {
        // addr: args[0] = local index
        const args = value.args();
        if (args.len == 0) return;

        const local_idx = args[0];
        if (local_idx >= self.func.locals.len) return;

        const local = self.func.locals[@intCast(local_idx)];
        const sp_offset = convertOffset(local.offset, self.stack_size);

        const dest = try self.allocReg(value.id);

        // ADD dest, sp, #offset
        try self.addSpOffset(dest, sp_offset);

        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate slice from local array/slice.
    /// args[0] = local index (raw), args[1] = start, args[2] = end. aux_int = elem_size
    pub fn genSliceLocal(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 3) return;

        const local_idx = args[0];
        if (local_idx >= self.func.locals.len) return;

        const local = self.func.locals[@intCast(local_idx)];
        const base_sp = convertOffset(local.offset, self.stack_size);
        const elem_size: i64 = if (value.aux_int != 0) value.aux_int else 8;
        const local_size = local.size;

        const start_mcv = self.getValue(args[1]);
        const end_mcv = self.getValue(args[2]);

        // Check if source is a string/slice (16 bytes = ptr+len) or array (inline data)
        if (local_size == 16) {
            // String/slice: load the ptr from local into x8
            try self.ldrSpOffset(.x8, base_sp);
        } else {
            // Array: base address is the stack location itself
            try self.addSpOffset(.x8, base_sp);
        }

        // Get start value into x9
        try self.loadToReg(.x9, start_mcv);

        // Get end value into x10
        try self.loadToReg(.x10, end_mcv);

        // Compute len = end - start -> x1
        try aarch64.subRegReg(self.buf, .x1, .x10, .x9);

        // Compute ptr = base + start * elem_size -> x0
        try aarch64.movRegImm64(self.buf, .x11, elem_size);
        try aarch64.mulRegReg(self.buf, .x11, .x9, .x11);
        try aarch64.addRegReg(self.buf, .x0, .x8, .x11);

        // Result is in x0 (ptr) and x1 (len) - mark as used
        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    /// Generate slice from SSA value (e.g., state.content[0:2]).
    /// args[0] = SSA value ref (base slice), args[1] = start, args[2] = end. aux_int = elem_size
    pub fn genSliceValue(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 3) return;

        const elem_size: i64 = if (value.aux_int != 0) value.aux_int else 8;
        const base_mcv = self.getValue(args[0]);
        const start_mcv = self.getValue(args[1]);
        const end_mcv = self.getValue(args[2]);

        // Load base slice ptr into x8
        switch (base_mcv) {
            .stack => |stack_offset| {
                // Slice is on stack: ptr at stack_offset
                try self.ldrSpOffset(.x8, stack_offset);
            },
            .register => |reg| {
                // Base ptr is in a register
                try aarch64.movRegReg(self.buf, .x8, reg);
            },
            else => {
                // Fallback - shouldn't happen
                try aarch64.movRegImm64(self.buf, .x8, 0);
            },
        }

        // Get start value into x9
        try self.loadToReg(.x9, start_mcv);

        // Get end value into x10
        try self.loadToReg(.x10, end_mcv);

        // Compute len = end - start -> x1
        try aarch64.subRegReg(self.buf, .x1, .x10, .x9);

        // Compute ptr = base + start * elem_size -> x0
        try aarch64.movRegImm64(self.buf, .x11, elem_size);
        try aarch64.mulRegReg(self.buf, .x11, .x9, .x11);
        try aarch64.addRegReg(self.buf, .x0, .x8, .x11);

        // Result is in x0 (ptr) and x1 (len) - mark as used
        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    pub fn genSliceIndex(self: *CodeGen, value: *ssa.Value) !void {
        // slice_index: args[0] = slice local, args[1] = index
        // aux_int = element size
        // Slice is stored as (ptr, len) at local offset
        // Result always in x0 (archive pattern)
        const args = value.args();
        if (args.len < 2) return;

        const local_idx = args[0];
        if (local_idx >= self.func.locals.len) return;

        const local = self.func.locals[@intCast(local_idx)];
        const sp_offset = convertOffset(local.offset, self.stack_size);
        const elem_size: i64 = if (value.aux_int != 0) value.aux_int else 8;

        const idx_mcv = self.getValue(args[1]);

        // Load slice ptr from local (first 8 bytes of slice) into x8
        try self.ldrSpOffset(.x8, sp_offset);

        // Get index value into x9
        try self.loadToReg(.x9, idx_mcv);

        // Multiply index by element size: x9 = x9 * elem_size
        try aarch64.movRegImm64(self.buf, .x10, elem_size);
        try aarch64.mulRegReg(self.buf, .x9, .x9, .x10);

        // Add to ptr: x8 = x8 + x9
        try aarch64.addRegReg(self.buf, .x8, .x8, .x9);

        // Load value from [x8] based on element size
        if (elem_size == 1) {
            // Byte load: ldrb x0, [x8]
            try aarch64.ldrbRegImm(self.buf, .x0, .x8, 0);
        } else {
            // 64-bit load: ldr x0, [x8, #0]
            try aarch64.ldrRegImm(self.buf, .x0, .x8, 0);
        }

        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    /// Generate code for union_tag: extract tag from union
    /// CRITICAL: args[0] can be a local index OR an SSA value reference
    /// IMPORTANT: Always spill to stack immediately after loading, because union_payload
    /// in other branches may call spillReg(x0) which corrupts the tracking for values
    /// that are used across multiple control flow paths.
    pub fn genUnionTag(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const maybe_local_or_ssa = args[0];

        // Determine source offset for the union tag
        var src_offset: ?u32 = null;

        // If args[0] is an SSA value, check its MCValue location
        if (maybe_local_or_ssa < self.func.values.items.len) {
            const union_val = &self.func.values.items[maybe_local_or_ssa];

            // First check if we have a tracked MCValue for this union
            const mcv = self.getValue(maybe_local_or_ssa);
            if (mcv == .stack) {
                // Union is on stack at this offset - tag is at offset 0
                src_offset = mcv.stack;
            } else if (union_val.op == .load) {
                // The load's local index is in args[0], not aux_int
                const load_args = union_val.args();
                if (load_args.len > 0) {
                    const local_idx: usize = @intCast(load_args[0]);
                    if (local_idx < self.func.locals.len) {
                        const local = self.func.locals[local_idx];
                        src_offset = convertOffset(local.offset, self.stack_size);
                    }
                }
            }
        }

        // Fallback: treat as direct local index (legacy behavior)
        if (src_offset == null and maybe_local_or_ssa < self.func.locals.len) {
            const local = self.func.locals[@intCast(maybe_local_or_ssa)];
            src_offset = convertOffset(local.offset, self.stack_size);
        }

        if (src_offset) |offset| {
            // Load tag into x0
            try self.ldrSpOffset(.x0, offset);

            // CRITICAL: Immediately spill to stack to ensure consistent location
            // across all control flow paths. This prevents corruption when
            // genUnionPayload in another branch calls spillReg(x0).
            const spill_offset = self.next_spill_offset;
            self.next_spill_offset += 8;
            try self.strSpOffset(.x0, spill_offset);

            // Record result as stack location (not register)
            try self.setResult(value.id, .{ .stack = spill_offset });
        }
    }

    /// Generate code for union_payload: extract payload from union (at offset 8)
    /// CRITICAL: args[0] can be a local index OR an SSA value reference
    pub fn genUnionPayload(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const maybe_local_or_ssa = args[0];

        // Spill x0 if it's holding a live value (e.g., union_tag result)
        // This is critical because both union_tag and union_payload use x0
        try self.spillReg(.x0);

        // If args[0] is an SSA value, check its MCValue location
        if (maybe_local_or_ssa < self.func.values.items.len) {
            const union_val = &self.func.values.items[maybe_local_or_ssa];

            // First check if we have a tracked MCValue for this union
            const mcv = self.getValue(maybe_local_or_ssa);

            // Get the payload size
            const payload_size = self.type_reg.sizeOf(value.type_idx);

            if (mcv == .stack) {
                // Union is on stack at this offset - payload is at offset +8
                const payload_offset = mcv.stack + 8;

                if (payload_size > 8) {
                    // Large payload - return stack reference to payload location
                    try self.setResult(value.id, .{ .stack = payload_offset });
                    return;
                }

                try self.ldrSpOffset(.x0, payload_offset);
                self.reg_manager.markUsed(.x0, value.id);
                try self.setResult(value.id, .{ .register = .x0 });
                return;
            }

            if (union_val.op == .load) {
                // The load's local index is in args[0], not aux_int
                const load_args = union_val.args();
                if (load_args.len == 0) return;
                const local_idx: usize = @intCast(load_args[0]);
                if (local_idx < self.func.locals.len) {
                    const local = self.func.locals[local_idx];
                    const payload_offset = convertOffset(local.offset + 8, self.stack_size);

                    if (payload_size > 8) {
                        // Large payload - return stack reference to payload location
                        try self.setResult(value.id, .{ .stack = payload_offset });
                        return;
                    }

                    // Load payload into x0
                    try self.ldrSpOffset(.x0, payload_offset);
                    self.reg_manager.markUsed(.x0, value.id);
                    try self.setResult(value.id, .{ .register = .x0 });
                    return;
                }
            }
        }

        // Fallback: treat as direct local index (legacy behavior)
        if (maybe_local_or_ssa < self.func.locals.len) {
            const local = self.func.locals[@intCast(maybe_local_or_ssa)];
            const payload_offset = convertOffset(local.offset + 8, self.stack_size);
            const payload_size = self.type_reg.sizeOf(value.type_idx);

            if (payload_size > 8) {
                // Large payload - return stack reference
                try self.setResult(value.id, .{ .stack = payload_offset });
                return;
            }

            try self.ldrSpOffset(.x0, payload_offset);
            self.reg_manager.markUsed(.x0, value.id);
            try self.setResult(value.id, .{ .register = .x0 });
        }
    }

    /// Generate code for union_init: create tagged union value
    /// aux_int = variant index (tag), args[0] = payload value (if any)
    /// Result: x0 = tag, x1 = payload (for 16-byte store)
    pub fn genUnionInit(self: *CodeGen, value: *ssa.Value) !void {
        const variant_idx: i64 = value.aux_int;
        const args = value.args();

        // Get the union's total size to determine how to handle it
        const union_size = self.type_reg.sizeOf(value.type_idx);

        // For large unions (> 16 bytes), build on stack
        if (union_size > 16) {
            // Allocate stack space for the union
            const dest_offset = self.next_spill_offset;
            self.next_spill_offset +|= @intCast(alignTo(union_size, 8));

            // Store tag at offset 0
            try aarch64.movRegImm64(self.buf, scratch0, variant_idx);
            try self.strSpOffset(scratch0, dest_offset);

            // If there's a payload, copy it to offset 8
            if (args.len > 0) {
                const payload_val = &self.func.values.items[args[0]];
                const payload_mcv = self.getValue(args[0]);
                const payload_size = self.type_reg.sizeOf(payload_val.type_idx);

                if (payload_mcv == .stack) {
                    // Payload is on stack - copy it
                    var copied: u32 = 0;
                    while (copied < payload_size) {
                        const src_off = payload_mcv.stack + copied;
                        const dst_off = dest_offset + 8 + copied;
                        try self.ldrSpOffset(scratch0, src_off);
                        try self.strSpOffset(scratch0, dst_off);
                        copied += 8;
                    }
                } else if (payload_val.op == .const_int) {
                    // Constant payload - store directly
                    try aarch64.movRegImm64(self.buf, scratch0, payload_val.aux_int);
                    try self.strSpOffset(scratch0, dest_offset + 8);
                } else if (payload_mcv == .register) {
                    // Payload in a register (small value)
                    try self.strSpOffset(payload_mcv.register, dest_offset + 8);
                }
            }

            // Result is on stack
            try self.setResult(value.id, .{ .stack = dest_offset });
            return;
        }

        // If there's a payload, get its MCValue first (before any spilling)
        if (args.len > 0) {
            const payload_val = &self.func.values.items[args[0]];
            const payload_mcv = self.getValue(args[0]);

            if (payload_val.op == .const_int) {
                // Payload is constant - safe to spill x0 and load both directly
                try self.spillReg(.x0);
                try aarch64.movRegImm64(self.buf, .x0, variant_idx);
                try aarch64.movRegImm64(self.buf, .x1, payload_val.aux_int);
            } else if (payload_mcv == .register and payload_mcv.register == .x0) {
                // Payload is in x0 - save to x1 BEFORE spilling anything
                try aarch64.movRegReg(self.buf, .x1, .x0); // save payload to x1
                try aarch64.movRegImm64(self.buf, .x0, variant_idx); // load tag to x0
            } else {
                // Payload is elsewhere (stack, other register) - spill x0 and load properly
                try self.spillReg(.x0);
                try self.loadToReg(.x1, payload_mcv); // load payload to x1
                try aarch64.movRegImm64(self.buf, .x0, variant_idx); // load tag to x0
            }
        } else {
            // No payload - just set tag
            try self.spillReg(.x0);
            try aarch64.movRegImm64(self.buf, .x0, variant_idx);
            try aarch64.movRegImm64(self.buf, .x1, 0); // zero payload
        }

        // Result: x0 = tag, x1 = payload
        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    /// Generate code for list_get: call runtime cot_list_get(handle, index)
    /// For elements <= 8 bytes: result is the value in x0
    /// For elements > 8 bytes: result is a pointer to the element in x0, copy to stack
    pub fn genListGet(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        // Spill x0 before we overwrite it with the result
        try self.spillReg(.x0);

        // Load handle into x0 via MCValue
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.x0, handle_mcv);

        // Load index into x1 via MCValue
        const idx_mcv = self.getValue(args[1]);
        try self.loadToReg(.x1, idx_mcv);

        try aarch64.callSymbol(self.buf, "_cot_list_get");

        // Check if element type is > 8 bytes (returns pointer)
        const elem_size = self.type_reg.sizeOf(value.type_idx);
        if (elem_size > 8) {
            // x0 contains a pointer to the element, copy to stack
            const dest_offset = self.next_spill_offset;
            self.next_spill_offset +|= @intCast(alignTo(elem_size, 8));

            // x0 = pointer to element, copy to [sp + dest_offset]
            var copied: u32 = 0;
            while (copied < elem_size) {
                // Load 8 bytes from source pointer
                try aarch64.ldrRegImm(self.buf, scratch0, .x0, @intCast(copied));
                // Store to stack
                const stack_off = dest_offset + copied;
                try self.strSpOffset(scratch0, stack_off);
                copied += 8;
            }

            // Result is now on stack
            try self.setResult(value.id, .{ .stack = dest_offset });
        } else {
            // Small element - value is directly in x0
            self.reg_manager.markUsed(.x0, value.id);
            try self.setResult(value.id, .{ .register = .x0 });
        }
    }

    pub fn genMapGet(self: *CodeGen, value: *ssa.Value) !void {
        // map_get: args[0] = handle, args[1] = key
        // Uses MCValue for handle, special handling for string keys
        // For large struct values (> 8 bytes), uses cot_map_get_struct with destination pointer
        const args = value.args();
        if (args.len < 2) return;

        try self.spillCallerSaved();

        // Check if value type is a large struct (> 8 bytes)
        const value_size = self.type_reg.sizeOf(value.type_idx);
        const is_large_struct = value_size > 8;

        // Load key FIRST to avoid clobbering handle
        // Check if key is a slice (string key)
        const key_val = &self.func.values.items[args[1]];
        const key_type = self.type_reg.get(key_val.type_idx);
        if (key_type == .slice) {
            // String key: load directly based on op type
            if (key_val.op == .const_slice) {
                // Regenerate const_slice into x1/x2
                const string_idx: usize = @intCast(key_val.aux_int);
                if (string_idx < self.string_infos.len) {
                    const info = self.string_infos[string_idx];
                    try aarch64.loadSymbolAddr(self.buf, .x1, info.symbol_name);
                    try aarch64.movRegImm64(self.buf, .x2, @intCast(info.len));
                }
            } else {
                // Load slice from stack or other location
                try self.loadSliceToRegs(key_val, .x1, .x2);
            }
        } else {
            const key_mcv = self.getValue(args[1]);
            try self.loadToReg(.x1, key_mcv);
        }

        // Load map handle into x0 AFTER loading key to avoid clobber
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.x0, handle_mcv);

        if (is_large_struct) {
            // Large struct value: use cot_map_get_struct
            // Allocate temp stack slot for the result
            const spill_offset = self.next_spill_offset;
            self.next_spill_offset +|= @intCast(alignTo(value_size, 8));

            // x0 = handle (already loaded)
            // x1/x2 = key ptr/len (already loaded)
            // x3 = destination pointer (our temp slot)
            // x4 = value size
            try self.addSpOffset(.x3, spill_offset);
            try aarch64.movRegImm64(self.buf, .x4, @intCast(value_size));

            const func_name = if (self.os == .macos) "_cot_map_get_struct" else "cot_map_get_struct";
            try aarch64.callSymbol(self.buf, func_name);

            // Result is now in the temp slot
            try self.setResult(value.id, .{ .stack = spill_offset });
        } else {
            // Small value: use regular cot_map_get
            const func_name = if (self.os == .macos) "_cot_map_get" else "cot_map_get";
            try aarch64.callSymbol(self.buf, func_name);

            self.reg_manager.markUsed(.x0, value.id);
            try self.setResult(value.id, .{ .register = .x0 });
        }
    }

    fn emitRuntimeCall(self: *CodeGen, name: []const u8) !void {
        // BL to runtime function (will be relocated by linker)
        // For now, emit a placeholder that gets patched
        // The actual symbol resolution happens at link time
        _ = name;
        // Emit BL with 0 offset - linker will fix it up
        try aarch64.bl(self.buf, 0);
    }

    /// Generate code for arg: load function parameter from local slot
    /// Parameters are spilled to local slots in the prologue
    pub fn genArg(self: *CodeGen, value: *ssa.Value) !void {
        const param_idx: u32 = @intCast(value.aux_int);
        if (param_idx >= self.func.locals.len) return;

        const local = self.func.locals[param_idx];
        const sp_offset = convertOffset(local.offset, self.stack_size);
        const dest = try self.allocReg(value.id);

        // Load from the parameter's local slot
        try self.ldrSpOffset(dest, sp_offset);

        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate code for map_new: create new map via runtime call
    pub fn genMapNew(self: *CodeGen, value: *ssa.Value) !void {
        try aarch64.callSymbol(self.buf, "_cot_map_new");
        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    /// Generate code for map_set: args[0]=handle, args[1]=key_ptr, args[2]=key_len, args[3]=value
    /// or args[0]=handle, args[1]=key (slice), args[2]=value (legacy)
    /// Uses MCValue for handle and value, special handling for string keys
    /// For large struct values (> 8 bytes), uses cot_map_set_struct with value pointer
    pub fn genMapSet(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 3) return;

        try self.spillCallerSaved();

        // Determine which arg is the value and check if it's a large struct
        const val_arg_idx: usize = if (args.len >= 4 and args[1] != args[2]) 3 else if (args.len >= 4) 3 else 2;
        const val_value = &self.func.values.items[args[val_arg_idx]];
        const val_size = self.type_reg.sizeOf(val_value.type_idx);
        const is_large_struct = val_size > 8;

        // Check if we have 4 args (handle, key_ptr, key_len, value) with distinct ptr/len
        if (args.len >= 4 and args[1] != args[2]) {
            // 4 args: key_ptr and key_len are separate
            if (is_large_struct) {
                // Large struct: pass value pointer + size instead of value
                const val_mcv = self.getValue(args[3]);
                if (val_mcv == .stack) {
                    // Value is on stack - compute its address
                    try self.addSpOffset(.x3, val_mcv.stack);
                } else {
                    // Value in register (shouldn't happen for large struct, but handle it)
                    try self.loadToReg(.x3, val_mcv);
                }
                try aarch64.movRegImm64(self.buf, .x4, @intCast(val_size));
            } else {
                // Load value into x3 FIRST (before key and handle to avoid clobber)
                const val_mcv = self.getValue(args[3]);
                try self.loadToReg(.x3, val_mcv);
            }

            // Load key_len into x2
            const key_len_mcv = self.getValue(args[2]);
            try self.loadToReg(.x2, key_len_mcv);

            // Load key_ptr into x1
            const key_ptr_mcv = self.getValue(args[1]);
            try self.loadToReg(.x1, key_ptr_mcv);

            // Load map handle into x0 LAST
            const handle_mcv = self.getValue(args[0]);
            try self.loadToReg(.x0, handle_mcv);
        } else {
            // 3 args or 4 args with same ptr/len (const_slice): key is a single value

            // Load key FIRST to avoid clobbering
            const key_val = &self.func.values.items[args[1]];
            const key_type = self.type_reg.get(key_val.type_idx);
            if (key_type == .slice) {
                // String key: load directly based on op type
                if (key_val.op == .const_slice) {
                    // Regenerate const_slice into x1/x2
                    const string_idx: usize = @intCast(key_val.aux_int);
                    if (string_idx < self.string_infos.len) {
                        const info = self.string_infos[string_idx];
                        try aarch64.loadSymbolAddr(self.buf, .x1, info.symbol_name);
                        try aarch64.movRegImm64(self.buf, .x2, @intCast(info.len));
                    }
                } else {
                    // Load slice from stack or other location
                    try self.loadSliceToRegs(key_val, .x1, .x2);
                }
            } else {
                const key_mcv = self.getValue(args[1]);
                try self.loadToReg(.x1, key_mcv);
            }

            if (is_large_struct) {
                // Large struct: pass value pointer + size
                const val_mcv = self.getValue(args[val_arg_idx]);
                if (val_mcv == .stack) {
                    // Value is on stack - compute its address
                    try self.addSpOffset(.x3, val_mcv.stack);
                } else {
                    // Value in register (shouldn't happen for large struct, but handle it)
                    try self.loadToReg(.x3, val_mcv);
                }
                try aarch64.movRegImm64(self.buf, .x4, @intCast(val_size));
            } else {
                // Load value into x3 BEFORE handle (x3 won't be clobbered by handle load)
                const val_mcv = self.getValue(args[val_arg_idx]);
                try self.loadToReg(.x3, val_mcv);
            }

            // Load map handle into x0 LAST to avoid clobber
            const handle_mcv = self.getValue(args[0]);
            try self.loadToReg(.x0, handle_mcv);
        }

        if (is_large_struct) {
            const func_name = if (self.os == .macos) "_cot_map_set_struct" else "cot_map_set_struct";
            try aarch64.callSymbol(self.buf, func_name);
        } else {
            const func_name = if (self.os == .macos) "_cot_map_set" else "cot_map_set";
            try aarch64.callSymbol(self.buf, func_name);
        }
    }

    /// Generate code for map_has: args[0]=handle, args[1]=key
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
                // Regenerate const_slice into x1/x2
                const string_idx: usize = @intCast(key_val.aux_int);
                if (string_idx < self.string_infos.len) {
                    const info = self.string_infos[string_idx];
                    try aarch64.loadSymbolAddr(self.buf, .x1, info.symbol_name);
                    try aarch64.movRegImm64(self.buf, .x2, @intCast(info.len));
                }
            } else {
                // Load slice from stack or other location
                try self.loadSliceToRegs(key_val, .x1, .x2);
            }
        } else {
            const key_mcv = self.getValue(args[1]);
            try self.loadToReg(.x1, key_mcv);
        }

        // Load map handle into x0 AFTER loading key to avoid clobber
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.x0, handle_mcv);

        const func_name = if (self.os == .macos) "_cot_map_has" else "cot_map_has";
        try aarch64.callSymbol(self.buf, func_name);
        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    /// Generate code for map_size: args[0]=handle
    pub fn genMapSize(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.x0, handle_mcv);

        try aarch64.callSymbol(self.buf, "_cot_map_size");
        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    /// Generate code for map_free: args[0]=handle
    pub fn genMapFree(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.x0, handle_mcv);

        try aarch64.callSymbol(self.buf, "_cot_map_free");
    }

    /// Generate code for list_new: call cot_list_new(elem_size) runtime function
    pub fn genListNew(self: *CodeGen, value: *ssa.Value) !void {
        // Get element size from list type
        var elem_size: i64 = 8; // default to 8 bytes
        const list_type = self.type_reg.get(value.type_idx);
        if (list_type == .list_type) {
            elem_size = @intCast(self.type_reg.sizeOf(list_type.list_type.elem));
        }

        // Pass elem_size in x0
        try aarch64.movRegImm64(self.buf, .x0, elem_size);
        try aarch64.callSymbol(self.buf, "_cot_list_new");

        // x0 now has list handle
        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    /// Generate code for list_push: args[0]=handle, args[1]=value
    /// For small elements (<= 8 bytes): x0=handle, x1=value
    /// For large elements (> 8 bytes): x0=handle, x1=pointer to value
    pub fn genListPush(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        // Get the value's type to determine element size
        const value_ssa = &self.func.values.items[args[1]];
        const elem_size = self.type_reg.sizeOf(value_ssa.type_idx);

        const handle_mcv = self.getValue(args[0]);
        const val_mcv = self.getValue(args[1]);

        if (elem_size <= 8) {
            // Small element - pass value directly in x1
            // Handle register clobbering: if value is in x0, we must load it first
            if (val_mcv == .register and val_mcv.register == .x0) {
                // Value is in x0 - move it to x1 first
                try aarch64.movRegReg(self.buf, .x1, .x0);
                // Then load handle into x0
                try self.loadToReg(.x0, handle_mcv);
            } else {
                // Normal order: load handle to x0, then value to x1
                try self.loadToReg(.x0, handle_mcv);
                try self.loadToReg(.x1, val_mcv);
            }
        } else {
            // Large element - pass pointer in x1
            // Use MCValue to determine where the value actually is (not operation type)
            switch (val_mcv) {
                .stack => |stack_offset| {
                    // Value already on stack - use its address directly
                    try self.loadToReg(.x0, handle_mcv);
                    try self.addSpOffset(.x1, stack_offset);
                },
                .register => |reg| {
                    // Value in single register - need to copy to stack first
                    // This handles union_init results for 9-16 byte unions
                    const temp_offset = self.next_spill_offset;
                    self.next_spill_offset +|= @intCast(alignTo(elem_size, 8));

                    // For 16-byte unions, tag in x0, payload in x1
                    if (elem_size > 8 and elem_size <= 16 and value_ssa.op == .union_init) {
                        try self.strSpOffset(.x0, temp_offset);
                        try self.strSpOffset(.x1, temp_offset + 8);
                    } else {
                        try self.strSpOffset(reg, temp_offset);
                    }

                    try self.loadToReg(.x0, handle_mcv);
                    try self.addSpOffset(.x1, temp_offset);
                },
                else => {
                    // Unknown location - allocate temp and try to copy
                    const temp_offset = self.next_spill_offset;
                    self.next_spill_offset +|= @intCast(alignTo(elem_size, 8));
                    try self.loadToReg(.x0, handle_mcv);
                    try self.addSpOffset(.x1, temp_offset);
                },
            }
        }

        try aarch64.callSymbol(self.buf, "_cot_list_push");
    }

    /// Generate code for list_len: args[0]=handle
    pub fn genListLen(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        // Load handle into x0 via MCValue
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.x0, handle_mcv);

        try aarch64.callSymbol(self.buf, "_cot_list_len");

        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    /// Generate code for list_free: args[0]=handle
    pub fn genListFree(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        // Load handle into x0 via MCValue
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.x0, handle_mcv);

        try aarch64.callSymbol(self.buf, "_cot_list_free");
    }

    /// Generate code for str_concat: args[0]=left string, args[1]=right string
    /// Calls cot_str_concat(ptr1, len1, ptr2, len2) -> returns (ptr, len) in x0, x1
    pub fn genStrConcat(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        // Spill caller-saved registers
        try self.spillCallerSaved();

        // Load left string (ptr, len) to x0, x1
        const left_val = &self.func.values.items[args[0]];
        try self.loadSliceToRegs(left_val, .x0, .x1);

        // Load right string (ptr, len) to x2, x3
        const right_val = &self.func.values.items[args[1]];
        try self.loadSliceToRegs(right_val, .x2, .x3);

        // Call cot_str_concat(ptr1, len1, ptr2, len2)
        const func_name = if (self.os == .macos) "_cot_str_concat" else "cot_str_concat";
        try self.buf.addRelocation(.pc_rel_32, func_name, 0);
        try aarch64.bl(self.buf, 0);

        // Result is in x0 (ptr), x1 (len) - it's a slice
        // Save to a temp slot so other ops don't clobber it
        const temp_offset = self.next_spill_offset;
        self.next_spill_offset +|= 16; // 16 bytes for ptr+len
        try self.strSpOffset(.x0, temp_offset);
        try self.strSpOffset(.x1, temp_offset + 8);

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
                const sp_offset = convertOffset(local.offset, self.stack_size);
                try self.addSpOffset(dest, sp_offset);
            }
        } else {
            // Just return current stack pointer as address
            try aarch64.movRegReg(self.buf, dest, .sp);
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
        const field_offset: u12 = @intCast(@as(u32, @intCast(value.aux_int)));

        // Check if local is a struct parameter that was copied in prologue
        // If local.size > 8, it's an actual struct (not a pointer)
        const local_type = self.type_reg.get(local.type_idx);
        const is_struct_copy = (local_type == .struct_type);

        if (is_struct_copy) {
            // Local IS the struct (after prologue copy), access field directly
            const sp_offset = convertOffset(local.offset + @as(i32, @intCast(field_offset)), self.stack_size);

            const dest = try self.allocReg(value.id);
            const size = self.type_reg.sizeOf(value.type_idx);
            if (size == 1) {
                try self.ldrbSpOffset(dest, sp_offset);
            } else {
                try self.ldrSpOffset(dest, sp_offset);
            }
            try self.setResult(value.id, .{ .register = dest });
        } else {
            // Local is a pointer, dereference to access field
            const sp_offset = convertOffset(local.offset, self.stack_size);
            try self.ldrSpOffset(scratch0, sp_offset);

            const dest = try self.allocReg(value.id);
            try aarch64.ldrRegImm(self.buf, dest, scratch0, field_offset);
            try self.setResult(value.id, .{ .register = dest });
        }
    }

    pub fn genReturn(self: *CodeGen, block: *ssa.Block) !void {
        const ret_class = classifyType(self.type_reg, self.func.return_type);

        if (block.control != ssa.null_value) {
            const ret_val = &self.func.values.items[block.control];

            switch (ret_class) {
                .by_pointer => {
                    // Large struct return: copy result to address in x19 (saved from x8 in prologue)
                    const struct_size = self.type_reg.sizeOf(self.func.return_type);
                    const ret_mcv = self.getValue(block.control);

                    if (ret_mcv == .stack) {
                        // Result is in a spill slot - copy from there
                        var copied: u32 = 0;
                        while (copied < struct_size) {
                            const src_offset = ret_mcv.stack + copied;
                            try self.ldrSpOffset(scratch0, src_offset);
                            try aarch64.strRegImm(self.buf, scratch0, .x19, @intCast(copied));
                            copied += 8;
                        }
                    } else {
                        // Fallback: try to load from local if available
                        const args = ret_val.args();
                        if (args.len > 0 and args[0] < self.func.locals.len) {
                            const local_idx: u32 = @intCast(args[0]);
                            const local = self.func.locals[local_idx];
                            var copied: u32 = 0;
                            while (copied < struct_size) {
                                const src_offset = convertOffset(local.offset + @as(i32, @intCast(copied)), self.stack_size);
                                try self.ldrSpOffset(scratch0, src_offset);
                                try aarch64.strRegImm(self.buf, scratch0, .x19, @intCast(copied));
                                copied += 8;
                            }
                        }
                    }
                },
                .double_reg => {
                    // Medium struct (9-16 bytes): return in x0 + x1
                    // Use getValue to handle any MCValue (local, spill slot, etc.)
                    const ret_mcv = self.getValue(block.control);
                    if (ret_mcv == .stack) {
                        try self.ldrSpOffset(.x0, ret_mcv.stack);
                        try self.ldrSpOffset(.x1, ret_mcv.stack + 8);
                    } else {
                        // Fallback: try to load from local if available
                        const args = ret_val.args();
                        if (args.len > 0 and args[0] < self.func.locals.len) {
                            const local_idx: u32 = @intCast(args[0]);
                            const local = self.func.locals[local_idx];
                            const sp_offset = convertOffset(local.offset, self.stack_size);
                            try self.ldrSpOffset(.x0, sp_offset);
                            const sp_offset_plus8 = convertOffset(local.offset + 8, self.stack_size);
                            try self.ldrSpOffset(.x1, sp_offset_plus8);
                        }
                    }
                },
                .single_reg => {
                    // Small type: load to x0
                    const ret_mcv = self.getValue(block.control);
                    try self.loadToReg(.x0, ret_mcv);
                },
                .slice => {
                    // Slice: load ptr to x0, len to x1
                    const ret_mcv = self.getValue(block.control);
                    switch (ret_mcv) {
                        .stack => |offset| {
                            // Offset is already sp-relative (from spill during select/call)
                            // Don't use convertOffset - it expects fp-relative negative offsets
                            try self.ldrSpOffset(.x0, offset);
                            try self.ldrSpOffset(.x1, offset + 8);
                        },
                        .register => |reg| {
                            // Slice in register means it's already in x0/x1 (or needs move)
                            if (reg != .x0) {
                                try aarch64.movRegReg(self.buf, .x0, reg);
                            }
                            // Assume x1 is already set if this is a returned slice from a call
                        },
                        else => {
                            // Fallback - try to load to x0, might need more work for other cases
                            try self.loadToReg(.x0, ret_mcv);
                        },
                    }
                },
            }
        }

        // Epilogue: restore callee-saved registers, fp/lr, and deallocate stack frame

        // Restore ALL callee-saved registers (x19-x28) from stack
        // Must match prologue saves
        try aarch64.ldpSignedOffset(self.buf, .x19, .x20, .sp, 2); // sp+16
        try aarch64.ldpSignedOffset(self.buf, .x21, .x22, .sp, 4); // sp+32
        try aarch64.ldpSignedOffset(self.buf, .x23, .x24, .sp, 6); // sp+48
        try aarch64.ldpSignedOffset(self.buf, .x25, .x26, .sp, 8); // sp+64
        try aarch64.ldpSignedOffset(self.buf, .x27, .x28, .sp, 10); // sp+80

        // Restore fp/lr and deallocate stack frame
        // Must match prologue: small uses post-index, medium/large use separate add
        const stack_units = @divExact(self.stack_size, 8);

        if (stack_units <= 63) {
            // Small frame: single post-index instruction
            const stack_offset: i7 = @intCast(stack_units);
            try aarch64.ldpPostIndex(self.buf, .fp, .lr, .sp, stack_offset);
        } else if (self.stack_size <= 4095) {
            // Medium frame: ldp + add
            try aarch64.ldpSignedOffset(self.buf, .fp, .lr, .sp, 0);
            try aarch64.addRegImm12(self.buf, .sp, .sp, @intCast(self.stack_size));
        } else {
            // Large frame: ldp + mov + add
            try aarch64.ldpSignedOffset(self.buf, .fp, .lr, .sp, 0);
            try aarch64.movRegImm64(self.buf, .x16, @intCast(self.stack_size));
            try aarch64.addRegReg(self.buf, .sp, .sp, .x16);
        }
        try aarch64.ret(self.buf);
    }

    // ========================================================================
    // Main generation entry point
    // ========================================================================

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
            .field_local, .field => try self.genFieldLocal(value),
            .field_value => try self.genFieldValue(value),
            .not => try self.genNot(value),
            .@"and" => try self.genAnd(value),
            .@"or" => try self.genOr(value),
            .select => try self.genSelect(value),
            .index_local, .index => try self.genIndexLocal(value),
            .index_value => try self.genIndexValue(value),
            .addr => try self.genAddr(value),
            .slice_local, .slice_make => try self.genSliceLocal(value),
            .slice_value => try self.genSliceValue(value),
            .slice_index => try self.genSliceIndex(value),
            .union_tag => try self.genUnionTag(value),
            .union_payload => try self.genUnionPayload(value),
            .list_get => try self.genListGet(value),
            .map_get => try self.genMapGet(value),
            // Block terminators handled in genBlockEnd
            .ret, .jump, .branch => {},
            // Operations that don't produce values or are handled elsewhere
            .union_init => try self.genUnionInit(value), // Generate tag+payload in x0/x1
            .phi, .copy => {}, // Handled by register allocator
            .const_float => {}, // TODO: implement (floating point not yet supported)
            .alloc => try self.genAlloc(value),
            .ptr_field => try self.genPtrField(value),
            .map_new => try self.genMapNew(value),
            .map_set => try self.genMapSet(value),
            .map_has => try self.genMapHas(value),
            .map_size => try self.genMapSize(value),
            .map_free => try self.genMapFree(value),
            .list_new => try self.genListNew(value),
            .list_push => try self.genListPush(value),
            .list_len => try self.genListLen(value),
            .list_free => try self.genListFree(value),
            .str_concat => try self.genStrConcat(value),
            .arg => try self.genArg(value),
            .retain, .release, .@"unreachable" => {}, // TODO: implement
        }
    }

    pub fn genBlockEnd(self: *CodeGen, block: *ssa.Block) !void {
        switch (block.kind) {
            .ret => try self.genReturn(block),
            .plain, .@"if", .exit => {},
        }
    }

    pub fn genPrologue(self: *CodeGen) !void {
        // Allocate stack frame and save fp/lr
        // Three cases based on frame size:
        //   Small (≤504 bytes):  stp fp, lr, [sp, #-N]!
        //   Medium (≤4095 bytes): sub sp, sp, #N; stp fp, lr, [sp]
        //   Large (>4095 bytes):  mov x16, #N; sub sp, sp, x16; stp fp, lr, [sp]
        const stack_units = @divExact(self.stack_size, 8);

        if (stack_units <= 63) {
            // Small frame: single pre-index instruction
            const neg_offset: i7 = -@as(i7, @intCast(stack_units));
            try aarch64.stpPreIndex(self.buf, .fp, .lr, .sp, neg_offset);
        } else if (self.stack_size <= 4095) {
            // Medium frame: sub + stp
            try aarch64.subRegImm12(self.buf, .sp, .sp, @intCast(self.stack_size));
            try aarch64.stpSignedOffset(self.buf, .fp, .lr, .sp, 0);
        } else {
            // Large frame: load size to scratch register, sub, stp
            try aarch64.movRegImm64(self.buf, .x16, @intCast(self.stack_size));
            try aarch64.subRegReg(self.buf, .sp, .sp, .x16);
            try aarch64.stpSignedOffset(self.buf, .fp, .lr, .sp, 0);
        }
        // mov fp, sp
        try aarch64.movFromSp(self.buf, .fp);

        // Save ALL callee-saved registers (x19-x28) to stack
        // This is the simple approach - always save all, even if not used.
        // Layout: sp+16=x19/x20, sp+32=x21/x22, sp+48=x23/x24, sp+64=x25/x26, sp+80=x27/x28
        try aarch64.stpSignedOffset(self.buf, .x19, .x20, .sp, 2); // sp+16
        try aarch64.stpSignedOffset(self.buf, .x21, .x22, .sp, 4); // sp+32
        try aarch64.stpSignedOffset(self.buf, .x23, .x24, .sp, 6); // sp+48
        try aarch64.stpSignedOffset(self.buf, .x25, .x26, .sp, 8); // sp+64
        try aarch64.stpSignedOffset(self.buf, .x27, .x28, .sp, 10); // sp+80

        // For large struct returns (>16 bytes), save x8 (result pointer) to x19 (callee-saved)
        // x19 is now safe to use since we saved it above
        const ret_class = classifyType(self.type_reg, self.func.return_type);
        if (ret_class == .by_pointer) {
            try aarch64.movRegReg(self.buf, .x19, .x8);
            // Lock x19 so the register allocator won't use it for other purposes
            self.reg_manager.lock(.x19);
        }

        // Spill parameters to local slots using ABIClass for consistent decisions
        const param_regs = [_]aarch64.Reg{ .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7 };
        const num_params = self.func.param_count;

        var reg_idx: usize = 0;
        for (0..num_params) |param_idx| {
            if (param_idx >= self.func.locals.len or reg_idx >= param_regs.len) break;

            const local = self.func.locals[param_idx];
            const sp_offset = convertOffset(local.offset, self.stack_size);
            const param_class = classifyType(self.type_reg, local.type_idx);
            const needed = regsNeeded(param_class);

            if (reg_idx + needed > param_regs.len) break;

            switch (param_class) {
                .by_pointer => {
                    // Large type: register holds pointer to caller's copy
                    // Copy entire value from that address to our local slot
                    const src_addr = param_regs[reg_idx];
                    const param_size = local.size;
                    var copied: u32 = 0;
                    while (copied < param_size) {
                        const dst_offset = convertOffset(local.offset + @as(i32, @intCast(copied)), self.stack_size);
                        // Load from src_addr (small offset OK since it's from start of struct)
                        if (copied <= 4095) {
                            try aarch64.ldrRegImm(self.buf, scratch0, src_addr, @intCast(copied));
                        } else {
                            try aarch64.movRegImm64(self.buf, .x17, copied);
                            try aarch64.addRegReg(self.buf, .x17, src_addr, .x17);
                            try aarch64.ldrRegImm(self.buf, scratch0, .x17, 0);
                        }
                        try self.strSpOffset(scratch0, dst_offset);
                        copied += 8;
                    }
                    reg_idx += 1;
                },
                .double_reg, .slice => {
                    // Medium type or slice: 2 registers
                    try self.strSpOffset(param_regs[reg_idx], sp_offset);
                    const sp_offset_plus8 = convertOffset(local.offset + 8, self.stack_size);
                    try self.strSpOffset(param_regs[reg_idx + 1], sp_offset_plus8);
                    reg_idx += 2;
                },
                .single_reg => {
                    // Small type: single register
                    // Use appropriate store size based on type
                    const param_size = self.type_reg.sizeOf(local.type_idx);
                    if (param_size == 1) {
                        try self.strbSpOffset(param_regs[reg_idx], sp_offset);
                    } else {
                        try self.strSpOffset(param_regs[reg_idx], sp_offset);
                    }
                    reg_idx += 1;
                },
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

/// Convert rbp-relative offset (negative) to sp-relative offset (positive)
/// Returns u32 for large stack frames
fn convertOffset(rbp_offset: i32, stack_size: u32) u32 {
    // rbp points to saved fp/lr, locals are at negative offsets from rbp
    // sp is stack_size bytes below rbp
    // sp_offset = stack_size + rbp_offset (should be positive)
    const sp_offset = @as(i32, @intCast(stack_size)) + rbp_offset;
    if (sp_offset < 0) {
        std.debug.print("convertOffset error: rbp_offset={d}, stack_size={d}, sp_offset={d}\n", .{ rbp_offset, stack_size, sp_offset });
        @panic("negative sp_offset in convertOffset");
    }
    return @intCast(sp_offset);
}

// ============================================================================
// Tests
// ============================================================================

test "MCValue basics" {
    const imm = MCValue{ .immediate = 42 };
    try std.testing.expect(!imm.isRegister());

    const reg = MCValue{ .register = .x0 };
    try std.testing.expect(reg.isRegister());
}

test "RegisterManager allocation" {
    var rm = RegisterManager{};

    try std.testing.expect(rm.isFree(.x19));

    const reg = rm.tryAlloc(0);
    try std.testing.expect(reg != null);
    try std.testing.expect(!rm.isFree(reg.?));

    rm.markFree(reg.?);
    try std.testing.expect(rm.isFree(reg.?));
}
