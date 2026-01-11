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

// ============================================================================
// MCValue - Machine Code Value (where a value lives)
// ============================================================================

pub const MCValue = union(enum) {
    none,
    dead,
    immediate: i64,
    register: aarch64.Reg,
    stack: u12, // offset from sp (positive, ARM64 unsigned immediate)
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

    pub fn getStack(self: MCValue) ?u12 {
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
/// Callee-saved first (survive calls), then caller-saved.
pub const allocatable_regs = [_]aarch64.Reg{
    // Callee-saved (survive function calls)
    .x19, .x20, .x21, .x22, .x23, .x24, .x25, .x26, .x27, .x28,
    // Caller-saved (clobbered by calls)
    .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7,
    .x9, .x10, .x11, .x12, .x13, .x14, .x15,
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
    string_offsets: *std.StringHashMap(u32),
    next_spill_offset: u12,
    stack_size: u32,

    pub fn init(
        allocator: Allocator,
        buf: *be.CodeBuffer,
        func: *ssa.Func,
        type_reg: *types.TypeRegistry,
        os: be.OS,
        string_offsets: *std.StringHashMap(u32),
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
            .string_offsets = string_offsets,
            .next_spill_offset = @intCast(stack_size), // Spill slots start after locals
            .stack_size = stack_size,
        };
    }

    pub fn deinit(self: *CodeGen) void {
        self.tracking.deinit();
    }

    // ========================================================================
    // Core allocation functions
    // ========================================================================

    pub fn allocReg(self: *CodeGen, value_id: ?ssa.ValueID) !aarch64.Reg {
        if (self.reg_manager.tryAlloc(value_id)) |reg| {
            return reg;
        }

        const spill_reg = self.reg_manager.findSpillCandidate() orelse {
            return error.AllRegistersLocked;
        };

        try self.spillReg(spill_reg);

        if (value_id) |vid| {
            self.reg_manager.markUsed(spill_reg, vid);
        }
        return spill_reg;
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
        try aarch64.strRegImm(self.buf, reg, .sp, offset);

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
                try aarch64.ldrRegImm(self.buf, dest, .sp, offset);
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

    pub fn spillCallerSaved(self: *CodeGen) !void {
        const caller_saved = [_]aarch64.Reg{
            .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7,
            .x9, .x10, .x11, .x12, .x13, .x14, .x15,
        };

        for (caller_saved) |reg| {
            if (!self.reg_manager.isFree(reg)) {
                try self.spillReg(reg);
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

    pub fn genAdd(self: *CodeGen, value: *ssa.Value) !void {
        // Result always in x0 (archive pattern)
        const args = value.args();
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        // If right is in x0, save it to x9 first before we load left into x0
        if (right_mcv == .register and right_mcv.register == .x0) {
            try aarch64.movRegReg(self.buf, .x9, .x0);
            // Load left operand into x0
            try self.loadToReg(.x0, left_mcv);
            // Add saved right from x9
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
                    try aarch64.ldrRegImm(self.buf, .x9, .sp, offset);
                    try aarch64.addRegReg(self.buf, .x0, .x0, .x9);
                },
                else => {},
            }
        }

        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    pub fn genSub(self: *CodeGen, value: *ssa.Value) !void {
        // Result always in x0 (archive pattern)
        const args = value.args();
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        // If right is in x0, save it to x9 first before we load left into x0
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
                    try aarch64.ldrRegImm(self.buf, .x9, .sp, offset);
                    try aarch64.subRegReg(self.buf, .x0, .x0, .x9);
                },
                else => {},
            }
        }

        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    pub fn genMul(self: *CodeGen, value: *ssa.Value) !void {
        // Result always in x0 (archive pattern)
        const args = value.args();
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        // If right is in x0, save it to x9 first before we load left into x0
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
                    try aarch64.ldrRegImm(self.buf, .x9, .sp, offset);
                    try aarch64.mulRegReg(self.buf, .x0, .x0, .x9);
                },
                .immediate => |imm| {
                    try aarch64.movRegImm64(self.buf, .x9, imm);
                    try aarch64.mulRegReg(self.buf, .x0, .x0, .x9);
                },
                else => {},
            }
        }

        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    pub fn genDiv(self: *CodeGen, value: *ssa.Value) !void {
        // Result always in x0 (archive pattern)
        const args = value.args();
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        // If right is in x0, save it to x9 first before we load left into x0
        if (right_mcv == .register and right_mcv.register == .x0) {
            try aarch64.movRegReg(self.buf, .x9, .x0);
            try self.loadToReg(.x0, left_mcv);
        } else {
            try self.loadToReg(.x0, left_mcv);
            try self.loadToReg(.x9, right_mcv);
        }

        // ARM64 SDIV: x0 = x0 / x9
        try aarch64.sdivRegReg(self.buf, .x0, .x0, .x9);

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
        // scratch1 = dest / scratch0
        try aarch64.sdivRegReg(self.buf, scratch1, dest, scratch0);
        // scratch1 = scratch1 * scratch0
        try aarch64.mulRegReg(self.buf, scratch1, scratch1, scratch0);
        // dest = dest - scratch1
        try aarch64.subRegReg(self.buf, dest, dest, scratch1);

        try self.setResult(value.id, .{ .register = dest });
    }

    pub fn genNeg(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        const src_mcv = self.getValue(args[0]);

        const dest = try self.allocReg(value.id);
        try self.loadToReg(dest, src_mcv);
        // NEG is SUB from zero: dest = 0 - dest
        try aarch64.negReg(self.buf, dest, dest);

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

        const dest = try self.allocReg(value.id);

        switch (size) {
            1 => try aarch64.ldrbRegImm(self.buf, dest, .sp, sp_offset),
            else => try aarch64.ldrRegImm(self.buf, dest, .sp, sp_offset),
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
        // These ops leave ptr in x0, len/payload in x1
        if (src_value.op == .slice_make or src_value.op == .union_init or src_value.op == .str_concat) {
            // Store 16-byte value: ptr/tag at offset, len/payload at offset+8
            try aarch64.strRegImm(self.buf, .x0, .sp, sp_offset);
            const sp_offset_plus8 = convertOffset(total_offset + 8, self.stack_size);
            try aarch64.strRegImm(self.buf, .x1, .sp, sp_offset_plus8);
            return;
        }

        if (src_value.op == .const_string) {
            // Store string literal: load ptr from rodata, store ptr+len
            const str_content = src_value.aux_str;
            const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                str_content[1 .. str_content.len - 1]
            else
                str_content;
            const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
            try aarch64.loadSymbolAddr(self.buf, .x0, sym_name);
            try aarch64.strRegImm(self.buf, .x0, .sp, sp_offset);
            try aarch64.movRegImm64(self.buf, .x0, @intCast(stripped.len));
            const sp_offset_plus8 = convertOffset(total_offset + 8, self.stack_size);
            try aarch64.strRegImm(self.buf, .x0, .sp, sp_offset_plus8);
            return;
        }

        // Standard value store
        const size = self.type_reg.sizeOf(src_value.type_idx);

        // For ops that leave result in x0 (call, field, slice_index, etc.)
        const uses_x0 = switch (src_value.op) {
            .add, .sub, .mul, .div, .call, .field, .index, .slice_index,
            .union_payload, .map_new, .map_get, .map_has, .map_size,
            .list_new, .list_get, .list_len => true,
            else => false,
        };

        if (uses_x0) {
            switch (size) {
                1 => try aarch64.strbRegImm(self.buf, .x0, .sp, sp_offset),
                else => try aarch64.strRegImm(self.buf, .x0, .sp, sp_offset),
            }
            return;
        }

        const src_mcv = self.getValue(src_id);

        switch (src_mcv) {
            .register => |reg| {
                switch (size) {
                    1 => try aarch64.strbRegImm(self.buf, reg, .sp, sp_offset),
                    else => try aarch64.strRegImm(self.buf, reg, .sp, sp_offset),
                }
            },
            .immediate => |imm| {
                try aarch64.movRegImm64(self.buf, scratch0, imm);
                switch (size) {
                    1 => try aarch64.strbRegImm(self.buf, scratch0, .sp, sp_offset),
                    else => try aarch64.strRegImm(self.buf, scratch0, .sp, sp_offset),
                }
            },
            .stack => |offset| {
                try aarch64.ldrRegImm(self.buf, scratch0, .sp, offset);
                switch (size) {
                    1 => try aarch64.strbRegImm(self.buf, scratch0, .sp, sp_offset),
                    else => try aarch64.strRegImm(self.buf, scratch0, .sp, sp_offset),
                }
            },
            else => {},
        }
    }

    pub fn genComparison(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
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

        try self.setResult(value.id, .{ .register = dest });
    }

    pub fn genCall(self: *CodeGen, value: *ssa.Value) !void {
        try self.spillCallerSaved();

        // ARM64 ABI: x0-x7 for arguments
        const arg_regs = [_]aarch64.Reg{ .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7 };
        const args = value.args();

        for (args, 0..) |arg_id, i| {
            if (i >= arg_regs.len) break;
            const arg_mcv = self.getValue(arg_id);
            try self.loadToReg(arg_regs[i], arg_mcv);
        }

        // BL symbol
        const sym_name = if (self.os == .macos)
            try std.fmt.allocPrint(self.allocator, "_{s}", .{value.aux_str})
        else
            value.aux_str;
        try aarch64.callSymbol(self.buf, sym_name);

        // Result is in x0
        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    /// Generate code for field access
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
            const sp_offset = convertOffset(local.offset + field_offset, self.stack_size);

            if (size == 1) {
                try aarch64.ldrbRegImm(self.buf, dest, .sp, sp_offset);
            } else {
                try aarch64.ldrRegImm(self.buf, dest, .sp, sp_offset);
            }
        } else {
            // CASE 2: SSA value reference - address in x0 from prior .addr
            const field_scaled: u12 = @intCast(@divExact(@as(u32, @intCast(field_offset)), 8));
            if (size == 1) {
                try aarch64.ldrbRegImm(self.buf, dest, .x0, @intCast(field_offset));
            } else {
                try aarch64.ldrRegImm(self.buf, dest, .x0, field_scaled);
            }
        }

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
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        const dest = try self.allocReg(value.id);
        try self.loadToReg(dest, left_mcv);
        try self.loadToReg(scratch1, right_mcv);
        try aarch64.andRegReg(self.buf, dest, dest, scratch1);

        try self.setResult(value.id, .{ .register = dest });
    }

    pub fn genOr(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        const left_mcv = self.getValue(args[0]);
        const right_mcv = self.getValue(args[1]);

        const dest = try self.allocReg(value.id);
        try self.loadToReg(dest, left_mcv);
        try self.loadToReg(scratch1, right_mcv);
        try aarch64.orrRegReg(self.buf, dest, dest, scratch1);

        try self.setResult(value.id, .{ .register = dest });
    }

    pub fn genSelect(self: *CodeGen, value: *ssa.Value) !void {
        // select: args[0] = condition, args[1] = true_val, args[2] = false_val
        const args = value.args();
        if (args.len < 3) return;

        const cond_mcv = self.getValue(args[0]);
        const true_mcv = self.getValue(args[1]);
        const false_mcv = self.getValue(args[2]);

        const dest = try self.allocReg(value.id);

        // Load condition and check if non-zero
        try self.loadToReg(scratch0, cond_mcv);
        try self.loadToReg(dest, true_mcv);
        try self.loadToReg(scratch1, false_mcv);

        // CMP scratch0, #0
        try aarch64.cmpRegImm12(self.buf, scratch0, 0);
        // CSEL dest, dest, scratch1, NE (if cond != 0, keep true_val, else use false_val)
        try aarch64.csel(self.buf, dest, dest, scratch1, .ne);

        try self.setResult(value.id, .{ .register = dest });
    }

    pub fn genIndex(self: *CodeGen, value: *ssa.Value) !void {
        // index: args[0] = base local, args[1] = index value
        // aux_int = element size
        // Result always in x0 (archive pattern)
        const args = value.args();
        if (args.len < 2) return;

        const local_idx = args[0];
        if (local_idx >= self.func.locals.len) return;

        const local = self.func.locals[@intCast(local_idx)];
        const base_sp = convertOffset(local.offset, self.stack_size);
        const elem_size: i64 = if (value.aux_int != 0) value.aux_int else 8;

        const idx_mcv = self.getValue(args[1]);

        // Load index into x9
        try self.loadToReg(.x9, idx_mcv);

        // Calculate offset: index * elem_size -> x9
        if (elem_size > 1) {
            try aarch64.movRegImm64(self.buf, .x10, elem_size);
            try aarch64.mulRegReg(self.buf, .x9, .x9, .x10);
        }

        // Add base offset: x9 = x9 + base_sp
        try aarch64.movRegImm64(self.buf, .x10, base_sp);
        try aarch64.addRegReg(self.buf, .x9, .x9, .x10);

        // Load from [sp + x9] -> x0
        try aarch64.ldrRegReg(self.buf, .x0, .sp, .x9);

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
        try aarch64.addRegImm12(self.buf, dest, .sp, sp_offset);

        try self.setResult(value.id, .{ .register = dest });
    }

    pub fn genSliceMake(self: *CodeGen, value: *ssa.Value) !void {
        // slice_make: args[0] = base local, args[1] = start, args[2] = end
        // aux_int = element size
        // Result in x0 (ptr), x1 (len) - multi-register result
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
            try aarch64.ldrRegImm(self.buf, .x8, .sp, base_sp);
        } else {
            // Array: base address is the stack location itself
            // Use addRegImm12 which properly handles sp as base
            try aarch64.addRegImm12(self.buf, .x8, .sp, @intCast(base_sp));
        }

        // Get start value into x9
        try self.loadToReg(.x9, start_mcv);

        // Get end value into x10
        try self.loadToReg(.x10, end_mcv);

        // Compute len = end - start -> x1
        try aarch64.subRegReg(self.buf, .x1, .x10, .x9);

        // Compute ptr = base + start * elem_size -> x0
        // First: x11 = start * elem_size
        try aarch64.movRegImm64(self.buf, .x11, elem_size);
        try aarch64.mulRegReg(self.buf, .x11, .x9, .x11);
        // Then: x0 = base + x11
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
        try aarch64.ldrRegImm(self.buf, .x8, .sp, sp_offset);

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
    pub fn genUnionTag(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const maybe_local_or_ssa = args[0];

        // If args[0] is a load op, get the local index from it
        if (maybe_local_or_ssa < self.func.values.items.len) {
            const union_val = &self.func.values.items[maybe_local_or_ssa];
            if (union_val.op == .load) {
                // The load's aux_int is the local index
                const local_idx: usize = @intCast(union_val.aux_int);
                if (local_idx < self.func.locals.len) {
                    const local = self.func.locals[local_idx];
                    const sp_offset = convertOffset(local.offset, self.stack_size);
                    // Load tag into x0 (use fixed register for simpler tracking)
                    try aarch64.ldrRegImm(self.buf, .x0, .sp, sp_offset);
                    self.reg_manager.markUsed(.x0, value.id);
                    try self.setResult(value.id, .{ .register = .x0 });
                    return;
                }
            }
        }

        // Fallback: treat as direct local index (legacy behavior)
        if (maybe_local_or_ssa < self.func.locals.len) {
            const local = self.func.locals[@intCast(maybe_local_or_ssa)];
            const sp_offset = convertOffset(local.offset, self.stack_size);
            try aarch64.ldrRegImm(self.buf, .x0, .sp, sp_offset);
            self.reg_manager.markUsed(.x0, value.id);
            try self.setResult(value.id, .{ .register = .x0 });
        }
    }

    /// Generate code for union_payload: extract payload from union (at offset 8)
    /// CRITICAL: args[0] can be a local index OR an SSA value reference
    pub fn genUnionPayload(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const maybe_local_or_ssa = args[0];

        // If args[0] is a load op, get the local index from it
        if (maybe_local_or_ssa < self.func.values.items.len) {
            const union_val = &self.func.values.items[maybe_local_or_ssa];
            if (union_val.op == .load) {
                // The load's aux_int is the local index
                const local_idx: usize = @intCast(union_val.aux_int);
                if (local_idx < self.func.locals.len) {
                    const local = self.func.locals[local_idx];
                    const payload_offset = convertOffset(local.offset + 8, self.stack_size);
                    // Load payload into x0
                    try aarch64.ldrRegImm(self.buf, .x0, .sp, payload_offset);
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
            try aarch64.ldrRegImm(self.buf, .x0, .sp, payload_offset);
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

        // If there's a payload, check if it comes from a computation (in x0)
        if (args.len > 0) {
            const payload_val = &self.func.values.items[args[0]];
            if (payload_val.op == .const_int) {
                // Payload is constant - load tag first, then payload
                try aarch64.movRegImm64(self.buf, .x0, variant_idx);
                try aarch64.movRegImm64(self.buf, .x1, payload_val.aux_int);
            } else {
                // Payload comes from computation (in x0) - save it, load tag, swap
                try aarch64.movRegReg(self.buf, .x1, .x0); // save payload to x1
                try aarch64.movRegImm64(self.buf, .x0, variant_idx); // load tag to x0
            }
        } else {
            // No payload - just set tag
            try aarch64.movRegImm64(self.buf, .x0, variant_idx);
            try aarch64.movRegImm64(self.buf, .x1, 0); // zero payload
        }

        // Result: x0 = tag, x1 = payload
        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    /// Generate code for list_get: call runtime cot_list_get(handle, index)
    /// Uses MCValue for all operands
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

        // Result in x0
        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    pub fn genMapGet(self: *CodeGen, value: *ssa.Value) !void {
        // map_get: args[0] = handle, args[1] = key
        // Uses MCValue for handle, special handling for string keys
        const args = value.args();
        if (args.len < 2) return;

        // Load map handle into x0 via MCValue
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.x0, handle_mcv);

        // Load key - special handling for const_string (need ptr + len)
        const key_val = &self.func.values.items[args[1]];
        if (key_val.op == .const_string) {
            const str_content = key_val.aux_str;
            const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                str_content[1 .. str_content.len - 1]
            else
                str_content;
            const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
            try aarch64.loadSymbolAddr(self.buf, .x1, sym_name);
            try aarch64.movRegImm64(self.buf, .x2, @intCast(stripped.len));
        } else {
            const key_mcv = self.getValue(args[1]);
            try self.loadToReg(.x1, key_mcv);
        }

        try aarch64.callSymbol(self.buf, "_cot_map_get");

        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
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
        try aarch64.ldrRegImm(self.buf, dest, .sp, sp_offset);

        try self.setResult(value.id, .{ .register = dest });
    }

    /// Generate code for map_new: create new map via runtime call
    pub fn genMapNew(self: *CodeGen, value: *ssa.Value) !void {
        try aarch64.callSymbol(self.buf, "_cot_map_new");
        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    /// Generate code for map_set: args[0]=handle, args[1]=key, args[2]=value
    /// Uses MCValue for handle and value, special handling for string keys
    pub fn genMapSet(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 3) return;

        // Load map handle into x0 via MCValue
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.x0, handle_mcv);

        // Load key - special handling for const_string (need ptr + len)
        const key_val = &self.func.values.items[args[1]];
        if (key_val.op == .const_string) {
            const str_content = key_val.aux_str;
            const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                str_content[1 .. str_content.len - 1]
            else
                str_content;
            const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
            try aarch64.loadSymbolAddr(self.buf, .x1, sym_name);
            try aarch64.movRegImm64(self.buf, .x2, @intCast(stripped.len));
        } else {
            // For non-const strings, load ptr via MCValue (len would need separate tracking)
            const key_mcv = self.getValue(args[1]);
            try self.loadToReg(.x1, key_mcv);
            // TODO: handle string len properly for non-const strings
        }

        // Load value into x3 via MCValue
        const val_mcv = self.getValue(args[2]);
        try self.loadToReg(.x3, val_mcv);

        try aarch64.callSymbol(self.buf, "_cot_map_set");
    }

    /// Generate code for map_has: args[0]=handle, args[1]=key
    /// Inline op type lookup for key
    pub fn genMapHas(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        // Load map handle into x0 via MCValue
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.x0, handle_mcv);

        // Load key - special handling for const_string (need ptr + len)
        const key_val = &self.func.values.items[args[1]];
        if (key_val.op == .const_string) {
            const str_content = key_val.aux_str;
            const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                str_content[1 .. str_content.len - 1]
            else
                str_content;
            const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
            try aarch64.loadSymbolAddr(self.buf, .x1, sym_name);
            try aarch64.movRegImm64(self.buf, .x2, @intCast(stripped.len));
        } else {
            const key_mcv = self.getValue(args[1]);
            try self.loadToReg(.x1, key_mcv);
        }

        try aarch64.callSymbol(self.buf, "_cot_map_has");
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

    /// Generate code for list_new: call cot_list_new() runtime function
    pub fn genListNew(self: *CodeGen, value: *ssa.Value) !void {
        try aarch64.callSymbol(self.buf, "_cot_list_new");
        // x0 now has list handle
        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
    }

    /// Generate code for list_push: args[0]=handle, args[1]=value
    /// Uses MCValue for all operands
    pub fn genListPush(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        // Load handle into x0 via MCValue
        const handle_mcv = self.getValue(args[0]);
        try self.loadToReg(.x0, handle_mcv);

        // Load value into x1 via MCValue
        const val_mcv = self.getValue(args[1]);
        try self.loadToReg(.x1, val_mcv);

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

    /// Generate code for str_concat: concatenate two strings via runtime
    /// Call cot_str_concat(ptr1, len1, ptr2, len2) -> (new_ptr in x0, new_len in x1)
    /// Uses inline op type lookup (archive pattern)
    pub fn genStrConcat(self: *CodeGen, value: *ssa.Value) !void {
        const args = value.args();
        if (args.len < 2) return;

        // Load first string (ptr in x0, len in x1)
        const str1_val = &self.func.values.items[args[0]];
        if (str1_val.op == .const_string) {
            const str_content = str1_val.aux_str;
            const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                str_content[1 .. str_content.len - 1]
            else
                str_content;
            const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
            try aarch64.loadSymbolAddr(self.buf, .x0, sym_name);
            try aarch64.movRegImm64(self.buf, .x1, @intCast(stripped.len));
        } else if (str1_val.op == .load or str1_val.op == .copy) {
            const local_idx: u32 = @intCast(str1_val.aux_int);
            if (local_idx < self.func.locals.len) {
                const offset = self.func.locals[local_idx].offset;
                const sp_offset = convertOffset(offset, self.stack_size);
                const sp_offset_plus8 = convertOffset(offset + 8, self.stack_size);
                try aarch64.ldrRegImm(self.buf, .x0, .sp, sp_offset); // ptr
                try aarch64.ldrRegImm(self.buf, .x1, .sp, sp_offset_plus8); // len
            }
        } else if (str1_val.op == .str_concat) {
            // Result from previous str_concat already in x0/x1
        }

        // Load second string (ptr in x2, len in x3)
        const str2_val = &self.func.values.items[args[1]];
        if (str2_val.op == .const_string) {
            const str_content = str2_val.aux_str;
            const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                str_content[1 .. str_content.len - 1]
            else
                str_content;
            const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
            try aarch64.loadSymbolAddr(self.buf, .x2, sym_name);
            try aarch64.movRegImm64(self.buf, .x3, @intCast(stripped.len));
        } else if (str2_val.op == .load or str2_val.op == .copy) {
            const local_idx: u32 = @intCast(str2_val.aux_int);
            if (local_idx < self.func.locals.len) {
                const offset = self.func.locals[local_idx].offset;
                const sp_offset = convertOffset(offset, self.stack_size);
                const sp_offset_plus8 = convertOffset(offset + 8, self.stack_size);
                try aarch64.ldrRegImm(self.buf, .x2, .sp, sp_offset); // ptr
                try aarch64.ldrRegImm(self.buf, .x3, .sp, sp_offset_plus8); // len
            }
        }

        try aarch64.callSymbol(self.buf, "_cot_str_concat");

        // Result: ptr in x0, len in x1
        self.reg_manager.markUsed(.x0, value.id);
        try self.setResult(value.id, .{ .register = .x0 });
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
                try aarch64.addRegImm12(self.buf, dest, .sp, sp_offset);
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
        const sp_offset = convertOffset(local.offset, self.stack_size);
        const field_offset: u12 = @intCast(@as(u32, @intCast(value.aux_int)));

        const dest = try self.allocReg(value.id);

        // Load pointer from local
        try aarch64.ldrRegImm(self.buf, scratch0, .sp, sp_offset);

        // Load from ptr + field_offset
        try aarch64.ldrRegImm(self.buf, dest, scratch0, field_offset);

        try self.setResult(value.id, .{ .register = dest });
    }

    pub fn genReturn(self: *CodeGen, block: *ssa.Block) !void {
        if (block.control != ssa.null_value) {
            const ret_mcv = self.getValue(block.control);
            try self.loadToReg(.x0, ret_mcv);
        }

        // Epilogue: ldp fp, lr, [sp], #stack_size; ret
        const stack_offset: i7 = @intCast(@divExact(self.stack_size, 8));
        try aarch64.ldpPostIndex(self.buf, .fp, .lr, .sp, stack_offset);
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
            .const_string => {
                // String constants are stored as lea_symbol references
                try self.setResult(value.id, .{ .lea_symbol = .{
                    .name = value.aux_str,
                    .len = value.aux_str.len,
                } });
            },
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
            .field => try self.genField(value),
            .not => try self.genNot(value),
            .@"and" => try self.genAnd(value),
            .@"or" => try self.genOr(value),
            .select => try self.genSelect(value),
            .index => try self.genIndex(value),
            .addr => try self.genAddr(value),
            .slice_make => try self.genSliceMake(value),
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
        // stp fp, lr, [sp, #-stack_size]!
        // Note: self.stack_size already includes room for fp/lr (alignTo(frame_size+16, 16))
        const neg_offset: i7 = -@as(i7, @intCast(@divExact(self.stack_size, 8)));
        try aarch64.stpPreIndex(self.buf, .fp, .lr, .sp, neg_offset);
        // mov fp, sp
        try aarch64.movFromSp(self.buf, .fp);

        // Spill parameters to local slots
        const param_regs = [_]aarch64.Reg{ .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7 };
        const num_params = @min(self.func.param_count, @as(u32, @intCast(param_regs.len)));

        for (0..num_params) |i| {
            if (i < self.func.locals.len) {
                const sp_offset = convertOffset(self.func.locals[i].offset, self.stack_size);
                try aarch64.strRegImm(self.buf, param_regs[i], .sp, sp_offset);
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
/// Returns u12 for use with ARM64 load/store unsigned offset
fn convertOffset(rbp_offset: i32, stack_size: u32) u12 {
    // rbp points to saved fp/lr, locals are at negative offsets from rbp
    // sp is stack_size bytes below rbp
    // sp_offset = stack_size + rbp_offset (should be positive)
    const sp_offset = @as(i32, @intCast(stack_size)) + rbp_offset;
    return @intCast(@as(u32, @intCast(sp_offset)));
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
