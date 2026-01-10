///! x86-64 code generation backend.
///!
///! Combines patterns from:
///! - Roc: gen_dev/src/generic64/x86_64.rs (direct byte emission)
///! - Go: cmd/compile/internal/amd64 (SSA lowering)
///!
///! Key patterns:
///! - REX prefix construction for 64-bit operations
///! - ModRM byte encoding for register/memory addressing
///! - SIB byte for RSP/R12 base addressing
///! - Direct emission to CodeBuffer

const std = @import("std");
const be = @import("backend.zig");
const ssa = @import("../ssa.zig");
const debug = @import("../debug.zig");

const Allocator = std.mem.Allocator;

// Scoped logger for x86-64 codegen
const log = debug.scoped(.codegen);
const CodeBuffer = be.CodeBuffer;
const StorageManager = be.StorageManager;
const Storage = be.Storage;
const GeneralReg = be.GeneralReg;

// ============================================================================
// x86-64 Registers
// ============================================================================

/// x86-64 general-purpose registers.
pub const Reg = enum(u8) {
    rax = 0,
    rcx = 1,
    rdx = 2,
    rbx = 3,
    rsp = 4,
    rbp = 5,
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

    /// Get the low 3 bits (for encoding).
    pub fn low3(self: Reg) u8 {
        return @intFromEnum(self) & 0x7;
    }

    /// Check if register requires REX extension.
    pub fn needsRex(self: Reg) bool {
        return @intFromEnum(self) > 7;
    }
};

/// x86-64 XMM registers for floating point.
pub const XmmReg = enum(u8) {
    xmm0 = 0,
    xmm1 = 1,
    xmm2 = 2,
    xmm3 = 3,
    xmm4 = 4,
    xmm5 = 5,
    xmm6 = 6,
    xmm7 = 7,
    xmm8 = 8,
    xmm9 = 9,
    xmm10 = 10,
    xmm11 = 11,
    xmm12 = 12,
    xmm13 = 13,
    xmm14 = 14,
    xmm15 = 15,
};

// ============================================================================
// REX Prefix Construction
// ============================================================================

/// REX prefix base.
const REX: u8 = 0x40;

/// REX.W - 64-bit operand size.
const REX_W: u8 = 0x08;
/// REX.R - extension to ModRM.reg.
const REX_R: u8 = 0x04;
/// REX.X - extension to SIB.index.
const REX_X: u8 = 0x02;
/// REX.B - extension to ModRM.rm or opcode reg.
const REX_B: u8 = 0x01;

/// Build REX prefix for two-register operation.
fn rex(w: bool, reg: Reg, rm: Reg) u8 {
    var r: u8 = REX;
    if (w) r |= REX_W;
    if (reg.needsRex()) r |= REX_R;
    if (rm.needsRex()) r |= REX_B;
    return r;
}

/// Build REX prefix for single-register operation.
fn rex1(w: bool, rm: Reg) u8 {
    var r: u8 = REX;
    if (w) r |= REX_W;
    if (rm.needsRex()) r |= REX_B;
    return r;
}

// ============================================================================
// ModRM Byte Construction
// ============================================================================

/// ModRM addressing modes.
const ModRM = struct {
    /// Register-indirect: [reg]
    const indirect: u8 = 0x00;
    /// Indirect + disp8: [reg + disp8]
    const disp8: u8 = 0x40;
    /// Indirect + disp32: [reg + disp32]
    const disp32: u8 = 0x80;
    /// Register-direct: reg
    const direct: u8 = 0xC0;

    /// Build ModRM byte for register-to-register.
    fn regReg(reg: Reg, rm: Reg) u8 {
        return direct | (reg.low3() << 3) | rm.low3();
    }

    /// Build ModRM byte for reg with displacement.
    fn regDisp(mod: u8, reg: Reg, rm: Reg) u8 {
        return mod | (reg.low3() << 3) | rm.low3();
    }

    /// Build ModRM byte with opcode extension.
    fn opExt(mod: u8, ext: u8, rm: Reg) u8 {
        return mod | (ext << 3) | rm.low3();
    }
};

// ============================================================================
// Instruction Emission
// ============================================================================

/// Emit REX prefix if needed, otherwise nothing.
fn emitRexOpt(buf: *CodeBuffer, r: u8) !void {
    if (r != REX) {
        try buf.emit8(r);
    }
}

/// Emit 64-bit register-to-register binary operation.
fn emitBinopReg64Reg64(buf: *CodeBuffer, opcode: u8, dst: Reg, src: Reg) !void {
    try buf.emit8(rex(true, src, dst));
    try buf.emit8(opcode);
    try buf.emit8(ModRM.regReg(src, dst));
}

/// Emit 32-bit register-to-register binary operation.
fn emitBinopReg32Reg32(buf: *CodeBuffer, opcode: u8, dst: Reg, src: Reg) !void {
    const r = rex(false, src, dst);
    if (r != REX) try buf.emit8(r);
    try buf.emit8(opcode);
    try buf.emit8(ModRM.regReg(src, dst));
}

// ============================================================================
// MOV Instructions
// ============================================================================

/// MOV r64, r64
pub fn movRegReg(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    try emitBinopReg64Reg64(buf, 0x89, dst, src);
}

/// MOV r64, imm32 (sign-extended)
pub fn movRegImm32(buf: *CodeBuffer, dst: Reg, imm: i32) !void {
    try buf.emit8(rex1(true, dst));
    try buf.emit8(0xC7);
    try buf.emit8(ModRM.opExt(ModRM.direct, 0, dst));
    try buf.emit32(@bitCast(imm));
}

/// MOV r64, imm64
pub fn movRegImm64(buf: *CodeBuffer, dst: Reg, imm: i64) !void {
    // Use shorter encoding if possible
    if (imm >= std.math.minInt(i32) and imm <= std.math.maxInt(i32)) {
        return movRegImm32(buf, dst, @intCast(imm));
    }
    // Full 64-bit immediate: REX.W + B8+rd + imm64
    try buf.emit8(rex1(true, dst));
    try buf.emit8(0xB8 | dst.low3());
    try buf.emit64(@bitCast(imm));
}

/// MOV [base + offset], r64
pub fn movMemReg(buf: *CodeBuffer, base: Reg, offset: i32, src: Reg) !void {
    try buf.emit8(rex(true, src, base));
    try buf.emit8(0x89);

    if (offset == 0 and base != .rbp and base != .r13) {
        // [base] - no displacement needed
        try buf.emit8(ModRM.regDisp(ModRM.indirect, src, base));
    } else if (offset >= -128 and offset <= 127) {
        // [base + disp8]
        try buf.emit8(ModRM.regDisp(ModRM.disp8, src, base));
    } else {
        // [base + disp32]
        try buf.emit8(ModRM.regDisp(ModRM.disp32, src, base));
    }

    // SIB byte required for RSP/R12 as base
    if (base == .rsp or base == .r12) {
        try buf.emit8(0x24); // SIB: scale=0, index=RSP, base=RSP
    }

    // Emit displacement
    if (offset == 0 and base != .rbp and base != .r13) {
        // No displacement
    } else if (offset >= -128 and offset <= 127) {
        try buf.emit8(@bitCast(@as(i8, @intCast(offset))));
    } else {
        try buf.emit32(@bitCast(offset));
    }
}

/// MOV r64, [base + offset]
pub fn movRegMem(buf: *CodeBuffer, dst: Reg, base: Reg, offset: i32) !void {
    try buf.emit8(rex(true, dst, base));
    try buf.emit8(0x8B);

    if (offset == 0 and base != .rbp and base != .r13) {
        try buf.emit8(ModRM.regDisp(ModRM.indirect, dst, base));
    } else if (offset >= -128 and offset <= 127) {
        try buf.emit8(ModRM.regDisp(ModRM.disp8, dst, base));
    } else {
        try buf.emit8(ModRM.regDisp(ModRM.disp32, dst, base));
    }

    if (base == .rsp or base == .r12) {
        try buf.emit8(0x24);
    }

    if (offset == 0 and base != .rbp and base != .r13) {
        // No displacement
    } else if (offset >= -128 and offset <= 127) {
        try buf.emit8(@bitCast(@as(i8, @intCast(offset))));
    } else {
        try buf.emit32(@bitCast(offset));
    }
}

// ============================================================================
// Arithmetic Instructions
// ============================================================================

/// ADD r64, r64
pub fn addRegReg(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    try emitBinopReg64Reg64(buf, 0x01, dst, src);
}

/// ADD r64, imm32
pub fn addRegImm32(buf: *CodeBuffer, dst: Reg, imm: i32) !void {
    try buf.emit8(rex1(true, dst));
    try buf.emit8(0x81);
    try buf.emit8(ModRM.opExt(ModRM.direct, 0, dst)); // /0 for ADD
    try buf.emit32(@bitCast(imm));
}

/// SUB r64, r64
pub fn subRegReg(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    try emitBinopReg64Reg64(buf, 0x29, dst, src);
}

/// SUB r64, imm32
pub fn subRegImm32(buf: *CodeBuffer, dst: Reg, imm: i32) !void {
    try buf.emit8(rex1(true, dst));
    try buf.emit8(0x81);
    try buf.emit8(ModRM.opExt(ModRM.direct, 5, dst)); // /5 for SUB
    try buf.emit32(@bitCast(imm));
}

/// IMUL r64, r64
pub fn imulRegReg(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    // Two-byte opcode: 0F AF
    try buf.emit8(rex(true, dst, src));
    try buf.emit8(0x0F);
    try buf.emit8(0xAF);
    try buf.emit8(ModRM.regReg(dst, src));
}

/// IMUL r64, r64, imm32 - three-operand form
pub fn imulRegRegImm(buf: *CodeBuffer, dst: Reg, src: Reg, imm: i32) !void {
    // Check if immediate fits in 8 bits
    if (imm >= -128 and imm <= 127) {
        // Use imm8 form: REX.W + 6B /r ib
        try buf.emit8(rex(true, dst, src));
        try buf.emit8(0x6B);
        try buf.emit8(ModRM.regReg(dst, src));
        try buf.emit8(@bitCast(@as(i8, @intCast(imm))));
    } else {
        // Use imm32 form: REX.W + 69 /r id
        try buf.emit8(rex(true, dst, src));
        try buf.emit8(0x69);
        try buf.emit8(ModRM.regReg(dst, src));
        try buf.emit32(@bitCast(imm));
    }
}

/// CQO - sign-extend RAX into RDX:RAX
pub fn cqo(buf: *CodeBuffer) !void {
    try buf.emit8(REX | REX_W); // 0x48
    try buf.emit8(0x99);
}

/// IDIV r64 - signed divide RDX:RAX by r64
pub fn idivReg(buf: *CodeBuffer, src: Reg) !void {
    try buf.emit8(rex1(true, src));
    try buf.emit8(0xF7);
    try buf.emit8(ModRM.opExt(ModRM.direct, 7, src)); // /7 for IDIV
}

// ============================================================================
// Bitwise Instructions
// ============================================================================

/// AND r64, r64
pub fn andRegReg(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    try emitBinopReg64Reg64(buf, 0x21, dst, src);
}

/// OR r64, r64
pub fn orRegReg(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    try emitBinopReg64Reg64(buf, 0x09, dst, src);
}

/// XOR r64, r64
pub fn xorRegReg(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    try emitBinopReg64Reg64(buf, 0x31, dst, src);
}

/// NOT r64
pub fn notReg(buf: *CodeBuffer, dst: Reg) !void {
    try buf.emit8(rex1(true, dst));
    try buf.emit8(0xF7);
    try buf.emit8(ModRM.opExt(ModRM.direct, 2, dst)); // /2 for NOT
}

/// NEG r64
pub fn negReg(buf: *CodeBuffer, dst: Reg) !void {
    try buf.emit8(rex1(true, dst));
    try buf.emit8(0xF7);
    try buf.emit8(ModRM.opExt(ModRM.direct, 3, dst)); // /3 for NEG
}

// ============================================================================
// Shift Instructions
// ============================================================================

/// SHL r64, imm8
pub fn shlRegImm(buf: *CodeBuffer, dst: Reg, imm: u8) !void {
    try buf.emit8(rex1(true, dst));
    try buf.emit8(0xC1);
    try buf.emit8(ModRM.opExt(ModRM.direct, 4, dst)); // /4 for SHL
    try buf.emit8(imm);
}

/// SHR r64, imm8
pub fn shrRegImm(buf: *CodeBuffer, dst: Reg, imm: u8) !void {
    try buf.emit8(rex1(true, dst));
    try buf.emit8(0xC1);
    try buf.emit8(ModRM.opExt(ModRM.direct, 5, dst)); // /5 for SHR
    try buf.emit8(imm);
}

/// SAR r64, imm8 (arithmetic shift right)
pub fn sarRegImm(buf: *CodeBuffer, dst: Reg, imm: u8) !void {
    try buf.emit8(rex1(true, dst));
    try buf.emit8(0xC1);
    try buf.emit8(ModRM.opExt(ModRM.direct, 7, dst)); // /7 for SAR
    try buf.emit8(imm);
}

// ============================================================================
// Comparison Instructions
// ============================================================================

/// CMP r64, r64
pub fn cmpRegReg(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    try emitBinopReg64Reg64(buf, 0x39, dst, src);
}

/// CMP r64, imm32
pub fn cmpRegImm32(buf: *CodeBuffer, dst: Reg, imm: i32) !void {
    try buf.emit8(rex1(true, dst));
    try buf.emit8(0x81);
    try buf.emit8(ModRM.opExt(ModRM.direct, 7, dst)); // /7 for CMP
    try buf.emit32(@bitCast(imm));
}

/// TEST r64, r64
pub fn testRegReg(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    try emitBinopReg64Reg64(buf, 0x85, dst, src);
}

// ============================================================================
// Control Flow Instructions
// ============================================================================

/// PUSH r64
pub fn pushReg(buf: *CodeBuffer, reg: Reg) !void {
    if (reg.needsRex()) {
        try buf.emit8(REX | REX_B);
    }
    try buf.emit8(0x50 | reg.low3());
}

/// POP r64
pub fn popReg(buf: *CodeBuffer, reg: Reg) !void {
    if (reg.needsRex()) {
        try buf.emit8(REX | REX_B);
    }
    try buf.emit8(0x58 | reg.low3());
}

/// RET
pub fn ret(buf: *CodeBuffer) !void {
    try buf.emit8(0xC3);
}

/// CALL rel32
pub fn callRel32(buf: *CodeBuffer, offset: i32) !void {
    try buf.emit8(0xE8);
    try buf.emit32(@bitCast(offset));
}

/// CALL with relocation (placeholder for linker)
pub fn callSymbol(buf: *CodeBuffer, symbol: []const u8) !void {
    try buf.emit8(0xE8);
    try buf.addRelocation(.pc_rel_32, symbol, -4);
    try buf.emit32(0); // Placeholder for linker
}

/// JMP rel32
pub fn jmpRel32(buf: *CodeBuffer, offset: i32) !void {
    try buf.emit8(0xE9);
    try buf.emit32(@bitCast(offset));
}

/// JMP rel8
pub fn jmpRel8(buf: *CodeBuffer, offset: i8) !void {
    try buf.emit8(0xEB);
    try buf.emit8(@bitCast(offset));
}

/// Conditional jump opcodes (two-byte: 0F 8x).
pub const CondCode = enum(u8) {
    o = 0x00, // Overflow
    no = 0x01, // Not overflow
    b = 0x02, // Below (unsigned <)
    ae = 0x03, // Above or equal (unsigned >=)
    e = 0x04, // Equal
    ne = 0x05, // Not equal
    be = 0x06, // Below or equal (unsigned <=)
    a = 0x07, // Above (unsigned >)
    s = 0x08, // Sign (negative)
    ns = 0x09, // Not sign (positive or zero)
    l = 0x0C, // Less (signed <)
    ge = 0x0D, // Greater or equal (signed >=)
    le = 0x0E, // Less or equal (signed <=)
    g = 0x0F, // Greater (signed >)
};

/// Jcc rel32 (conditional jump)
pub fn jccRel32(buf: *CodeBuffer, cc: CondCode, offset: i32) !void {
    try buf.emit8(0x0F);
    try buf.emit8(0x80 | @intFromEnum(cc));
    try buf.emit32(@bitCast(offset));
}

/// Jcc rel8 (short conditional jump)
pub fn jccRel8(buf: *CodeBuffer, cc: CondCode, offset: i8) !void {
    try buf.emit8(0x70 | @intFromEnum(cc));
    try buf.emit8(@bitCast(offset));
}

// ============================================================================
// LEA Instruction
// ============================================================================

/// LEA r64, [base + offset]
pub fn leaRegMem(buf: *CodeBuffer, dst: Reg, base: Reg, offset: i32) !void {
    try buf.emit8(rex(true, dst, base));
    try buf.emit8(0x8D);

    if (offset == 0 and base != .rbp and base != .r13) {
        try buf.emit8(ModRM.regDisp(ModRM.indirect, dst, base));
    } else if (offset >= -128 and offset <= 127) {
        try buf.emit8(ModRM.regDisp(ModRM.disp8, dst, base));
    } else {
        try buf.emit8(ModRM.regDisp(ModRM.disp32, dst, base));
    }

    if (base == .rsp or base == .r12) {
        try buf.emit8(0x24);
    }

    if (offset == 0 and base != .rbp and base != .r13) {
        // No displacement
    } else if (offset >= -128 and offset <= 127) {
        try buf.emit8(@bitCast(@as(i8, @intCast(offset))));
    } else {
        try buf.emit32(@bitCast(offset));
    }
}

// ============================================================================
// NOP Instructions
// ============================================================================

/// NOP (1 byte)
pub fn nop(buf: *CodeBuffer) !void {
    try buf.emit8(0x90);
}

/// Multi-byte NOP for alignment
pub fn nopN(buf: *CodeBuffer, n: usize) !void {
    // Use optimal NOP sequences
    var remaining = n;
    while (remaining > 0) {
        if (remaining >= 9) {
            // 66 0F 1F 84 00 00 00 00 00 (9-byte NOP)
            try buf.emitSlice(&.{ 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 });
            remaining -= 9;
        } else if (remaining >= 8) {
            // 0F 1F 84 00 00 00 00 00 (8-byte NOP)
            try buf.emitSlice(&.{ 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 });
            remaining -= 8;
        } else if (remaining >= 7) {
            // 0F 1F 80 00 00 00 00 (7-byte NOP)
            try buf.emitSlice(&.{ 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 });
            remaining -= 7;
        } else if (remaining >= 6) {
            // 66 0F 1F 44 00 00 (6-byte NOP)
            try buf.emitSlice(&.{ 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 });
            remaining -= 6;
        } else if (remaining >= 5) {
            // 0F 1F 44 00 00 (5-byte NOP)
            try buf.emitSlice(&.{ 0x0F, 0x1F, 0x44, 0x00, 0x00 });
            remaining -= 5;
        } else if (remaining >= 4) {
            // 0F 1F 40 00 (4-byte NOP)
            try buf.emitSlice(&.{ 0x0F, 0x1F, 0x40, 0x00 });
            remaining -= 4;
        } else if (remaining >= 3) {
            // 0F 1F 00 (3-byte NOP)
            try buf.emitSlice(&.{ 0x0F, 0x1F, 0x00 });
            remaining -= 3;
        } else if (remaining >= 2) {
            // 66 90 (2-byte NOP)
            try buf.emitSlice(&.{ 0x66, 0x90 });
            remaining -= 2;
        } else {
            // 90 (1-byte NOP)
            try buf.emit8(0x90);
            remaining -= 1;
        }
    }
}

// ============================================================================
// x86-64 Backend Implementation
// ============================================================================

pub const X86_64Backend = struct {
    allocator: Allocator,
    storage: StorageManager,

    pub fn init(allocator: Allocator) X86_64Backend {
        var self = X86_64Backend{
            .allocator = allocator,
            .storage = StorageManager.init(allocator),
        };

        // Initialize free registers (System V ABI caller-saved)
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.rax)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.rcx)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.rdx)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.rsi)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.rdi)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.r8)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.r9)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.r10)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.r11)) catch {};

        return self;
    }

    pub fn deinit(self: *X86_64Backend) void {
        self.storage.deinit();
    }

    /// Get the Backend interface for this implementation.
    pub fn getBackend(self: *X86_64Backend) be.Backend {
        return .{
            .vtable = &vtable,
            .ptr = self,
        };
    }

    const vtable = be.Backend.VTable{
        .genFunc = genFunc,
        .genValue = genValue,
        .genBlock = genBlock,
        .emitPrologue = emitPrologue,
        .emitEpilogue = emitEpilogue,
    };

    fn genFunc(ptr: *anyopaque, func: *ssa.Func, buf: *CodeBuffer) !void {
        const self: *X86_64Backend = @ptrCast(@alignCast(ptr));
        self.storage.reset();

        log.debug("genFunc: {s} ({d} blocks, {d} values)", .{
            func.name,
            func.numBlocks(),
            func.numValues(),
        });

        // Emit prologue placeholder (will patch later)
        const prologue_start = buf.pos();
        try emitPrologue(ptr, buf, &self.storage);

        // Generate code for each block
        for (func.blocks.items, 0..) |*block, i| {
            log.debug("  block b{d} ({d} values)", .{ block.id, block.values.items.len });

            // Generate values in block
            for (block.values.items) |vid| {
                const value = func.getValue(vid);
                try genValue(ptr, func, value, buf, &self.storage);
            }

            // Generate block control flow
            const next_block: ?*ssa.Block = if (i + 1 < func.blocks.items.len)
                &func.blocks.items[i + 1]
            else
                null;
            try genBlock(ptr, func, block, next_block, buf);
        }

        // Log total bytes generated
        log.debug("genFunc: {s} done, {d} bytes", .{ func.name, buf.pos() - prologue_start });
    }

    fn genValue(ptr: *anyopaque, func: *ssa.Func, v: *ssa.Value, buf: *CodeBuffer, storage: *StorageManager) !void {
        const self: *X86_64Backend = @ptrCast(@alignCast(ptr));
        _ = self;
        _ = func;

        const start_pos = buf.pos();

        switch (v.op) {
            .const_int => {
                // Load constant into a register
                if (storage.allocGeneral()) |reg| {
                    const imm = v.aux_int;
                    try movRegImm64(buf, @enumFromInt(reg), imm);
                    try storage.setStorage(v.id, .{ .general_reg = reg });
                    log.debug("    v{d} = const_int {d} -> r{d}", .{ v.id, imm, reg });
                } else {
                    // Spill to stack
                    const offset = storage.allocStack(8);
                    try storage.setStorage(v.id, .{ .stack = offset });
                    log.debug("    v{d} = const_int {d} -> [rbp{d}]", .{ v.id, v.aux_int, offset });
                }
            },
            .add => {
                const value_args = v.args();
                if (value_args.len >= 2) {
                    const dst_storage = storage.getStorage(value_args[0]);
                    const src_storage = storage.getStorage(value_args[1]);

                    if (dst_storage == .general_reg and src_storage == .general_reg) {
                        const dst_reg: Reg = @enumFromInt(dst_storage.general_reg);
                        const src_reg: Reg = @enumFromInt(src_storage.general_reg);
                        try addRegReg(buf, dst_reg, src_reg);
                        try storage.setStorage(v.id, dst_storage);
                        log.debug("    v{d} = add v{d}, v{d} -> r{d}", .{ v.id, value_args[0], value_args[1], dst_storage.general_reg });
                    }
                }
            },
            .sub => {
                const value_args = v.args();
                if (value_args.len >= 2) {
                    const dst_storage = storage.getStorage(value_args[0]);
                    const src_storage = storage.getStorage(value_args[1]);

                    if (dst_storage == .general_reg and src_storage == .general_reg) {
                        const dst_reg: Reg = @enumFromInt(dst_storage.general_reg);
                        const src_reg: Reg = @enumFromInt(src_storage.general_reg);
                        try subRegReg(buf, dst_reg, src_reg);
                        try storage.setStorage(v.id, dst_storage);
                        log.debug("    v{d} = sub v{d}, v{d} -> r{d}", .{ v.id, value_args[0], value_args[1], dst_storage.general_reg });
                    }
                }
            },
            .mul => {
                const value_args = v.args();
                if (value_args.len >= 2) {
                    const dst_storage = storage.getStorage(value_args[0]);
                    const src_storage = storage.getStorage(value_args[1]);

                    if (dst_storage == .general_reg and src_storage == .general_reg) {
                        const dst_reg: Reg = @enumFromInt(dst_storage.general_reg);
                        const src_reg: Reg = @enumFromInt(src_storage.general_reg);
                        try imulRegReg(buf, dst_reg, src_reg);
                        try storage.setStorage(v.id, dst_storage);
                        log.debug("    v{d} = mul v{d}, v{d} -> r{d}", .{ v.id, value_args[0], value_args[1], dst_storage.general_reg });
                    }
                }
            },
            .ret => {
                // Move return value to RAX if needed
                const value_args = v.args();
                if (value_args.len >= 1) {
                    const ret_storage = storage.getStorage(value_args[0]);
                    if (ret_storage == .general_reg) {
                        const ret_reg: Reg = @enumFromInt(ret_storage.general_reg);
                        if (ret_reg != .rax) {
                            try movRegReg(buf, .rax, ret_reg);
                        }
                        log.debug("    v{d} = ret v{d}", .{ v.id, value_args[0] });
                    }
                }
            },
            else => {
                // Other ops not yet implemented
                log.debug("    v{d} = {s} (unimplemented)", .{ v.id, @tagName(v.op) });
            },
        }

        _ = start_pos;
    }

    fn genBlock(ptr: *anyopaque, func: *ssa.Func, b: *ssa.Block, next: ?*ssa.Block, buf: *CodeBuffer) !void {
        _ = ptr;
        _ = func;

        switch (b.kind) {
            .plain => {
                // Fall through to next block if adjacent
                const block_succs = b.succs();
                if (block_succs.len > 0) {
                    const target = block_succs[0].block;
                    if (next) |n| {
                        if (n.id != target) {
                            // Need explicit jump
                            log.debug("  b{d}: jmp b{d}", .{ b.id, target });
                            try jmpRel32(buf, 0); // Placeholder, will patch
                        } else {
                            log.debug("  b{d}: fallthrough to b{d}", .{ b.id, target });
                        }
                    } else {
                        log.debug("  b{d}: jmp b{d} (tail)", .{ b.id, target });
                        try jmpRel32(buf, 0);
                    }
                }
            },
            .@"if" => {
                // Conditional branch
                const block_succs = b.succs();
                if (block_succs.len >= 2) {
                    log.debug("  b{d}: branch to b{d}/b{d}", .{ b.id, block_succs[0].block, block_succs[1].block });
                    // Compare and branch
                    try jccRel32(buf, .ne, 0); // Placeholder for then branch
                    // Fall through to else or jump
                    if (next) |n| {
                        if (n.id != block_succs[1].block) {
                            try jmpRel32(buf, 0);
                        }
                    }
                }
            },
            .ret => {
                // Return from function
                log.debug("  b{d}: ret", .{b.id});
                try ret(buf);
            },
            .exit => {
                log.debug("  b{d}: exit", .{b.id});
            },
        }
    }

    fn emitPrologue(ptr: *anyopaque, buf: *CodeBuffer, storage: *StorageManager) !void {
        _ = ptr;
        // Standard x86-64 function prologue
        // push rbp
        try pushReg(buf, .rbp);
        // mov rbp, rsp
        try movRegReg(buf, .rbp, .rsp);

        // Reserve stack space (will be patched later with actual size)
        const stack_size: u32 = @intCast(@abs(storage.max_stack));
        if (stack_size > 0) {
            // sub rsp, stack_size
            try subRegImm32(buf, .rsp, @intCast(stack_size));
        }
    }

    fn emitEpilogue(ptr: *anyopaque, buf: *CodeBuffer, storage: *StorageManager) !void {
        _ = ptr;
        _ = storage;
        // Standard x86-64 function epilogue
        // mov rsp, rbp
        try movRegReg(buf, .rsp, .rbp);
        // pop rbp
        try popReg(buf, .rbp);
        // ret
        try ret(buf);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "mov reg64 reg64" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try movRegReg(&buf, .rax, .rcx);
    // Expected: 48 89 C8 (REX.W MOV rax, rcx)
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x89, 0xC8 }, buf.getBytes());
}

test "mov reg64 imm32" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try movRegImm32(&buf, .rax, 42);
    // Expected: 48 C7 C0 2A 00 00 00
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00 }, buf.getBytes());
}

test "add reg64 reg64" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try addRegReg(&buf, .rax, .rbx);
    // Expected: 48 01 D8 (REX.W ADD rax, rbx)
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x01, 0xD8 }, buf.getBytes());
}

test "push pop reg64" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try pushReg(&buf, .rbp);
    try popReg(&buf, .rbp);
    // Expected: 55 5D
    try std.testing.expectEqualSlices(u8, &.{ 0x55, 0x5D }, buf.getBytes());
}

test "extended registers" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try movRegReg(&buf, .r8, .r9);
    // Expected: 4D 89 C8 (REX.WRB MOV r8, r9)
    try std.testing.expectEqualSlices(u8, &.{ 0x4D, 0x89, 0xC8 }, buf.getBytes());
}

test "jcc rel32" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try jccRel32(&buf, .e, 0x100);
    // Expected: 0F 84 00 01 00 00
    try std.testing.expectEqualSlices(u8, &.{ 0x0F, 0x84, 0x00, 0x01, 0x00, 0x00 }, buf.getBytes());
}

test "x86_64 backend init" {
    const allocator = std.testing.allocator;
    var x86_be = X86_64Backend.init(allocator);
    defer x86_be.deinit();

    // Check that registers were initialized
    try std.testing.expect(x86_be.storage.free_general_regs.items.len > 0);
}
