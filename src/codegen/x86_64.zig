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
const types = @import("../types.zig");

const Allocator = std.mem.Allocator;
const TypeRegistry = types.TypeRegistry;
const Location = ssa.Location;

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

/// LEA reg, [rip+symbol] - Load effective address with RIP-relative symbol
/// Used to load address of data in rodata section
pub fn leaRipSymbol(buf: *CodeBuffer, dst: Reg, symbol: []const u8) !void {
    // REX.W prefix for 64-bit operand, REX.R if dst is extended
    try buf.emit8(0x48 | (if (dst.needsRex()) @as(u8, 0x04) else 0));
    // LEA opcode
    try buf.emit8(0x8D);
    // ModRM: mod=00, reg=dst, rm=101 (RIP-relative)
    try buf.emit8((dst.low3() << 3) | 0x05);
    // RIP-relative displacement (placeholder for linker)
    try buf.addRelocation(.pc_rel_32, symbol, -4);
    try buf.emit32(0);
}

/// SYSCALL instruction
pub fn syscall(buf: *CodeBuffer) !void {
    try buf.emit8(0x0F);
    try buf.emit8(0x05);
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

/// SETcc r8 - set byte based on condition
pub fn setcc(buf: *CodeBuffer, cc: CondCode, dst: Reg) !void {
    // REX prefix needed for:
    // - r8-r15: to access r8b-r15b (REX.B)
    // - rsp/rbp/rsi/rdi (4-7): to access spl/bpl/sil/dil instead of ah/ch/dh/bh
    if (@intFromEnum(dst) >= 8) {
        try buf.emit8(0x41); // REX.B
    } else if (@intFromEnum(dst) >= 4) {
        try buf.emit8(0x40); // REX (no extension bits, just enables new byte regs)
    }
    try buf.emit8(0x0F);
    try buf.emit8(0x90 | @intFromEnum(cc));
    try buf.emit8(0xC0 | (@intFromEnum(dst) & 0x7));
}

/// MOVZX r64, r8 - zero extend byte register to 64-bit
pub fn movzxReg8(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    try buf.emit8(rex(true, dst, src));
    try buf.emit8(0x0F);
    try buf.emit8(0xB6);
    try buf.emit8(ModRM.regReg(dst, src));
}

// ============================================================================
// CMOVcc Instructions (conditional move)
// ============================================================================

/// CMOVcc r64, r64 - conditional move based on condition code
pub fn cmovccRegReg(buf: *CodeBuffer, cc: CondCode, dst: Reg, src: Reg) !void {
    try buf.emit8(rex(true, dst, src));
    try buf.emit8(0x0F);
    try buf.emit8(0x40 | @intFromEnum(cc));
    try buf.emit8(ModRM.regReg(dst, src));
}

/// CMOVE r64, r64 - move if equal (ZF=1)
pub fn cmoveRegReg(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    try cmovccRegReg(buf, .e, dst, src);
}

/// CMOVNE r64, r64 - move if not equal (ZF=0)
pub fn cmovneRegReg(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    try cmovccRegReg(buf, .ne, dst, src);
}

pub fn cmovlRegReg(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    try cmovccRegReg(buf, .l, dst, src);
}

pub fn cmovleRegReg(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    try cmovccRegReg(buf, .le, dst, src);
}

pub fn cmovgRegReg(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    try cmovccRegReg(buf, .g, dst, src);
}

pub fn cmovgeRegReg(buf: *CodeBuffer, dst: Reg, src: Reg) !void {
    try cmovccRegReg(buf, .ge, dst, src);
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
// Byte-Level Memory Operations (for native map implementation)
// ============================================================================

/// MOVZX r64, byte [base+offset] - Load byte with zero extension
pub fn movzxRegMem8(buf: *CodeBuffer, dst: Reg, base: Reg, offset: i32) !void {
    // REX.W + 0F B6 /r (same pattern as movRegMem but with 0F B6 opcode)
    try buf.emit8(rex(true, dst, base));
    try buf.emit8(0x0F);
    try buf.emit8(0xB6);

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

/// MOV byte [base+offset], r8 - Store low byte of register
pub fn movMem8Reg(buf: *CodeBuffer, base: Reg, offset: i32, src: Reg) !void {
    // REX prefix for extended registers or to access low byte of RSI/RDI/RSP/RBP
    var rex_byte: u8 = 0x40; // REX base
    if (src.needsRex()) rex_byte |= REX_R;
    if (base.needsRex()) rex_byte |= REX_B;
    // Always emit REX if accessing SIL/DIL/BPL/SPL (src is rsi/rdi/rbp/rsp)
    if (@intFromEnum(src) >= 4 and @intFromEnum(src) <= 7) rex_byte |= 0x40;

    if (rex_byte != 0x40 or @intFromEnum(src) >= 4) {
        try buf.emit8(rex_byte);
    }

    try buf.emit8(0x88); // MOV r/m8, r8

    // Handle addressing modes
    if (base == .rsp or base == .r12) {
        if (offset == 0) {
            try buf.emit8((src.low3() << 3) | 0x04);
            try buf.emit8(0x24);
        } else if (offset >= -128 and offset <= 127) {
            try buf.emit8(0x44 | (src.low3() << 3));
            try buf.emit8(0x24);
            try buf.emit8(@bitCast(@as(i8, @intCast(offset))));
        } else {
            try buf.emit8(0x84 | (src.low3() << 3));
            try buf.emit8(0x24);
            try buf.emit32(@bitCast(offset));
        }
    } else if (base == .rbp or base == .r13) {
        if (offset >= -128 and offset <= 127) {
            try buf.emit8(0x45 | (src.low3() << 3));
            try buf.emit8(@bitCast(@as(i8, @intCast(offset))));
        } else {
            try buf.emit8(0x85 | (src.low3() << 3));
            try buf.emit32(@bitCast(offset));
        }
    } else {
        if (offset == 0) {
            try buf.emit8((src.low3() << 3) | base.low3());
        } else if (offset >= -128 and offset <= 127) {
            try buf.emit8(0x40 | (src.low3() << 3) | base.low3());
            try buf.emit8(@bitCast(@as(i8, @intCast(offset))));
        } else {
            try buf.emit8(0x80 | (src.low3() << 3) | base.low3());
            try buf.emit32(@bitCast(offset));
        }
    }
}

/// XOR r64, imm32 (sign-extended)
pub fn xorRegImm32(buf: *CodeBuffer, dst: Reg, imm: i32) !void {
    try buf.emit8(rex1(true, dst));
    try buf.emit8(0x81);
    try buf.emit8(ModRM.opExt(ModRM.direct, 6, dst)); // /6 for XOR
    try buf.emit32(@bitCast(imm));
}

/// INC r64
pub fn incReg(buf: *CodeBuffer, dst: Reg) !void {
    try buf.emit8(rex1(true, dst));
    try buf.emit8(0xFF);
    try buf.emit8(ModRM.opExt(ModRM.direct, 0, dst)); // /0 for INC
}

/// DEC r64
pub fn decReg(buf: *CodeBuffer, dst: Reg) !void {
    try buf.emit8(rex1(true, dst));
    try buf.emit8(0xFF);
    try buf.emit8(ModRM.opExt(ModRM.direct, 1, dst)); // /1 for DEC
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
// SSA Codegen (Go-style: separate from instruction encoding)
// ============================================================================
// This section contains the SSA-to-machine-code translation, following Go's
// amd64/ssa.go pattern. The instruction encoding functions above are used
// by this higher-level codegen.

/// Scratch registers for codegen - NEVER allocated by regalloc
pub const scratch0: Reg = .r10;
pub const scratch1: Reg = .r11;

/// Jump patch record for fixing up forward jumps
pub const JumpPatch = struct {
    patch_offset: u32, // Offset right after the rel32 field
    target_block: u32, // Target block index
};

/// Align value up to alignment boundary
pub fn alignTo(value: u32, alignment: u32) u32 {
    return (value + alignment - 1) & ~(alignment - 1);
}

/// Load a value from its location into a register
pub fn loadToReg(buf: *CodeBuffer, reg: Reg, loc: Location) !void {
    switch (loc) {
        .reg => |r| {
            if (r != @intFromEnum(reg)) {
                try movRegReg(buf, reg, @enumFromInt(r));
            }
        },
        .stack => |offset| {
            try movRegMem(buf, reg, .rbp, offset);
        },
        .none => {},
    }
}

/// Generate code for one SSA value (Go's ssaGenValue pattern)
pub fn generateValue(
    buf: *CodeBuffer,
    func: *ssa.Func,
    value: *ssa.Value,
    type_reg: *TypeRegistry,
    os: be.OS,
    string_offsets: *std.StringHashMap(u32),
    allocator: Allocator,
) !void {
    // Get destination location (pre-assigned by regalloc)
    const dest_loc = func.locations.items[value.id];

    switch (value.op) {
        .const_int => {
            if (dest_loc.getReg()) |dest_reg| {
                try movRegImm64(buf, @enumFromInt(dest_reg), value.aux_int);
            } else if (dest_loc.getStack()) |offset| {
                try movRegImm64(buf, scratch0, value.aux_int);
                try movMemReg(buf, .rbp, offset, scratch0);
            }
        },

        .add => {
            const dest_reg = dest_loc.getReg() orelse return;
            const left_loc = func.locations.items[value.args()[0]];
            const right_loc = func.locations.items[value.args()[1]];

            try loadToReg(buf, @enumFromInt(dest_reg), left_loc);

            if (right_loc.getReg()) |r| {
                try addRegReg(buf, @enumFromInt(dest_reg), @enumFromInt(r));
            } else if (right_loc.getStack()) |offset| {
                try movRegMem(buf, .r11, .rbp, offset);
                try addRegReg(buf, @enumFromInt(dest_reg), .r11);
            }
        },

        .sub => {
            const dest_reg: Reg = @enumFromInt(dest_loc.getReg() orelse return);
            const left_loc = func.locations.items[value.args()[0]];
            const right_loc = func.locations.items[value.args()[1]];

            try loadToReg(buf, dest_reg, left_loc);

            if (right_loc.getReg()) |r| {
                try subRegReg(buf, dest_reg, @enumFromInt(r));
            } else if (right_loc.getStack()) |offset| {
                try movRegMem(buf, .r11, .rbp, offset);
                try subRegReg(buf, dest_reg, .r11);
            }
        },

        .mul => {
            const dest_reg: Reg = @enumFromInt(dest_loc.getReg() orelse return);
            const left_loc = func.locations.items[value.args()[0]];
            const right_loc = func.locations.items[value.args()[1]];

            try loadToReg(buf, dest_reg, left_loc);

            if (right_loc.getReg()) |r| {
                try imulRegReg(buf, dest_reg, @enumFromInt(r));
            } else if (right_loc.getStack()) |offset| {
                try movRegMem(buf, .r11, .rbp, offset);
                try imulRegReg(buf, dest_reg, .r11);
            }
        },

        .div => {
            // x86 division: RAX = RDX:RAX / operand, RDX = remainder
            const left_loc = func.locations.items[value.args()[0]];
            const right_loc = func.locations.items[value.args()[1]];

            try loadToReg(buf, .rax, left_loc);
            try cqo(buf); // Sign-extend RAX into RDX:RAX

            if (right_loc.getReg()) |r| {
                try idivReg(buf, @enumFromInt(r));
            } else if (right_loc.getStack()) |offset| {
                try movRegMem(buf, .r11, .rbp, offset);
                try idivReg(buf, .r11);
            }

            // Result in RAX, move to dest if different
            if (dest_loc.getReg()) |dest_reg| {
                if (dest_reg != @intFromEnum(Reg.rax)) {
                    try movRegReg(buf, @enumFromInt(dest_reg), .rax);
                }
            } else if (dest_loc.getStack()) |offset| {
                try movMemReg(buf, .rbp, offset, .rax);
            }
        },

        .mod => {
            const left_loc = func.locations.items[value.args()[0]];
            const right_loc = func.locations.items[value.args()[1]];

            try loadToReg(buf, .rax, left_loc);
            try cqo(buf);

            if (right_loc.getReg()) |r| {
                try idivReg(buf, @enumFromInt(r));
            } else if (right_loc.getStack()) |offset| {
                try movRegMem(buf, .r11, .rbp, offset);
                try idivReg(buf, .r11);
            }

            // Remainder in RDX
            if (dest_loc.getReg()) |dest_reg| {
                if (dest_reg != @intFromEnum(Reg.rdx)) {
                    try movRegReg(buf, @enumFromInt(dest_reg), .rdx);
                }
            } else if (dest_loc.getStack()) |offset| {
                try movMemReg(buf, .rbp, offset, .rdx);
            }
        },

        .neg => {
            const dest_reg: Reg = @enumFromInt(dest_loc.getReg() orelse return);
            const src_loc = func.locations.items[value.args()[0]];
            try loadToReg(buf, dest_reg, src_loc);
            try negReg(buf, dest_reg);
        },

        // Comparison ops
        .eq, .ne, .lt, .le, .gt, .ge => {
            const dest_reg = dest_loc.getReg() orelse return;
            const left_loc = func.locations.items[value.args()[0]];
            const right_loc = func.locations.items[value.args()[1]];

            try loadToReg(buf, scratch0, left_loc);

            if (right_loc.getReg()) |r| {
                try cmpRegReg(buf, scratch0, @enumFromInt(r));
            } else if (right_loc.getStack()) |offset| {
                try movRegMem(buf, scratch1, .rbp, offset);
                try cmpRegReg(buf, scratch0, scratch1);
            }

            // Clear dest, then set based on condition
            try xorRegReg(buf, @enumFromInt(dest_reg), @enumFromInt(dest_reg));
            try movRegImm64(buf, scratch0, 1);

            switch (value.op) {
                .eq => try cmoveRegReg(buf, @enumFromInt(dest_reg), scratch0),
                .ne => try cmovneRegReg(buf, @enumFromInt(dest_reg), scratch0),
                .lt => try cmovlRegReg(buf, @enumFromInt(dest_reg), scratch0),
                .le => try cmovleRegReg(buf, @enumFromInt(dest_reg), scratch0),
                .gt => try cmovgRegReg(buf, @enumFromInt(dest_reg), scratch0),
                .ge => try cmovgeRegReg(buf, @enumFromInt(dest_reg), scratch0),
                else => {},
            }
        },

        // Bitwise ops
        .bit_and => {
            const dest_reg: Reg = @enumFromInt(dest_loc.getReg() orelse return);
            const left_loc = func.locations.items[value.args()[0]];
            const right_loc = func.locations.items[value.args()[1]];
            try loadToReg(buf, dest_reg, left_loc);
            if (right_loc.getReg()) |r| {
                try andRegReg(buf, dest_reg, @enumFromInt(r));
            } else if (right_loc.getStack()) |offset| {
                try movRegMem(buf, scratch1, .rbp, offset);
                try andRegReg(buf, dest_reg, scratch1);
            }
        },

        .bit_or => {
            const dest_reg: Reg = @enumFromInt(dest_loc.getReg() orelse return);
            const left_loc = func.locations.items[value.args()[0]];
            const right_loc = func.locations.items[value.args()[1]];
            try loadToReg(buf, dest_reg, left_loc);
            if (right_loc.getReg()) |r| {
                try orRegReg(buf, dest_reg, @enumFromInt(r));
            } else if (right_loc.getStack()) |offset| {
                try movRegMem(buf, scratch1, .rbp, offset);
                try orRegReg(buf, dest_reg, scratch1);
            }
        },

        .bit_xor => {
            const dest_reg: Reg = @enumFromInt(dest_loc.getReg() orelse return);
            const left_loc = func.locations.items[value.args()[0]];
            const right_loc = func.locations.items[value.args()[1]];
            try loadToReg(buf, dest_reg, left_loc);
            if (right_loc.getReg()) |r| {
                try xorRegReg(buf, dest_reg, @enumFromInt(r));
            } else if (right_loc.getStack()) |offset| {
                try movRegMem(buf, scratch1, .rbp, offset);
                try xorRegReg(buf, dest_reg, scratch1);
            }
        },

        .shl => {
            const dest_reg: Reg = @enumFromInt(dest_loc.getReg() orelse return);
            const left_loc = func.locations.items[value.args()[0]];
            const shift_val = func.getValue(value.args()[1]);
            try loadToReg(buf, dest_reg, left_loc);
            if (shift_val.op == .const_int) {
                try shlRegImm(buf, dest_reg, @intCast(shift_val.aux_int));
            }
        },

        .shr => {
            const dest_reg: Reg = @enumFromInt(dest_loc.getReg() orelse return);
            const left_loc = func.locations.items[value.args()[0]];
            const shift_val = func.getValue(value.args()[1]);
            try loadToReg(buf, dest_reg, left_loc);
            if (shift_val.op == .const_int) {
                try shrRegImm(buf, dest_reg, @intCast(shift_val.aux_int));
            }
        },

        // Logical ops
        .@"and" => {
            const dest_reg = dest_loc.getReg() orelse return;
            const left_loc = func.locations.items[value.args()[0]];
            const right_loc = func.locations.items[value.args()[1]];
            try loadToReg(buf, @enumFromInt(dest_reg), left_loc);
            try testRegReg(buf, @enumFromInt(dest_reg), @enumFromInt(dest_reg));
            try buf.emit8(0x0F);
            try buf.emit8(0x84); // JZ
            const jz_patch = buf.pos();
            try buf.emit32(0);
            try loadToReg(buf, @enumFromInt(dest_reg), right_loc);
            const after = buf.pos();
            const offset: i32 = @intCast(after - jz_patch);
            buf.patch32(jz_patch - 4, offset);
        },

        .@"or" => {
            const dest_reg = dest_loc.getReg() orelse return;
            const left_loc = func.locations.items[value.args()[0]];
            const right_loc = func.locations.items[value.args()[1]];
            try loadToReg(buf, @enumFromInt(dest_reg), left_loc);
            try testRegReg(buf, @enumFromInt(dest_reg), @enumFromInt(dest_reg));
            try buf.emit8(0x0F);
            try buf.emit8(0x85); // JNZ
            const jnz_patch = buf.pos();
            try buf.emit32(0);
            try loadToReg(buf, @enumFromInt(dest_reg), right_loc);
            const after = buf.pos();
            const offset: i32 = @intCast(after - jnz_patch);
            buf.patch32(jnz_patch - 4, offset);
        },

        .not => {
            const dest_reg = dest_loc.getReg() orelse return;
            const src_loc = func.locations.items[value.args()[0]];
            try loadToReg(buf, @enumFromInt(dest_reg), src_loc);
            try testRegReg(buf, @enumFromInt(dest_reg), @enumFromInt(dest_reg));
            try xorRegReg(buf, @enumFromInt(dest_reg), @enumFromInt(dest_reg));
            try movRegImm64(buf, scratch0, 1);
            try cmoveRegReg(buf, @enumFromInt(dest_reg), scratch0);
        },

        // Store operation
        .store => {
            const local_idx: usize = @intCast(value.args()[0]);
            const field_offset: i32 = @intCast(value.aux_int);
            if (local_idx < func.locals.len) {
                const local = func.locals[local_idx];
                const total_offset = local.offset + field_offset;
                const src_value = &func.values.items[value.args()[1]];
                const size = type_reg.sizeOf(src_value.type_idx);

                // Special handling for multi-register values (slice, union)
                if (src_value.op == .slice_make or src_value.op == .union_init) {
                    try movMemReg(buf, .rbp, total_offset, .rax);
                    try movMemReg(buf, .rbp, total_offset + 8, .rdx);
                } else if (src_value.op == .slice_index or src_value.op == .index) {
                    if (size == 1) {
                        try movMem8Reg(buf, .rbp, total_offset, .rax);
                    } else {
                        try movMemReg(buf, .rbp, total_offset, .rax);
                    }
                } else if (src_value.op == .const_string) {
                    // String literal handling
                    const str_content = src_value.aux_str;
                    const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                        str_content[1 .. str_content.len - 1]
                    else
                        str_content;

                    if (string_offsets.get(stripped)) |str_offset| {
                        const sym_name = std.fmt.allocPrint(allocator, ".str.{d}", .{str_offset}) catch return;
                        try leaRipSymbol(buf, .rax, sym_name);
                        try movMemReg(buf, .rbp, total_offset, .rax);
                        try movRegImm64(buf, .rax, @intCast(stripped.len));
                        try movMemReg(buf, .rbp, total_offset + 8, .rax);
                    } else {
                        try xorRegReg(buf, .rax, .rax);
                        try movMemReg(buf, .rbp, total_offset, .rax);
                        try movMemReg(buf, .rbp, total_offset + 8, .rax);
                    }
                } else {
                    const src_loc = func.locations.items[value.args()[1]];
                    if (src_loc.getReg()) |r| {
                        if (size == 1) {
                            try movMem8Reg(buf, .rbp, total_offset, @enumFromInt(r));
                        } else {
                            try movMemReg(buf, .rbp, total_offset, @enumFromInt(r));
                        }
                    } else if (src_loc.getStack()) |src_offset| {
                        try movRegMem(buf, scratch0, .rbp, src_offset);
                        if (size == 1) {
                            try movMem8Reg(buf, .rbp, total_offset, scratch0);
                        } else {
                            try movMemReg(buf, .rbp, total_offset, scratch0);
                        }
                    }
                }
            }
        },

        // Load operation
        .load => {
            const local_idx: usize = @intCast(value.args()[0]);
            const field_offset: i32 = @intCast(value.aux_int);
            if (local_idx < func.locals.len) {
                const local = func.locals[local_idx];
                const total_offset = local.offset + field_offset;
                const size = type_reg.sizeOf(value.type_idx);

                if (dest_loc.getReg()) |dest_reg| {
                    if (size == 1) {
                        try movzxRegMem8(buf, @enumFromInt(dest_reg), .rbp, total_offset);
                    } else {
                        try movRegMem(buf, @enumFromInt(dest_reg), .rbp, total_offset);
                    }
                }
            }
        },

        // Function call
        .call => {
            // SysV ABI: args in rdi, rsi, rdx, rcx, r8, r9
            const arg_regs = [_]Reg{ .rdi, .rsi, .rdx, .rcx, .r8, .r9 };
            const args = value.args();

            // Load args into registers (skip first arg which is function ref)
            for (args[1..], 0..) |arg, i| {
                if (i >= arg_regs.len) break;
                const arg_loc = func.locations.items[arg];
                try loadToReg(buf, arg_regs[i], arg_loc);
            }

            // Emit call
            if (value.aux_str.len > 0) {
                // External call via PLT
                const sym_name = std.fmt.allocPrint(allocator, "{s}@PLT", .{value.aux_str}) catch return;
                try callSymbol(buf, sym_name, os);
            }

            // Result in rax
            if (dest_loc.getReg()) |dest_reg| {
                if (dest_reg != @intFromEnum(Reg.rax)) {
                    try movRegReg(buf, @enumFromInt(dest_reg), .rax);
                }
            } else if (dest_loc.getStack()) |offset| {
                try movMemReg(buf, .rbp, offset, .rax);
            }
        },

        // ========== Slice Operations ==========
        .slice_make => {
            // Slice construction from array or string
            // args[0] = source local index (raw), args[1] = start (SSA), args[2] = end (SSA)
            // aux_int = element size
            // Result: rax = ptr (base + start*elem_size), rdx = len (end - start)
            const args = value.args();
            if (args.len >= 3) {
                const local_idx = args[0];
                const start_id = args[1];
                const end_id = args[2];
                const elem_size: i64 = value.aux_int;

                const start_val = func.getValue(start_id);
                const end_val = func.getValue(end_id);

                if (local_idx < func.locals.len) {
                    const local_offset: i32 = func.locals[@intCast(local_idx)].offset;
                    const local_size = func.locals[@intCast(local_idx)].size;

                    // IMPORTANT: Load start/end FIRST before we touch rax/rdx
                    // Get start value into r9
                    if (start_val.op == .const_int) {
                        try movRegImm64(buf, .r9, start_val.aux_int);
                    } else {
                        try loadToReg(buf, .r9, func.locations.items[start_id]);
                    }

                    // Get end value into scratch0 (not rdx yet)
                    if (end_val.op == .const_int) {
                        try movRegImm64(buf, scratch0, end_val.aux_int);
                    } else {
                        try loadToReg(buf, scratch0, func.locations.items[end_id]);
                    }

                    // Now safe to use rax - load base address
                    if (local_size == 16) {
                        try movRegMem(buf, .rax, .rbp, local_offset);
                    } else {
                        try leaRegMem(buf, .rax, .rbp, local_offset);
                    }

                    // ptr = base + start * elem_size
                    if (elem_size == 1) {
                        try addRegReg(buf, .rax, .r9);
                    } else {
                        try imulRegRegImm(buf, scratch1, .r9, @intCast(elem_size));
                        try addRegReg(buf, .rax, scratch1);
                    }

                    // len = end - start
                    try movRegReg(buf, .rdx, scratch0);
                    try subRegReg(buf, .rdx, .r9);
                }
            }
        },

        .slice_index => {
            // Slice indexing: load ptr from slice, compute ptr + index*elem_size, load value
            const args = value.args();
            if (args.len >= 2) {
                const local_idx = args[0];
                const idx_val_id = args[1];
                const idx_val = func.getValue(idx_val_id);
                const elem_size: i64 = value.aux_int;

                if (local_idx < func.locals.len) {
                    const local_offset: i32 = func.locals[@intCast(local_idx)].offset;

                    // Load slice ptr into rax
                    try movRegMem(buf, .rax, .rbp, local_offset);

                    // Get index into r9
                    if (idx_val.op == .const_int) {
                        try movRegImm64(buf, .r9, idx_val.aux_int);
                    } else {
                        try loadToReg(buf, .r9, func.locations.items[idx_val_id]);
                    }

                    // Compute offset: r9 = index * elem_size
                    if (elem_size != 1) {
                        try imulRegRegImm(buf, .r9, .r9, @intCast(elem_size));
                    }

                    // Add to base: rax = ptr + offset
                    try addRegReg(buf, .rax, .r9);

                    // Load value from computed address
                    const size = type_reg.sizeOf(value.type_idx);
                    if (size == 1) {
                        try movzxRegMem8(buf, .rax, .rax, 0);
                    } else {
                        try movRegMem(buf, .rax, .rax, 0);
                    }
                }
            }
        },

        // ========== Union Operations ==========
        .union_init => {
            // Initialize union: aux_int = variant index (tag)
            // args[0] = payload (if any)
            // Result: rax = tag, rdx = payload
            const tag: i64 = value.aux_int;
            try movRegImm64(buf, .rax, tag);

            const args = value.args();
            if (args.len > 0) {
                const payload_val = func.getValue(args[0]);
                if (payload_val.op == .const_int) {
                    try movRegImm64(buf, .rdx, payload_val.aux_int);
                } else {
                    try loadToReg(buf, .rdx, func.locations.items[args[0]]);
                }
            } else {
                try xorRegReg(buf, .rdx, .rdx);
            }
        },

        .union_tag => {
            // Get union tag: args[0] = union local
            const args = value.args();
            if (args.len > 0) {
                const local_idx = args[0];
                if (local_idx < func.locals.len) {
                    const local_offset: i32 = func.locals[@intCast(local_idx)].offset;
                    try movRegMem(buf, .rax, .rbp, local_offset);
                }
            }
        },

        .union_payload => {
            // Get union payload: args[0] = union local
            const args = value.args();
            if (args.len > 0) {
                const local_idx = args[0];
                if (local_idx < func.locals.len) {
                    const local_offset: i32 = func.locals[@intCast(local_idx)].offset;
                    try movRegMem(buf, .rax, .rbp, local_offset + 8);
                }
            }
        },

        // ========== Array Index ==========
        .index => {
            // Array indexing: compute base + index*elem_size, load value
            const args = value.args();
            if (args.len >= 2) {
                const local_idx = args[0];
                const idx_val_id = args[1];
                const idx_val = func.getValue(idx_val_id);
                const elem_size: i64 = value.aux_int;

                if (local_idx < func.locals.len) {
                    const local_offset: i32 = func.locals[@intCast(local_idx)].offset;

                    // Load array base address
                    try leaRegMem(buf, .rax, .rbp, local_offset);

                    // Get index into r9
                    if (idx_val.op == .const_int) {
                        try movRegImm64(buf, .r9, idx_val.aux_int);
                    } else {
                        try loadToReg(buf, .r9, func.locations.items[idx_val_id]);
                    }

                    // Compute offset
                    if (elem_size != 1) {
                        try imulRegRegImm(buf, .r9, .r9, @intCast(elem_size));
                    }

                    try addRegReg(buf, .rax, .r9);

                    // Load value
                    const size = type_reg.sizeOf(value.type_idx);
                    if (size == 1) {
                        try movzxRegMem8(buf, .rax, .rax, 0);
                    } else {
                        try movRegMem(buf, .rax, .rax, 0);
                    }
                }
            }
        },

        // ========== String Operations ==========
        .str_concat => {
            // Concatenate two strings via runtime call
            const sym_name = if (os == .macos) "_cot_str_concat" else "cot_str_concat";
            try callSymbol(buf, sym_name, os);
        },

        // ========== Const Values ==========
        .const_bool => {
            if (dest_loc.getReg()) |dest_reg| {
                const val: i64 = if (value.aux_int != 0) 1 else 0;
                try movRegImm64(buf, @enumFromInt(dest_reg), val);
            }
        },

        .const_nil => {
            if (dest_loc.getReg()) |dest_reg| {
                try xorRegReg(buf, @enumFromInt(dest_reg), @enumFromInt(dest_reg));
            }
        },

        .const_string => {
            // String constants are handled in .store
        },

        // NOTE: More ops to be migrated (map, list FFI ops)

        else => {
            // Ops not yet migrated
        },
    }
}

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

// ============================================================================
// Instruction Encoding Validation Tests
// These tests verify byte-exact encodings against known-correct x86_64 values.
// Reference: Intel 64 and IA-32 Architectures Software Developer's Manual
// ============================================================================

test "SUB rax, rbx encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try subRegReg(&buf, .rax, .rbx);
    // SUB rax, rbx: REX.W (48) + 29 /r (SUB r/m64, r64) + ModRM C8 (rbx -> rax)
    // = 48 29 D8
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x29, 0xD8 }, buf.getBytes());
}

test "SUB r8, r9 encoding (extended regs)" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try subRegReg(&buf, .r8, .r9);
    // SUB r8, r9: REX.WRB (4D) + 29 + ModRM C8
    // = 4D 29 C8
    try std.testing.expectEqualSlices(u8, &.{ 0x4D, 0x29, 0xC8 }, buf.getBytes());
}

test "CMP rax, rbx encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try cmpRegReg(&buf, .rax, .rbx);
    // CMP rax, rbx: REX.W (48) + 39 /r + ModRM D8 (rbx -> rax)
    // = 48 39 D8
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x39, 0xD8 }, buf.getBytes());
}

test "CMP r8, r9 encoding (extended regs)" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try cmpRegReg(&buf, .r8, .r9);
    // CMP r8, r9: REX.WRB (4D) + 39 + ModRM C8
    // = 4D 39 C8
    try std.testing.expectEqualSlices(u8, &.{ 0x4D, 0x39, 0xC8 }, buf.getBytes());
}

test "CMP rax, imm32 encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try cmpRegImm32(&buf, .rax, 42);
    // CMP rax, 42: REX.W (48) + 81 /7 + ModRM F8 + imm32
    // = 48 81 F8 2A 00 00 00
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x81, 0xF8, 0x2A, 0x00, 0x00, 0x00 }, buf.getBytes());
}

test "IMUL rax, rbx encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try imulRegReg(&buf, .rax, .rbx);
    // IMUL rax, rbx: REX.W (48) + 0F AF /r + ModRM C3
    // = 48 0F AF C3
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x0F, 0xAF, 0xC3 }, buf.getBytes());
}

test "IDIV rbx encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try idivReg(&buf, .rbx);
    // IDIV rbx: REX.W (48) + F7 /7 + ModRM FB
    // = 48 F7 FB
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0xF7, 0xFB }, buf.getBytes());
}

test "NEG rax encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try negReg(&buf, .rax);
    // NEG rax: REX.W (48) + F7 /3 + ModRM D8
    // = 48 F7 D8
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0xF7, 0xD8 }, buf.getBytes());
}

test "MOV [rbp-8], rax encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try movMemReg(&buf, .rbp, -8, .rax);
    // MOV [rbp-8], rax: REX.W (48) + 89 + ModRM 45 (disp8) + F8 (-8)
    // = 48 89 45 F8
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x89, 0x45, 0xF8 }, buf.getBytes());
}

test "MOV rax, [rbp-8] encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try movRegMem(&buf, .rax, .rbp, -8);
    // MOV rax, [rbp-8]: REX.W (48) + 8B + ModRM 45 (disp8) + F8 (-8)
    // = 48 8B 45 F8
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x8B, 0x45, 0xF8 }, buf.getBytes());
}

test "MOV [rbp-256], rax encoding (disp32)" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try movMemReg(&buf, .rbp, -256, .rax);
    // MOV [rbp-256], rax: REX.W (48) + 89 + ModRM 85 (disp32) + imm32 (-256 = 0xFFFFFF00)
    // = 48 89 85 00 FF FF FF
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x89, 0x85, 0x00, 0xFF, 0xFF, 0xFF }, buf.getBytes());
}

test "RET encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try ret(&buf);
    // RET: C3
    try std.testing.expectEqualSlices(u8, &.{0xC3}, buf.getBytes());
}

test "JE rel32 encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try jccRel32(&buf, .e, 0);
    // JE rel32: 0F 84 + rel32
    // = 0F 84 00 00 00 00
    try std.testing.expectEqualSlices(u8, &.{ 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 }, buf.getBytes());
}

test "JNE rel32 encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try jccRel32(&buf, .ne, 0);
    // JNE rel32: 0F 85 + rel32
    // = 0F 85 00 00 00 00
    try std.testing.expectEqualSlices(u8, &.{ 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00 }, buf.getBytes());
}

test "JL rel32 encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try jccRel32(&buf, .l, 0);
    // JL rel32: 0F 8C + rel32
    // = 0F 8C 00 00 00 00
    try std.testing.expectEqualSlices(u8, &.{ 0x0F, 0x8C, 0x00, 0x00, 0x00, 0x00 }, buf.getBytes());
}

test "JGE rel32 encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try jccRel32(&buf, .ge, 0);
    // JGE rel32: 0F 8D + rel32
    // = 0F 8D 00 00 00 00
    try std.testing.expectEqualSlices(u8, &.{ 0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00 }, buf.getBytes());
}

test "CMOVE rax, rbx encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try cmoveRegReg(&buf, .rax, .rbx);
    // CMOVE rax, rbx: REX.W (48) + 0F 44 /r + ModRM C3
    // = 48 0F 44 C3
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x0F, 0x44, 0xC3 }, buf.getBytes());
}

test "AND rax, rbx encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try andRegReg(&buf, .rax, .rbx);
    // AND rax, rbx: REX.W (48) + 21 /r + ModRM D8
    // = 48 21 D8
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x21, 0xD8 }, buf.getBytes());
}

test "OR rax, rbx encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try orRegReg(&buf, .rax, .rbx);
    // OR rax, rbx: REX.W (48) + 09 /r + ModRM D8
    // = 48 09 D8
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x09, 0xD8 }, buf.getBytes());
}

test "XOR rax, rbx encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try xorRegReg(&buf, .rax, .rbx);
    // XOR rax, rbx: REX.W (48) + 31 /r + ModRM D8
    // = 48 31 D8
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x31, 0xD8 }, buf.getBytes());
}

test "SHL rax, 4 encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try shlRegImm(&buf, .rax, 4);
    // SHL rax, 4: REX.W (48) + C1 /4 + ModRM E0 + imm8
    // = 48 C1 E0 04
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0xC1, 0xE0, 0x04 }, buf.getBytes());
}

test "SHR rax, 4 encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try shrRegImm(&buf, .rax, 4);
    // SHR rax, 4: REX.W (48) + C1 /5 + ModRM E8 + imm8
    // = 48 C1 E8 04
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0xC1, 0xE8, 0x04 }, buf.getBytes());
}

test "LEA rax, [rbp-16] encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try leaRegMem(&buf, .rax, .rbp, -16);
    // LEA rax, [rbp-16]: REX.W (48) + 8D + ModRM 45 (disp8) + F0 (-16)
    // = 48 8D 45 F0
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x8D, 0x45, 0xF0 }, buf.getBytes());
}

test "CQO encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try cqo(&buf);
    // CQO: REX.W (48) + 99
    // = 48 99
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x99 }, buf.getBytes());
}
