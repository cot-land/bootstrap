///! AArch64 (ARM64) code generation backend.
///!
///! Combines patterns from:
///! - Roc: gen_dev/src/generic64/aarch64.rs (instruction encoding)
///! - ARM Architecture Reference Manual
///!
///! Key patterns:
///! - Fixed 32-bit instruction width
///! - 5-bit register encoding (0-31)
///! - Arithmetic ops use shifted register format
///! - MOV is aliased from ORR/MOVZ/MOVK

const std = @import("std");
const be = @import("backend.zig");
const ssa = @import("../ssa.zig");
const debug = @import("../debug.zig");

const Allocator = std.mem.Allocator;

// Scoped logger for AArch64 codegen
const log = debug.scoped(.codegen);
const CodeBuffer = be.CodeBuffer;
const StorageManager = be.StorageManager;
const Storage = be.Storage;
const GeneralReg = be.GeneralReg;

// ============================================================================
// AArch64 Registers
// ============================================================================

/// AArch64 general-purpose registers (64-bit: X0-X30, SP/ZR).
pub const Reg = enum(u5) {
    x0 = 0,
    x1 = 1,
    x2 = 2,
    x3 = 3,
    x4 = 4,
    x5 = 5,
    x6 = 6,
    x7 = 7,
    x8 = 8, // Indirect result (XR)
    x9 = 9,
    x10 = 10,
    x11 = 11,
    x12 = 12,
    x13 = 13,
    x14 = 14,
    x15 = 15,
    x16 = 16, // IP0 (intra-procedure scratch)
    x17 = 17, // IP1
    x18 = 18, // Platform register
    x19 = 19, // Callee-saved
    x20 = 20,
    x21 = 21,
    x22 = 22,
    x23 = 23,
    x24 = 24,
    x25 = 25,
    x26 = 26,
    x27 = 27,
    x28 = 28,
    fp = 29, // Frame pointer (X29)
    lr = 30, // Link register (X30)
    sp = 31, // Stack pointer / Zero register

    pub fn id(self: Reg) u5 {
        return @intFromEnum(self);
    }
};

/// Zero register (XZR/WZR) - encodes as 31.
pub const zr = Reg.sp;

/// AArch64 floating-point/SIMD registers.
pub const VReg = enum(u5) {
    v0 = 0,
    v1 = 1,
    v2 = 2,
    v3 = 3,
    v4 = 4,
    v5 = 5,
    v6 = 6,
    v7 = 7,
    // v8-v15 are callee-saved
    v8 = 8,
    v9 = 9,
    v10 = 10,
    v11 = 11,
    v12 = 12,
    v13 = 13,
    v14 = 14,
    v15 = 15,
    v16 = 16,
    v17 = 17,
    v18 = 18,
    v19 = 19,
    v20 = 20,
    v21 = 21,
    v22 = 22,
    v23 = 23,
    v24 = 24,
    v25 = 25,
    v26 = 26,
    v27 = 27,
    v28 = 28,
    v29 = 29,
    v30 = 30,
    v31 = 31,
};

/// Shift types for arithmetic operations.
pub const Shift = enum(u2) {
    lsl = 0b00, // Logical shift left
    lsr = 0b01, // Logical shift right
    asr = 0b10, // Arithmetic shift right
    ror = 0b11, // Rotate right (reserved for some ops)
};

/// Condition codes for conditional branches.
pub const Cond = enum(u4) {
    eq = 0b0000, // Equal (Z=1)
    ne = 0b0001, // Not equal (Z=0)
    cs = 0b0010, // Carry set / unsigned >= (C=1)
    cc = 0b0011, // Carry clear / unsigned < (C=0)
    mi = 0b0100, // Minus / negative (N=1)
    pl = 0b0101, // Plus / positive or zero (N=0)
    vs = 0b0110, // Overflow (V=1)
    vc = 0b0111, // No overflow (V=0)
    hi = 0b1000, // Unsigned higher (C=1 and Z=0)
    ls = 0b1001, // Unsigned lower or same
    ge = 0b1010, // Signed >= (N=V)
    lt = 0b1011, // Signed < (N!=V)
    gt = 0b1100, // Signed > (Z=0 and N=V)
    le = 0b1101, // Signed <= (Z=1 or N!=V)
    al = 0b1110, // Always
    nv = 0b1111, // Never (reserved)
};

// ============================================================================
// Instruction Encoding Helpers
// ============================================================================

/// Emit 32-bit instruction (little-endian).
fn emit32(buf: *CodeBuffer, inst: u32) !void {
    try buf.emit32(inst);
}

/// Build data processing (shifted register) instruction.
/// Format: sf|op|S|01011|shift|0|Rm|imm6|Rn|Rd
/// - sf: 1 for 64-bit, 0 for 32-bit
/// - op: 0 for ADD, 1 for SUB (bit 30)
/// - S: 1 to set flags (bit 29)
/// - Fixed pattern 01011 at bits 28-24
fn dataProcessingShifted(sf: bool, opc: u2, s: bool, rm: Reg, shift: Shift, imm6: u6, rn: Reg, rd: Reg) u32 {
    var inst: u32 = 0;
    if (sf) inst |= 1 << 31; // 64-bit
    // opc bit 1 is the op field (ADD=0, SUB=1) at bit 30
    inst |= @as(u32, (opc >> 1) & 1) << 30;
    if (s) inst |= 1 << 29; // S: set flags at bit 29
    inst |= 0b01011 << 24; // Fixed pattern at bits 28-24
    inst |= @as(u32, @intFromEnum(shift)) << 22;
    inst |= @as(u32, rm.id()) << 16;
    inst |= @as(u32, imm6) << 10;
    inst |= @as(u32, rn.id()) << 5;
    inst |= @as(u32, rd.id());
    return inst;
}

/// Build data processing (immediate) instruction for add/sub.
/// Format: sf|op|S|100010|sh|imm12|Rn|Rd
/// - sf: 1 for 64-bit, 0 for 32-bit
/// - op: 0 for ADD, 1 for SUB
/// - S: 1 to set flags (ADDS/SUBS), 0 otherwise
fn dataProcessingImm(sf: bool, op: u1, s: bool, sh: bool, imm12: u12, rn: Reg, rd: Reg) u32 {
    var inst: u32 = 0;
    if (sf) inst |= 1 << 31;
    inst |= @as(u32, op) << 30;
    if (s) inst |= 1 << 29;
    inst |= 0b100010 << 23;
    if (sh) inst |= 1 << 22; // Shift imm12 by 12
    inst |= @as(u32, imm12) << 10;
    inst |= @as(u32, rn.id()) << 5;
    inst |= @as(u32, rd.id());
    return inst;
}

/// Build logical (shifted register) instruction.
/// Format: sf|opc|01010|shift|N|Rm|imm6|Rn|Rd
fn logicalShifted(sf: bool, opc: u2, n: bool, rm: Reg, shift: Shift, imm6: u6, rn: Reg, rd: Reg) u32 {
    var inst: u32 = 0;
    if (sf) inst |= 1 << 31;
    inst |= @as(u32, opc) << 29;
    inst |= 0b01010 << 24;
    inst |= @as(u32, @intFromEnum(shift)) << 22;
    if (n) inst |= 1 << 21;
    inst |= @as(u32, rm.id()) << 16;
    inst |= @as(u32, imm6) << 10;
    inst |= @as(u32, rn.id()) << 5;
    inst |= @as(u32, rd.id());
    return inst;
}

/// Build move wide immediate instruction.
/// Format: sf|opc|100101|hw|imm16|Rd
fn moveWide(sf: bool, opc: u2, hw: u2, imm16: u16, rd: Reg) u32 {
    var inst: u32 = 0;
    if (sf) inst |= 1 << 31;
    inst |= @as(u32, opc) << 29;
    inst |= 0b100101 << 23;
    inst |= @as(u32, hw) << 21;
    inst |= @as(u32, imm16) << 5;
    inst |= @as(u32, rd.id());
    return inst;
}

/// Build load/store register (unsigned offset) instruction.
/// Format: size|111|V|01|opc|imm12|Rn|Rt
fn loadStoreUnsignedOffset(size: u2, v: bool, opc: u2, imm12: u12, rn: Reg, rt: Reg) u32 {
    var inst: u32 = 0;
    inst |= @as(u32, size) << 30;
    inst |= 0b111 << 27;
    if (v) inst |= 1 << 26; // SIMD/FP
    inst |= 0b01 << 24;
    inst |= @as(u32, opc) << 22;
    inst |= @as(u32, imm12) << 10;
    inst |= @as(u32, rn.id()) << 5;
    inst |= @as(u32, rt.id());
    return inst;
}

/// Build load/store register pair (pre/post index).
/// Format: opc|101|V|type|L|imm7|Rt2|Rn|Rt
fn loadStorePair(opc: u2, v: bool, indexType: u2, l: bool, imm7: u7, rt2: Reg, rn: Reg, rt: Reg) u32 {
    var inst: u32 = 0;
    inst |= @as(u32, opc) << 30;
    inst |= 0b101 << 27;
    if (v) inst |= 1 << 26;
    inst |= @as(u32, indexType) << 23;
    if (l) inst |= 1 << 22; // Load
    inst |= @as(u32, imm7) << 15;
    inst |= @as(u32, rt2.id()) << 10;
    inst |= @as(u32, rn.id()) << 5;
    inst |= @as(u32, rt.id());
    return inst;
}

/// Build unconditional branch (immediate).
/// Format: op|00101|imm26
fn branchImm(link: bool, imm26: i26) u32 {
    var inst: u32 = 0;
    if (link) inst |= 1 << 31; // BL vs B
    inst |= 0b00101 << 26;
    // Sign-extend to i32 first, then bitcast to u32, then mask to 26 bits
    const extended: i32 = imm26;
    inst |= @as(u32, @bitCast(extended)) & 0x3FFFFFF;
    return inst;
}

/// Build unconditional branch (register).
/// Format: 1101011|opc|11111|000000|Rn|00000
fn branchReg(opc: u2, rn: Reg) u32 {
    var inst: u32 = 0;
    inst |= 0b1101011 << 25;
    inst |= @as(u32, opc) << 21;
    inst |= 0b11111 << 16;
    inst |= @as(u32, rn.id()) << 5;
    return inst;
}

/// Build conditional branch (immediate).
/// Format: 01010100|imm19|0|cond
fn branchCond(cond: Cond, imm19: i19) u32 {
    var inst: u32 = 0;
    inst |= 0b01010100 << 24;
    // Sign-extend i19 to i32, then cast to u32, then mask
    const extended: i32 = imm19;
    inst |= (@as(u32, @bitCast(extended)) & 0x7FFFF) << 5;
    inst |= @as(u32, @intFromEnum(cond));
    return inst;
}

// ============================================================================
// Arithmetic Instructions
// ============================================================================

/// ADD Xd, Xn, Xm
pub fn addRegReg(buf: *CodeBuffer, rd: Reg, rn: Reg, rm: Reg) !void {
    try emit32(buf, dataProcessingShifted(true, 0b00, false, rm, .lsl, 0, rn, rd));
}

/// ADD Xd, Xn, #imm12
pub fn addRegImm12(buf: *CodeBuffer, rd: Reg, rn: Reg, imm12: u12) !void {
    try emit32(buf, dataProcessingImm(true, 0, false, false, imm12, rn, rd));
}

/// SUB Xd, Xn, Xm
pub fn subRegReg(buf: *CodeBuffer, rd: Reg, rn: Reg, rm: Reg) !void {
    try emit32(buf, dataProcessingShifted(true, 0b10, false, rm, .lsl, 0, rn, rd));
}

/// SUB Xd, Xn, #imm12
pub fn subRegImm12(buf: *CodeBuffer, rd: Reg, rn: Reg, imm12: u12) !void {
    try emit32(buf, dataProcessingImm(true, 1, false, false, imm12, rn, rd));
}

/// ADDS Xd, Xn, Xm (set flags)
pub fn addsRegReg(buf: *CodeBuffer, rd: Reg, rn: Reg, rm: Reg) !void {
    try emit32(buf, dataProcessingShifted(true, 0b00, true, rm, .lsl, 0, rn, rd));
}

/// SUBS Xd, Xn, Xm (set flags)
pub fn subsRegReg(buf: *CodeBuffer, rd: Reg, rn: Reg, rm: Reg) !void {
    try emit32(buf, dataProcessingShifted(true, 0b10, true, rm, .lsl, 0, rn, rd));
}

/// CMP Xn, Xm (SUBS XZR, Xn, Xm)
pub fn cmpRegReg(buf: *CodeBuffer, rn: Reg, rm: Reg) !void {
    try emit32(buf, dataProcessingShifted(true, 0b10, true, rm, .lsl, 0, rn, zr));
}

/// CMP Xn, #imm12 (SUBS XZR, Xn, #imm12)
pub fn cmpRegImm12(buf: *CodeBuffer, rn: Reg, imm12: u12) !void {
    try emit32(buf, dataProcessingImm(true, 1, true, false, imm12, rn, zr));
}

/// CSET Xd, cond - Set register to 1 if condition true, 0 otherwise
/// Alias for CSINC Xd, XZR, XZR, invert(cond)
pub fn cset(buf: *CodeBuffer, rd: Reg, cond: Cond) !void {
    // CSINC: sf=1 (64-bit), op=0, S=0, 11010100, Rm=XZR, cond, o2=0, Rn=XZR, Rd
    // We use inverted condition because CSINC picks Rm+1 when cond is FALSE
    const inv_cond: u4 = @intFromEnum(cond) ^ 1; // Invert condition
    const inst: u32 = (0b1 << 31) | // sf=1 (64-bit)
        (0b0 << 30) | // op=0
        (0b0 << 29) | // S=0
        (0b11010100 << 21) | // opcode
        (0b11111 << 16) | // Rm=XZR
        (@as(u32, inv_cond) << 12) | // inverted cond
        (0b0 << 11) | // o2=0
        (0b1 << 10) | // o2=1 for CSINC
        (0b11111 << 5) | // Rn=XZR
        @as(u32, @intFromEnum(rd)); // Rd
    try emit32(buf, inst);
}

/// NEG Xd, Xm (SUB Xd, XZR, Xm)
pub fn negReg(buf: *CodeBuffer, rd: Reg, rm: Reg) !void {
    try emit32(buf, dataProcessingShifted(true, 0b10, false, rm, .lsl, 0, zr, rd));
}

/// MUL Xd, Xn, Xm (MADD Xd, Xn, Xm, XZR)
pub fn mulRegReg(buf: *CodeBuffer, rd: Reg, rn: Reg, rm: Reg) !void {
    // Data processing 3-source: MADD
    // sf=1 (64-bit), op54=00, op31=000 (MADD), Rm, o0=0, Ra=XZR, Rn, Rd
    // 1 00 11011 000 Rm 0 11111 Rn Rd
    const inst: u32 = (0b1 << 31) | // sf=1 (64-bit)
        (0b00 << 29) | // op54
        (0b11011 << 24) | // op21
        (0b000 << 21) | // op31 (MADD)
        (@as(u32, @intFromEnum(rm)) << 16) | // Rm
        (0b0 << 15) | // o0=0
        (0b11111 << 10) | // Ra=XZR
        (@as(u32, @intFromEnum(rn)) << 5) | // Rn
        @as(u32, @intFromEnum(rd)); // Rd
    try emit32(buf, inst);
}

/// SDIV Xd, Xn, Xm (Signed division)
pub fn sdivRegReg(buf: *CodeBuffer, rd: Reg, rn: Reg, rm: Reg) !void {
    // Data processing 2-source: SDIV
    // sf=1 (64-bit), S=0, opcode=000011
    // 1 0 0 11010 110 Rm 00001 1 Rn Rd
    const inst: u32 = (0b1 << 31) | // sf=1 (64-bit)
        (0b0 << 29) | // S=0
        (0b11010110 << 21) | // fixed bits
        (@as(u32, @intFromEnum(rm)) << 16) | // Rm
        (0b000011 << 10) | // opcode for SDIV
        (@as(u32, @intFromEnum(rn)) << 5) | // Rn
        @as(u32, @intFromEnum(rd)); // Rd
    try emit32(buf, inst);
}

/// UDIV Xd, Xn, Xm (Unsigned division)
pub fn udivRegReg(buf: *CodeBuffer, rd: Reg, rn: Reg, rm: Reg) !void {
    // Data processing 2-source: UDIV
    // sf=1 (64-bit), S=0, opcode=000010
    // 1 0 0 11010 110 Rm 00001 0 Rn Rd
    const inst: u32 = (0b1 << 31) | // sf=1 (64-bit)
        (0b0 << 29) | // S=0
        (0b11010110 << 21) | // fixed bits
        (@as(u32, @intFromEnum(rm)) << 16) | // Rm
        (0b000010 << 10) | // opcode for UDIV
        (@as(u32, @intFromEnum(rn)) << 5) | // Rn
        @as(u32, @intFromEnum(rd)); // Rd
    try emit32(buf, inst);
}

// ============================================================================
// Logical Instructions
// ============================================================================

/// AND Xd, Xn, Xm
pub fn andRegReg(buf: *CodeBuffer, rd: Reg, rn: Reg, rm: Reg) !void {
    try emit32(buf, logicalShifted(true, 0b00, false, rm, .lsl, 0, rn, rd));
}

/// ORR Xd, Xn, Xm
pub fn orrRegReg(buf: *CodeBuffer, rd: Reg, rn: Reg, rm: Reg) !void {
    try emit32(buf, logicalShifted(true, 0b01, false, rm, .lsl, 0, rn, rd));
}

/// EOR Xd, Xn, Xm (XOR)
pub fn eorRegReg(buf: *CodeBuffer, rd: Reg, rn: Reg, rm: Reg) !void {
    try emit32(buf, logicalShifted(true, 0b10, false, rm, .lsl, 0, rn, rd));
}

/// MVN Xd, Xm (ORN Xd, XZR, Xm)
pub fn mvnReg(buf: *CodeBuffer, rd: Reg, rm: Reg) !void {
    try emit32(buf, logicalShifted(true, 0b01, true, rm, .lsl, 0, zr, rd));
}

// ============================================================================
// Move Instructions
// ============================================================================

/// MOV Xd, Xm (ORR Xd, XZR, Xm)
pub fn movRegReg(buf: *CodeBuffer, rd: Reg, rm: Reg) !void {
    try emit32(buf, logicalShifted(true, 0b01, false, rm, .lsl, 0, zr, rd));
}

/// MOV Xd, SP (ADD Xd, SP, #0)
pub fn movFromSp(buf: *CodeBuffer, rd: Reg) !void {
    try emit32(buf, dataProcessingImm(true, 0, false, false, 0, .sp, rd));
}

/// MOV SP, Xn (ADD SP, Xn, #0)
pub fn movToSp(buf: *CodeBuffer, rn: Reg) !void {
    try emit32(buf, dataProcessingImm(true, 0, false, false, 0, rn, .sp));
}

/// MOVZ Xd, #imm16{, LSL #shift}
pub fn movzImm16(buf: *CodeBuffer, rd: Reg, imm16: u16, hw: u2) !void {
    try emit32(buf, moveWide(true, 0b10, hw, imm16, rd));
}

/// MOVK Xd, #imm16{, LSL #shift}
pub fn movkImm16(buf: *CodeBuffer, rd: Reg, imm16: u16, hw: u2) !void {
    try emit32(buf, moveWide(true, 0b11, hw, imm16, rd));
}

/// MOVN Xd, #imm16{, LSL #shift}
pub fn movnImm16(buf: *CodeBuffer, rd: Reg, imm16: u16, hw: u2) !void {
    try emit32(buf, moveWide(true, 0b00, hw, imm16, rd));
}

/// MOV Xd, #imm64 (using MOVZ + MOVK sequence)
pub fn movRegImm64(buf: *CodeBuffer, rd: Reg, imm: i64) !void {
    const uimm: u64 = @bitCast(imm);

    // Handle small immediates efficiently
    if (uimm == 0) {
        // MOV Xd, XZR
        try movRegReg(buf, rd, zr);
        return;
    }

    // Check if all bits are set (can use MOVN)
    if (uimm == 0xFFFFFFFFFFFFFFFF) {
        try movnImm16(buf, rd, 0, 0);
        return;
    }

    // Use MOVZ for first non-zero 16-bit chunk, MOVK for rest
    var first = true;
    var remaining = uimm;
    var hw: u2 = 0;

    while (remaining != 0 or first) : (hw += 1) {
        const chunk: u16 = @truncate(remaining);
        if (chunk != 0 or first) {
            if (first) {
                try movzImm16(buf, rd, chunk, hw);
                first = false;
            } else {
                try movkImm16(buf, rd, chunk, hw);
            }
        }
        remaining >>= 16;
        if (hw == 3) break;
    }
}

// ============================================================================
// Load/Store Instructions
// ============================================================================

/// LDR Xd, [Xn, #imm] (unsigned offset, scaled by 8)
pub fn ldrRegImm(buf: *CodeBuffer, rt: Reg, rn: Reg, offset: u12) !void {
    // ARM64 LDR (immediate, unsigned offset): imm12 is scaled by 8 for 64-bit
    // Caller passes byte offset, we divide by 8 for encoding
    const scaled: u12 = offset >> 3;
    try emit32(buf, loadStoreUnsignedOffset(0b11, false, 0b01, scaled, rn, rt));
}

/// LDR Xd, [Xn, Xm] (register offset)
pub fn ldrRegReg(buf: *CodeBuffer, rt: Reg, rn: Reg, rm: Reg) !void {
    // Load/store register (register offset): LDR Xt, [Xn, Xm]
    // size=11, V=0, opc=01, Rm, option=011 (LSL), S=0, Rn, Rt
    const inst: u32 = (0b11 << 30) | // size=11 (64-bit)
        (0b111 << 27) | // fixed
        (0b0 << 26) | // V=0 (not SIMD)
        (0b00 << 24) | // fixed
        (0b01 << 22) | // opc=01 (LDR)
        (0b1 << 21) | // fixed
        (@as(u32, @intFromEnum(rm)) << 16) | // Rm
        (0b011 << 13) | // option=011 (LSL)
        (0b0 << 12) | // S=0 (no shift)
        (0b10 << 10) | // fixed
        (@as(u32, @intFromEnum(rn)) << 5) | // Rn
        @as(u32, @intFromEnum(rt)); // Rt
    try emit32(buf, inst);
}

/// STR Xd, [Xn, #imm] (unsigned offset, scaled by 8)
pub fn strRegImm(buf: *CodeBuffer, rt: Reg, rn: Reg, offset: u12) !void {
    // ARM64 STR (immediate, unsigned offset): imm12 is scaled by 8 for 64-bit
    // Caller passes byte offset, we divide by 8 for encoding
    const scaled: u12 = offset >> 3;
    try emit32(buf, loadStoreUnsignedOffset(0b11, false, 0b00, scaled, rn, rt));
}

/// STR Wd, [Xn, #imm] (32-bit store, unsigned offset, scaled by 4)
pub fn strwRegImm(buf: *CodeBuffer, rt: Reg, rn: Reg, offset: u12) !void {
    // ARM64 STR (immediate, unsigned offset): imm12 is scaled by 4 for 32-bit
    // Caller passes byte offset, we divide by 4 for encoding
    const scaled: u12 = offset >> 2;
    try emit32(buf, loadStoreUnsignedOffset(0b10, false, 0b00, scaled, rn, rt));
}

/// STR Hd, [Xn, #imm] (16-bit store, unsigned offset, scaled by 2)
pub fn strhRegImm(buf: *CodeBuffer, rt: Reg, rn: Reg, offset: u12) !void {
    // ARM64 STRH (immediate, unsigned offset): imm12 is scaled by 2 for 16-bit
    // Caller passes byte offset, we divide by 2 for encoding
    const scaled: u12 = offset >> 1;
    try emit32(buf, loadStoreUnsignedOffset(0b01, false, 0b00, scaled, rn, rt));
}

/// LDR Wd, [Xn, #imm] (32-bit load, unsigned offset, scaled by 4)
pub fn ldrwRegImm(buf: *CodeBuffer, rt: Reg, rn: Reg, offset: u12) !void {
    // ARM64 LDR (immediate, unsigned offset): imm12 is scaled by 4 for 32-bit
    // Caller passes byte offset, we divide by 4 for encoding
    const scaled: u12 = offset >> 2;
    try emit32(buf, loadStoreUnsignedOffset(0b10, false, 0b01, scaled, rn, rt));
}

/// LDR Hd, [Xn, #imm] (16-bit load, unsigned offset, scaled by 2)
pub fn ldrhRegImm(buf: *CodeBuffer, rt: Reg, rn: Reg, offset: u12) !void {
    // ARM64 LDRH (immediate, unsigned offset): imm12 is scaled by 2 for 16-bit
    // Caller passes byte offset, we divide by 2 for encoding
    const scaled: u12 = offset >> 1;
    try emit32(buf, loadStoreUnsignedOffset(0b01, false, 0b01, scaled, rn, rt));
}

/// LDP Xt1, Xt2, [Xn, #imm]! (pre-index)
pub fn ldpPreIndex(buf: *CodeBuffer, rt: Reg, rt2: Reg, rn: Reg, imm7: i7) !void {
    const uimm7: u7 = @bitCast(imm7);
    try emit32(buf, loadStorePair(0b10, false, 0b11, true, uimm7, rt2, rn, rt));
}

/// STP Xt1, Xt2, [Xn, #imm]! (pre-index)
pub fn stpPreIndex(buf: *CodeBuffer, rt: Reg, rt2: Reg, rn: Reg, imm7: i7) !void {
    const uimm7: u7 = @bitCast(imm7);
    try emit32(buf, loadStorePair(0b10, false, 0b11, false, uimm7, rt2, rn, rt));
}

/// STP Xt1, Xt2, [Xn, #imm] (signed offset, no writeback)
pub fn stpSignedOffset(buf: *CodeBuffer, rt: Reg, rt2: Reg, rn: Reg, imm7: i7) !void {
    const uimm7: u7 = @bitCast(imm7);
    try emit32(buf, loadStorePair(0b10, false, 0b10, false, uimm7, rt2, rn, rt));
}

/// LDP Xt1, Xt2, [Xn, #imm] (signed offset, no writeback)
pub fn ldpSignedOffset(buf: *CodeBuffer, rt: Reg, rt2: Reg, rn: Reg, imm7: i7) !void {
    const uimm7: u7 = @bitCast(imm7);
    try emit32(buf, loadStorePair(0b10, false, 0b10, true, uimm7, rt2, rn, rt));
}

/// LDP Xt1, Xt2, [Xn], #imm (post-index)
pub fn ldpPostIndex(buf: *CodeBuffer, rt: Reg, rt2: Reg, rn: Reg, imm7: i7) !void {
    const uimm7: u7 = @bitCast(imm7);
    try emit32(buf, loadStorePair(0b10, false, 0b01, true, uimm7, rt2, rn, rt));
}

/// STP Xt1, Xt2, [Xn], #imm (post-index)
pub fn stpPostIndex(buf: *CodeBuffer, rt: Reg, rt2: Reg, rn: Reg, imm7: i7) !void {
    const uimm7: u7 = @bitCast(imm7);
    try emit32(buf, loadStorePair(0b10, false, 0b01, false, uimm7, rt2, rn, rt));
}

/// LDRB Wd, [Xn, #imm] - Load byte with zero extension to 64-bit
pub fn ldrbRegImm(buf: *CodeBuffer, rt: Reg, rn: Reg, offset: u12) !void {
    // size=00 (byte), V=0, opc=01 (load unsigned)
    try emit32(buf, loadStoreUnsignedOffset(0b00, false, 0b01, offset, rn, rt));
}

/// LDRSB Xt, [Xn, #imm] - Load signed byte, sign-extend to 64-bit
pub fn ldrsbRegImm(buf: *CodeBuffer, rt: Reg, rn: Reg, offset: u12) !void {
    // size=00 (byte), V=0, opc=10 (load signed extend to 64-bit)
    try emit32(buf, loadStoreUnsignedOffset(0b00, false, 0b10, offset, rn, rt));
}

/// STRB Wd, [Xn, #imm] - Store low byte of register
pub fn strbRegImm(buf: *CodeBuffer, rt: Reg, rn: Reg, offset: u12) !void {
    // size=00 (byte), V=0, opc=00 (store)
    try emit32(buf, loadStoreUnsignedOffset(0b00, false, 0b00, offset, rn, rt));
}

/// STR Xd, [Xn, #0] via address computation for unaligned offsets
/// Computes address into x9, then stores rt there
pub fn strViaAddressComputation(buf: *CodeBuffer, rt: Reg, base: Reg, offset: u12) !void {
    // add x9, base, #offset
    try addRegImm12(buf, .x9, base, offset);
    // str rt, [x9]
    try strRegImm(buf, rt, .x9, 0);
}

/// LDR Xd, [Xn, #0] via address computation for unaligned offsets
/// Computes address into x9, then loads from there
pub fn ldrViaAddressComputation(buf: *CodeBuffer, rt: Reg, base: Reg, offset: u12) !void {
    // add x9, base, #offset
    try addRegImm12(buf, .x9, base, offset);
    // ldr rt, [x9]
    try ldrRegImm(buf, rt, .x9, 0);
}

/// LDRB Wd, [Xn, Xm] - Load byte with register offset
pub fn ldrbRegReg(buf: *CodeBuffer, rt: Reg, rn: Reg, rm: Reg) !void {
    // Load/store register (register offset): LDRB Wt, [Xn, Xm]
    // size=00, V=0, opc=01, Rm, option=011 (LSL), S=0, Rn, Rt
    const inst: u32 = (0b00 << 30) | // size=00 (byte)
        (0b111 << 27) | // fixed
        (0b0 << 26) | // V=0 (not SIMD)
        (0b00 << 24) | // fixed
        (0b01 << 22) | // opc=01 (LDR)
        (0b1 << 21) | // fixed
        (@as(u32, @intFromEnum(rm)) << 16) | // Rm
        (0b011 << 13) | // option=011 (LSL)
        (0b0 << 12) | // S=0 (no shift)
        (0b10 << 10) | // fixed
        (@as(u32, @intFromEnum(rn)) << 5) | // Rn
        @as(u32, @intFromEnum(rt)); // Rt
    try emit32(buf, inst);
}

// ============================================================================
// Branch Instructions
// ============================================================================

/// B label (unconditional branch)
pub fn b(buf: *CodeBuffer, offset: i26) !void {
    try emit32(buf, branchImm(false, offset));
}

/// BL label (branch with link - call)
pub fn bl(buf: *CodeBuffer, offset: i26) !void {
    try emit32(buf, branchImm(true, offset));
}

/// BR Xn (branch to register)
pub fn brReg(buf: *CodeBuffer, rn: Reg) !void {
    try emit32(buf, branchReg(0b00, rn));
}

/// BLR Xn (branch with link to register)
pub fn blrReg(buf: *CodeBuffer, rn: Reg) !void {
    try emit32(buf, branchReg(0b01, rn));
}

/// RET {Xn} (return - defaults to X30/LR)
pub fn ret(buf: *CodeBuffer) !void {
    try emit32(buf, branchReg(0b10, .lr));
}

/// RET Xn (return to specific register)
pub fn retReg(buf: *CodeBuffer, rn: Reg) !void {
    try emit32(buf, branchReg(0b10, rn));
}

/// B.cond label (conditional branch)
pub fn bCond(buf: *CodeBuffer, cond: Cond, offset: i19) !void {
    try emit32(buf, branchCond(cond, offset));
}

/// B label (unconditional branch, placeholder for patching)
pub fn bImm(buf: *CodeBuffer, offset: i26) !void {
    try emit32(buf, branchImm(false, offset));
}

/// CBZ Xn, label (compare and branch if zero)
pub fn cbz(buf: *CodeBuffer, rt: Reg, offset: i19) !void {
    // CBZ: sf=1 (64-bit), op=0 (CBZ), imm19, Rt
    // 1011010 0 imm19 Rt
    const sf: u32 = 1; // 64-bit
    const op: u32 = 0; // CBZ
    const imm19: u32 = @as(u32, @bitCast(@as(i32, offset))) & 0x7FFFF;
    const inst = (sf << 31) | (0b011010 << 25) | (op << 24) | (imm19 << 5) | @as(u32, @intFromEnum(rt));
    try emit32(buf, inst);
}

/// CBNZ Xn, label (compare and branch if not zero)
pub fn cbnz(buf: *CodeBuffer, rt: Reg, offset: i19) !void {
    // CBNZ: sf=1 (64-bit), op=1 (CBNZ), imm19, Rt
    // 1011010 1 imm19 Rt
    const sf: u32 = 1; // 64-bit
    const op: u32 = 1; // CBNZ
    const imm19: u32 = @as(u32, @bitCast(@as(i32, offset))) & 0x7FFFF;
    const inst = (sf << 31) | (0b011010 << 25) | (op << 24) | (imm19 << 5) | @as(u32, @intFromEnum(rt));
    try emit32(buf, inst);
}

/// Patch a branch instruction at the given offset with a new relative offset
/// Works for B, B.cond, CBZ, and CBNZ instructions
/// Note: inst_offset should point to the position AFTER the instruction (buf.pos() after emit)
pub fn patchBranch(buf: *CodeBuffer, inst_offset: u32, rel_offset: i32) void {
    // Go back 4 bytes to get the actual instruction position
    const actual_offset = inst_offset - 4;
    const old_inst = std.mem.readInt(u32, buf.bytes.items[actual_offset..][0..4], .little);

    // Check instruction type by examining top bits
    // B/BL: 00010x (bits [31:26])
    // CBZ/CBNZ: x011010x (bits [30:25] = 011010)
    // B.cond: 01010100 (bits [31:24])
    const is_unconditional = (old_inst >> 26) == 0b000101;
    const is_cbz_cbnz = ((old_inst >> 25) & 0b1111110) == 0b0110100;

    var new_inst: u32 = undefined;
    if (is_unconditional) {
        // B/BL: bits [25:0] are the imm26 offset
        const masked_offset: u32 = @as(u32, @bitCast(rel_offset)) & 0x3FFFFFF;
        new_inst = (old_inst & 0xFC000000) | masked_offset;
    } else if (is_cbz_cbnz) {
        // CBZ/CBNZ: bits [23:5] are the imm19 offset
        const imm19: u32 = @as(u32, @bitCast(rel_offset)) & 0x7FFFF;
        new_inst = (old_inst & 0xFF00001F) | (imm19 << 5);
    } else {
        // B.cond: bits [23:5] are the imm19 offset
        const imm19: u32 = @as(u32, @bitCast(rel_offset)) & 0x7FFFF;
        new_inst = (old_inst & 0xFF00001F) | (imm19 << 5);
    }

    buf.bytes.items[actual_offset] = @truncate(new_inst);
    buf.bytes.items[actual_offset + 1] = @truncate(new_inst >> 8);
    buf.bytes.items[actual_offset + 2] = @truncate(new_inst >> 16);
    buf.bytes.items[actual_offset + 3] = @truncate(new_inst >> 24);
}

/// CSEL Xd, Xn, Xm, cond - conditional select
/// If cond is true, Rd = Rn; else Rd = Rm
pub fn csel(buf: *CodeBuffer, rd: Reg, rn: Reg, rm: Reg, cond: Cond) !void {
    // Encoding: 1|00|11010100|Rm|cond|00|Rn|Rd
    const inst: u32 = 0x9A800000 // Base opcode for CSEL (64-bit)
    | (@as(u32, @intFromEnum(rm)) << 16) // Rm at bits 20:16
    | (@as(u32, @intFromEnum(cond)) << 12) // cond at bits 15:12
    | (@as(u32, @intFromEnum(rn)) << 5) // Rn at bits 9:5
    | @as(u32, @intFromEnum(rd)); // Rd at bits 4:0
    try emit32(buf, inst);
}

/// BL with relocation
pub fn callSymbol(buf: *CodeBuffer, symbol: []const u8) !void {
    try buf.addRelocation(.pc_rel_32, symbol, 0);
    try emit32(buf, branchImm(true, 0)); // Placeholder
}

/// ADRP + ADD to load symbol address into register
/// ADRP loads page address, ADD adds page offset
pub fn loadSymbolAddr(buf: *CodeBuffer, dst: Reg, symbol: []const u8) !void {
    // ADRP Xd, symbol@PAGE
    // Encoding: 1|immlo|10000|immhi|Rd
    // We use relocation, so just emit with zeros
    try buf.addRelocation(.aarch64_adrp, symbol, 0);
    const adrp_inst: u32 = (1 << 31) | (0b10000 << 24) | @as(u32, dst.id());
    try emit32(buf, adrp_inst);

    // ADD Xd, Xd, symbol@PAGEOFF
    // Encoding: 1|0|0|10001|00|imm12|Rn|Rd
    try buf.addRelocation(.aarch64_add_lo12, symbol, 0);
    const add_inst: u32 = (1 << 31) | (0b0010001 << 24) | (@as(u32, dst.id()) << 5) | @as(u32, dst.id());
    try emit32(buf, add_inst);
}

/// SVC #imm16 - Supervisor call (syscall)
pub fn svc(buf: *CodeBuffer, imm: u16) !void {
    // SVC encoding: 11010100|000|imm16|00001
    const inst: u32 = (0b11010100 << 24) | (0b000 << 21) | (@as(u32, imm) << 5) | 0b00001;
    try emit32(buf, inst);
}

// ============================================================================
// Miscellaneous
// ============================================================================

/// NOP
pub fn nop(buf: *CodeBuffer) !void {
    try emit32(buf, 0xD503201F);
}

// ============================================================================
// AArch64 Backend Implementation
// ============================================================================

pub const AArch64Backend = struct {
    allocator: Allocator,
    storage: StorageManager,

    pub fn init(allocator: Allocator) AArch64Backend {
        var self = AArch64Backend{
            .allocator = allocator,
            .storage = StorageManager.init(allocator),
        };

        // Initialize free registers (AAPCS64 caller-saved)
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.x0)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.x1)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.x2)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.x3)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.x4)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.x5)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.x6)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.x7)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.x9)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.x10)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.x11)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.x12)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.x13)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.x14)) catch {};
        self.storage.free_general_regs.append(allocator, @intFromEnum(Reg.x15)) catch {};

        return self;
    }

    pub fn deinit(self: *AArch64Backend) void {
        self.storage.deinit();
    }

    /// Get the Backend interface for this implementation.
    pub fn getBackend(self: *AArch64Backend) be.Backend {
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
        const self: *AArch64Backend = @ptrCast(@alignCast(ptr));
        self.storage.reset();

        log.debug("genFunc: {s} ({d} blocks, {d} values)", .{
            func.name,
            func.numBlocks(),
            func.numValues(),
        });

        // Emit prologue
        const prologue_start = buf.pos();
        try emitPrologue(ptr, buf, &self.storage);

        // Generate code for each block
        for (func.blocks.items, 0..) |*block, i| {
            log.debug("  block b{d} ({d} values)", .{ block.id, block.values.items.len });

            for (block.values.items) |vid| {
                const value = func.getValue(vid);
                try genValue(ptr, func, value, buf, &self.storage);
            }

            const next_block: ?*ssa.Block = if (i + 1 < func.blocks.items.len)
                &func.blocks.items[i + 1]
            else
                null;
            try genBlock(ptr, func, block, next_block, buf);
        }

        log.debug("genFunc: {s} done, {d} bytes", .{ func.name, buf.pos() - prologue_start });
    }

    fn genValue(ptr: *anyopaque, func: *ssa.Func, v: *ssa.Value, buf: *CodeBuffer, storage: *StorageManager) !void {
        const self: *AArch64Backend = @ptrCast(@alignCast(ptr));
        _ = self;
        _ = func;

        switch (v.op) {
            .const_int => {
                if (storage.allocGeneral()) |reg| {
                    const imm = v.aux_int;
                    try movRegImm64(buf, @enumFromInt(reg), imm);
                    try storage.setStorage(v.id, .{ .general_reg = reg });
                    log.debug("    v{d} = const_int {d} -> x{d}", .{ v.id, imm, reg });
                } else {
                    const offset = storage.allocStack(8);
                    try storage.setStorage(v.id, .{ .stack = offset });
                    log.debug("    v{d} = const_int {d} -> [sp{d}]", .{ v.id, v.aux_int, offset });
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
                        try addRegReg(buf, dst_reg, dst_reg, src_reg);
                        try storage.setStorage(v.id, dst_storage);
                        log.debug("    v{d} = add v{d}, v{d} -> x{d}", .{ v.id, value_args[0], value_args[1], dst_storage.general_reg });
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
                        try subRegReg(buf, dst_reg, dst_reg, src_reg);
                        try storage.setStorage(v.id, dst_storage);
                        log.debug("    v{d} = sub v{d}, v{d} -> x{d}", .{ v.id, value_args[0], value_args[1], dst_storage.general_reg });
                    }
                }
            },
            .ret => {
                const value_args = v.args();
                if (value_args.len >= 1) {
                    const ret_storage = storage.getStorage(value_args[0]);
                    if (ret_storage == .general_reg) {
                        const ret_reg: Reg = @enumFromInt(ret_storage.general_reg);
                        if (ret_reg != .x0) {
                            try movRegReg(buf, .x0, ret_reg);
                        }
                        log.debug("    v{d} = ret v{d}", .{ v.id, value_args[0] });
                    }
                }
            },
            else => {
                log.debug("    v{d} = {s} (unimplemented)", .{ v.id, @tagName(v.op) });
            },
        }
    }

    fn genBlock(ptr: *anyopaque, func: *ssa.Func, blk: *ssa.Block, next: ?*ssa.Block, buf: *CodeBuffer) !void {
        _ = ptr;
        _ = func;

        switch (blk.kind) {
            .plain => {
                const block_succs = blk.succs();
                if (block_succs.len > 0) {
                    const target = block_succs[0].block;
                    if (next) |n| {
                        if (n.id != target) {
                            log.debug("  b{d}: b b{d}", .{ blk.id, target });
                            try b(buf, 0); // Placeholder
                        } else {
                            log.debug("  b{d}: fallthrough to b{d}", .{ blk.id, target });
                        }
                    } else {
                        log.debug("  b{d}: b b{d} (tail)", .{ blk.id, target });
                        try b(buf, 0);
                    }
                }
            },
            .@"if" => {
                const block_succs = blk.succs();
                if (block_succs.len >= 2) {
                    log.debug("  b{d}: branch to b{d}/b{d}", .{ blk.id, block_succs[0].block, block_succs[1].block });
                    try bCond(buf, .ne, 0); // Placeholder
                    if (next) |n| {
                        if (n.id != block_succs[1].block) {
                            try b(buf, 0);
                        }
                    }
                }
            },
            .ret => {
                log.debug("  b{d}: ret", .{blk.id});
                try ret(buf);
            },
            .exit => {
                log.debug("  b{d}: exit", .{blk.id});
            },
        }
    }

    fn emitPrologue(ptr: *anyopaque, buf: *CodeBuffer, storage: *StorageManager) !void {
        _ = ptr;
        // Standard AArch64 function prologue
        // STP X29, X30, [SP, #-16]!  (save FP and LR)
        try stpPreIndex(buf, .fp, .lr, .sp, -2); // -2 * 8 = -16

        // MOV X29, SP (set up frame pointer)
        try movFromSp(buf, .fp);

        // Reserve stack space
        const stack_size: u32 = @intCast(@abs(storage.max_stack));
        if (stack_size > 0) {
            const aligned_size = (stack_size + 15) & ~@as(u32, 15); // 16-byte align
            if (aligned_size <= 0xFFF) {
                try subRegImm12(buf, .sp, .sp, @intCast(aligned_size));
            } else {
                // For larger stacks, use movz/movk + sub
                try movRegImm64(buf, .x16, @intCast(aligned_size));
                try subRegReg(buf, .sp, .sp, .x16);
            }
        }
    }

    fn emitEpilogue(ptr: *anyopaque, buf: *CodeBuffer, storage: *StorageManager) !void {
        _ = ptr;
        _ = storage;
        // Standard AArch64 function epilogue
        // MOV SP, X29 (restore stack pointer)
        try movToSp(buf, .fp);

        // LDP X29, X30, [SP], #16 (restore FP and LR)
        try ldpPostIndex(buf, .fp, .lr, .sp, 2); // 2 * 8 = 16

        // RET
        try ret(buf);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "add reg64 reg64" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try addRegReg(&buf, .x0, .x1, .x2);
    // ADD X0, X1, X2 = 0x8B020020
    const expected: u32 = 0x8B020020;
    const actual: u32 = @bitCast(buf.getBytes()[0..4].*);
    try std.testing.expectEqual(expected, actual);
}

test "mov reg64 reg64" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try movRegReg(&buf, .x0, .x1);
    // MOV X0, X1 = ORR X0, XZR, X1 = 0xAA0103E0
    const expected: u32 = 0xAA0103E0;
    const actual: u32 = @bitCast(buf.getBytes()[0..4].*);
    try std.testing.expectEqual(expected, actual);
}

test "ret" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try ret(&buf);
    // RET = 0xD65F03C0
    const expected: u32 = 0xD65F03C0;
    const actual: u32 = @bitCast(buf.getBytes()[0..4].*);
    try std.testing.expectEqual(expected, actual);
}

test "nop" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try nop(&buf);
    // NOP = 0xD503201F
    const expected: u32 = 0xD503201F;
    const actual: u32 = @bitCast(buf.getBytes()[0..4].*);
    try std.testing.expectEqual(expected, actual);
}

test "aarch64 backend init" {
    const allocator = std.testing.allocator;
    var arm64_be = AArch64Backend.init(allocator);
    defer arm64_be.deinit();

    // Check that registers were initialized
    try std.testing.expect(arm64_be.storage.free_general_regs.items.len > 0);
}

// ============================================================================
// Instruction Encoding Validation Tests
// These tests verify byte-exact encodings against known-correct ARM64 values.
// Reference: ARM Architecture Reference Manual for A-profile architecture
// ============================================================================

test "SUB X0, X1, X2 encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try subRegReg(&buf, .x0, .x1, .x2);
    // SUB X0, X1, X2: sf=1, op=1, S=0, 01011, shift=00, 0, Rm=x2, imm6=0, Rn=x1, Rd=x0
    // 1 1 0 01011 00 0 00010 000000 00001 00000
    // = 0xCB020020
    const expected: u32 = 0xCB020020;
    const actual: u32 = @bitCast(buf.getBytes()[0..4].*);
    try std.testing.expectEqual(expected, actual);
}

test "SUBS X0, X1, X2 encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try subsRegReg(&buf, .x0, .x1, .x2);
    // SUBS X0, X1, X2: sf=1, op=1, S=1, 01011, shift=00, 0, Rm=x2, imm6=0, Rn=x1, Rd=x0
    // 1 1 1 01011 00 0 00010 000000 00001 00000
    // = 0xEB020020
    const expected: u32 = 0xEB020020;
    const actual: u32 = @bitCast(buf.getBytes()[0..4].*);
    try std.testing.expectEqual(expected, actual);
}

test "CMP X8, X9 encoding (SUBS XZR, X8, X9)" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try cmpRegReg(&buf, .x8, .x9);
    // CMP X8, X9 = SUBS XZR, X8, X9: sf=1, op=1, S=1, 01011, shift=00, 0, Rm=x9, imm6=0, Rn=x8, Rd=xzr
    // 1 1 1 01011 00 0 01001 000000 01000 11111
    // = 0xEB09011F
    const expected: u32 = 0xEB09011F;
    const actual: u32 = @bitCast(buf.getBytes()[0..4].*);
    try std.testing.expectEqual(expected, actual);
}

test "ADDS X0, X1, X2 encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try addsRegReg(&buf, .x0, .x1, .x2);
    // ADDS X0, X1, X2: sf=1, op=0, S=1, 01011, shift=00, 0, Rm=x2, imm6=0, Rn=x1, Rd=x0
    // 1 0 1 01011 00 0 00010 000000 00001 00000
    // = 0xAB020020
    const expected: u32 = 0xAB020020;
    const actual: u32 = @bitCast(buf.getBytes()[0..4].*);
    try std.testing.expectEqual(expected, actual);
}

test "CMP X8, #imm12 encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try cmpRegImm12(&buf, .x8, 42);
    // CMP X8, #42 = SUBS XZR, X8, #42: sf=1, op=1, S=1, 100010, sh=0, imm12=42, Rn=x8, Rd=xzr
    // 1 1 1 100010 0 000000101010 01000 11111
    // = 0xF100A91F
    const expected: u32 = 0xF100A91F;
    const actual: u32 = @bitCast(buf.getBytes()[0..4].*);
    try std.testing.expectEqual(expected, actual);
}

test "LDR X0, [SP, #offset] encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    // Load from [SP + 16] (byte offset 16, scaled by 8 gives imm12=2)
    try ldrRegImm(&buf, .x0, .sp, 16);
    // LDR X0, [SP, #16]: size=11, V=0, opc=01, imm12=2, Rn=sp(31), Rt=x0(0)
    // 0xF9400000 (base) + 0x800 (imm12=2 << 10) + 0x3E0 (rn=31 << 5) + 0 (rt)
    // = 0xF9400BE0
    const expected: u32 = 0xF9400BE0;
    const actual: u32 = @bitCast(buf.getBytes()[0..4].*);
    try std.testing.expectEqual(expected, actual);
}

test "STR X0, [SP, #offset] encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    // Store to [SP + 16] (byte offset 16, scaled by 8 gives imm12=2)
    try strRegImm(&buf, .x0, .sp, 16);
    // STR X0, [SP, #16]: size=11, V=0, opc=00, imm12=2, Rn=sp(31), Rt=x0(0)
    // 0xF9000000 (base) + 0x800 (imm12=2 << 10) + 0x3E0 (rn=31 << 5) + 0 (rt)
    // = 0xF9000BE0
    const expected: u32 = 0xF9000BE0;
    const actual: u32 = @bitCast(buf.getBytes()[0..4].*);
    try std.testing.expectEqual(expected, actual);
}

test "B.cond encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    // B.EQ with offset 0 (placeholder)
    try bCond(&buf, .eq, 0);
    // B.EQ #+0: 0101010 0 imm19=0 0 cond=0000
    // = 0x54000000
    const expected: u32 = 0x54000000;
    const actual: u32 = @bitCast(buf.getBytes()[0..4].*);
    try std.testing.expectEqual(expected, actual);
}

test "B.GE encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    // B.GE with offset 0 (placeholder)
    try bCond(&buf, .ge, 0);
    // B.GE #+0: 0101010 0 imm19=0 0 cond=1010
    // = 0x5400000A
    const expected: u32 = 0x5400000A;
    const actual: u32 = @bitCast(buf.getBytes()[0..4].*);
    try std.testing.expectEqual(expected, actual);
}

test "MUL X0, X1, X2 encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try mulRegReg(&buf, .x0, .x1, .x2);
    // MUL X0, X1, X2 = MADD X0, X1, X2, XZR: sf=1, 00 11011 000 Rm=x2, 0 Ra=xzr, Rn=x1, Rd=x0
    // 1 00 11011 000 00010 0 11111 00001 00000
    // = 0x9B027C20
    const expected: u32 = 0x9B027C20;
    const actual: u32 = @bitCast(buf.getBytes()[0..4].*);
    try std.testing.expectEqual(expected, actual);
}

test "SDIV X0, X1, X2 encoding" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try sdivRegReg(&buf, .x0, .x1, .x2);
    // SDIV X0, X1, X2: sf=1, 0 0 11010110 Rm=x2, 00001 1 Rn=x1, Rd=x0
    // 1 0 0 11010110 00010 000011 00001 00000
    // = 0x9AC20C20
    const expected: u32 = 0x9AC20C20;
    const actual: u32 = @bitCast(buf.getBytes()[0..4].*);
    try std.testing.expectEqual(expected, actual);
}
