///! Code generation backend interface and storage management.
///!
///! Combines patterns from:
///! - Go: cmd/compile/internal/ssagen (plugin callbacks)
///! - Roc: gen_dev/src/generic64 (trait-based architecture)
///!
///! Key patterns:
///! - Backend interface for multi-architecture support
///! - StorageManager tracks symbol locations (registers/stack)
///! - Relocation list for deferred symbol resolution
///! - Direct bytecode emission to buffer

const std = @import("std");
const ssa = @import("../ssa.zig");
const types = @import("../types.zig");
const debug = @import("../debug.zig");

const Allocator = std.mem.Allocator;

// ============================================================================
// String Literal Info (for rodata section)
// ============================================================================

/// String literal info for rodata section
pub const StringInfo = struct {
    offset: u32, // Offset in rodata section
    len: u32, // Length of string (excluding null terminator if any)
    symbol_name: []const u8, // Symbol name for relocation (e.g., "_str_0")
};

// Scoped loggers for codegen debugging
const log_regalloc = debug.scoped(.regalloc);
const log_codegen = debug.scoped(.codegen);
const ValueID = ssa.ValueID;
const BlockID = ssa.BlockID;
const TypeIndex = types.TypeIndex;

// ============================================================================
// Registers (generic)
// ============================================================================

/// General purpose register (architecture-specific values).
pub const GeneralReg = u8;
pub const FloatReg = u8;

pub const no_reg: GeneralReg = 0xFF;
pub const no_float_reg: FloatReg = 0xFF;

// ============================================================================
// Storage (Roc's StorageManager pattern)
// ============================================================================

/// Where a value is stored.
pub const Storage = union(enum) {
    /// Value is in a general-purpose register.
    general_reg: GeneralReg,
    /// Value is in a float register.
    float_reg: FloatReg,
    /// Value is on the stack at [rbp + offset].
    stack: i32,
    /// Value is a constant (no storage needed).
    constant: i64,
    /// Value is not yet allocated.
    none,
};

/// Manages storage allocation for values.
/// Tracks register usage and stack layout.
pub const StorageManager = struct {
    allocator: Allocator,

    /// Map from SSA value to storage location.
    value_storage: std.AutoHashMap(ValueID, Storage),

    /// Available general-purpose registers.
    free_general_regs: std.ArrayList(GeneralReg),
    /// Available float registers.
    free_float_regs: std.ArrayList(FloatReg),

    /// Registers currently in use.
    used_general_regs: std.ArrayList(GeneralReg),
    used_float_regs: std.ArrayList(FloatReg),

    /// Callee-saved registers that we've used (need to save in prologue).
    used_callee_saved: std.ArrayList(GeneralReg),

    /// Current stack offset (grows negative from rbp).
    stack_offset: i32,
    /// Maximum stack space used.
    max_stack: i32,

    pub fn init(allocator: Allocator) StorageManager {
        return .{
            .allocator = allocator,
            .value_storage = std.AutoHashMap(ValueID, Storage).init(allocator),
            .free_general_regs = .{ .items = &.{}, .capacity = 0 },
            .free_float_regs = .{ .items = &.{}, .capacity = 0 },
            .used_general_regs = .{ .items = &.{}, .capacity = 0 },
            .used_float_regs = .{ .items = &.{}, .capacity = 0 },
            .used_callee_saved = .{ .items = &.{}, .capacity = 0 },
            .stack_offset = 0,
            .max_stack = 0,
        };
    }

    pub fn deinit(self: *StorageManager) void {
        self.value_storage.deinit();
        self.free_general_regs.deinit(self.allocator);
        self.free_float_regs.deinit(self.allocator);
        self.used_general_regs.deinit(self.allocator);
        self.used_float_regs.deinit(self.allocator);
        self.used_callee_saved.deinit(self.allocator);
    }

    /// Get storage for a value.
    pub fn getStorage(self: *StorageManager, id: ValueID) Storage {
        return self.value_storage.get(id) orelse .none;
    }

    /// Set storage for a value.
    pub fn setStorage(self: *StorageManager, id: ValueID, storage: Storage) !void {
        try self.value_storage.put(id, storage);
    }

    /// Allocate a general-purpose register.
    pub fn allocGeneral(self: *StorageManager) ?GeneralReg {
        if (self.free_general_regs.items.len > 0) {
            const reg = self.free_general_regs.pop().?;
            self.used_general_regs.append(self.allocator, reg) catch return null;
            log_regalloc.debug("allocGeneral: r{d} (free: {d}, used: {d})", .{
                reg,
                self.free_general_regs.items.len,
                self.used_general_regs.items.len,
            });
            return reg;
        }
        log_regalloc.debug("allocGeneral: none available (need spill)", .{});
        return null;
    }

    /// Free a general-purpose register.
    pub fn freeGeneral(self: *StorageManager, reg: GeneralReg) void {
        // Remove from used list
        for (self.used_general_regs.items, 0..) |r, i| {
            if (r == reg) {
                _ = self.used_general_regs.orderedRemove(i);
                break;
            }
        }
        // Add to free list
        self.free_general_regs.append(self.allocator, reg) catch {};
        log_regalloc.debug("freeGeneral: r{d} (free: {d}, used: {d})", .{
            reg,
            self.free_general_regs.items.len,
            self.used_general_regs.items.len,
        });
    }

    /// Allocate stack space.
    pub fn allocStack(self: *StorageManager, size: u32) i32 {
        // Align to 8 bytes
        const aligned_size: i32 = @intCast(((size + 7) / 8) * 8);
        self.stack_offset -= aligned_size;
        if (self.stack_offset < self.max_stack) {
            self.max_stack = self.stack_offset;
        }
        log_regalloc.debug("allocStack: {d} bytes at [rbp{d}] (max: {d})", .{
            aligned_size,
            self.stack_offset,
            self.max_stack,
        });
        return self.stack_offset;
    }

    /// Spill a register to stack.
    pub fn spill(self: *StorageManager, reg: GeneralReg) i32 {
        log_regalloc.info("spill: r{d} -> stack", .{reg});
        const offset = self.allocStack(8);
        self.freeGeneral(reg);
        return offset;
    }

    /// Reset for a new function.
    pub fn reset(self: *StorageManager) void {
        self.value_storage.clearRetainingCapacity();
        self.used_general_regs.clearRetainingCapacity();
        self.used_float_regs.clearRetainingCapacity();
        self.used_callee_saved.clearRetainingCapacity();
        self.stack_offset = 0;
        self.max_stack = 0;
    }
};

// ============================================================================
// Relocations
// ============================================================================

/// A relocation to be applied when linking.
pub const Relocation = struct {
    /// Offset in the code buffer where relocation applies.
    offset: u32,
    /// Type of relocation.
    kind: RelocKind,
    /// Symbol name (for external references).
    symbol: []const u8,
    /// Addend (offset from symbol).
    addend: i64,
};

pub const RelocKind = enum {
    /// PC-relative 32-bit (call, jmp).
    pc_rel_32,
    /// Absolute 64-bit address.
    abs_64,
    /// GOT-relative (position independent).
    got_rel,
    /// PLT-relative (function calls).
    plt_rel,
    /// AArch64 ADRP page address.
    aarch64_adrp,
    /// AArch64 ADD low 12 bits of address.
    aarch64_add_lo12,
};

// ============================================================================
// Code Buffer
// ============================================================================

/// Buffer for emitting machine code.
pub const CodeBuffer = struct {
    allocator: Allocator,
    bytes: std.ArrayList(u8),
    relocations: std.ArrayList(Relocation),

    pub fn init(allocator: Allocator) CodeBuffer {
        return .{
            .allocator = allocator,
            .bytes = .{ .items = &.{}, .capacity = 0 },
            .relocations = .{ .items = &.{}, .capacity = 0 },
        };
    }

    pub fn deinit(self: *CodeBuffer) void {
        self.bytes.deinit(self.allocator);
        self.relocations.deinit(self.allocator);
    }

    /// Current position in buffer.
    pub fn pos(self: *const CodeBuffer) u32 {
        return @intCast(self.bytes.items.len);
    }

    /// Emit a single byte.
    pub fn emit8(self: *CodeBuffer, b: u8) !void {
        try self.bytes.append(self.allocator, b);
    }

    /// Emit two bytes (little-endian).
    pub fn emit16(self: *CodeBuffer, v: u16) !void {
        try self.bytes.appendSlice(self.allocator, &.{
            @truncate(v),
            @truncate(v >> 8),
        });
    }

    /// Emit four bytes (little-endian).
    pub fn emit32(self: *CodeBuffer, v: u32) !void {
        try self.bytes.appendSlice(self.allocator, &.{
            @truncate(v),
            @truncate(v >> 8),
            @truncate(v >> 16),
            @truncate(v >> 24),
        });
    }

    /// Emit eight bytes (little-endian).
    pub fn emit64(self: *CodeBuffer, v: u64) !void {
        try self.bytes.appendSlice(self.allocator, &.{
            @truncate(v),
            @truncate(v >> 8),
            @truncate(v >> 16),
            @truncate(v >> 24),
            @truncate(v >> 32),
            @truncate(v >> 40),
            @truncate(v >> 48),
            @truncate(v >> 56),
        });
    }

    /// Emit a slice of bytes.
    pub fn emitSlice(self: *CodeBuffer, slice: []const u8) !void {
        try self.bytes.appendSlice(self.allocator, slice);
    }

    /// Add a relocation at current position.
    pub fn addRelocation(self: *CodeBuffer, kind: RelocKind, symbol: []const u8, addend: i64) !void {
        const offset = self.pos();
        try self.relocations.append(self.allocator, .{
            .offset = offset,
            .kind = kind,
            .symbol = symbol,
            .addend = addend,
        });
        log_codegen.debug("reloc: {s} @ {d} ({s}+{d})", .{
            @tagName(kind),
            offset,
            symbol,
            addend,
        });
    }

    /// Patch a 32-bit value at a previous offset.
    pub fn patch32(self: *CodeBuffer, offset: u32, v: u32) void {
        self.bytes.items[offset] = @truncate(v);
        self.bytes.items[offset + 1] = @truncate(v >> 8);
        self.bytes.items[offset + 2] = @truncate(v >> 16);
        self.bytes.items[offset + 3] = @truncate(v >> 24);
    }

    /// Get bytes as slice.
    pub fn getBytes(self: *const CodeBuffer) []const u8 {
        return self.bytes.items;
    }
};

// ============================================================================
// Backend Interface
// ============================================================================

/// Backend interface for code generation.
/// Each architecture implements this interface.
pub const Backend = struct {
    /// Virtual function table.
    vtable: *const VTable,
    /// Implementation pointer.
    ptr: *anyopaque,

    pub const VTable = struct {
        /// Generate code for an SSA function.
        genFunc: *const fn (*anyopaque, *ssa.Func, *CodeBuffer) anyerror!void,
        /// Generate code for a single SSA value.
        genValue: *const fn (*anyopaque, *ssa.Func, *ssa.Value, *CodeBuffer, *StorageManager) anyerror!void,
        /// Generate code for block control flow.
        genBlock: *const fn (*anyopaque, *ssa.Func, *ssa.Block, ?*ssa.Block, *CodeBuffer) anyerror!void,
        /// Emit function prologue.
        emitPrologue: *const fn (*anyopaque, *CodeBuffer, *StorageManager) anyerror!void,
        /// Emit function epilogue.
        emitEpilogue: *const fn (*anyopaque, *CodeBuffer, *StorageManager) anyerror!void,
    };

    /// Generate code for a function.
    pub fn genFunc(self: Backend, func: *ssa.Func, buf: *CodeBuffer) !void {
        return self.vtable.genFunc(self.ptr, func, buf);
    }

    /// Generate code for a value.
    pub fn genValue(self: Backend, func: *ssa.Func, v: *ssa.Value, buf: *CodeBuffer, storage: *StorageManager) !void {
        return self.vtable.genValue(self.ptr, func, v, buf, storage);
    }

    /// Generate block control flow.
    pub fn genBlock(self: Backend, func: *ssa.Func, b: *ssa.Block, next: ?*ssa.Block, buf: *CodeBuffer) !void {
        return self.vtable.genBlock(self.ptr, func, b, next, buf);
    }

    /// Emit prologue.
    pub fn emitPrologue(self: Backend, buf: *CodeBuffer, storage: *StorageManager) !void {
        return self.vtable.emitPrologue(self.ptr, buf, storage);
    }

    /// Emit epilogue.
    pub fn emitEpilogue(self: Backend, buf: *CodeBuffer, storage: *StorageManager) !void {
        return self.vtable.emitEpilogue(self.ptr, buf, storage);
    }
};

// ============================================================================
// Calling Convention
// ============================================================================

/// Calling convention definition.
pub const CallConv = struct {
    /// Registers for integer arguments.
    param_regs: []const GeneralReg,
    /// Registers for float arguments.
    float_param_regs: []const FloatReg,
    /// Registers for return values.
    return_regs: []const GeneralReg,
    /// Callee-saved registers.
    callee_saved: []const GeneralReg,
    /// Stack alignment requirement.
    stack_align: u8,
    /// Red zone size (bytes below RSP that can be used without allocation).
    red_zone: u32,
};

// ============================================================================
// Target Configuration
// ============================================================================

/// Target architecture.
pub const Arch = enum {
    x86_64,
    aarch64,
};

/// Target operating system.
pub const OS = enum {
    linux,
    macos,
    windows,
};

/// Complete target specification.
pub const Target = struct {
    arch: Arch,
    os: OS,

    /// Get the appropriate calling convention.
    pub fn getCallConv(self: Target) CallConv {
        return switch (self.arch) {
            .x86_64 => switch (self.os) {
                .linux, .macos => systemv_call_conv,
                .windows => windows_call_conv,
            },
            .aarch64 => aarch64_call_conv,
        };
    }

    /// Get pointer size in bytes.
    pub fn ptrSize(self: Target) u8 {
        return switch (self.arch) {
            .x86_64, .aarch64 => 8,
        };
    }
};

// ============================================================================
// Pre-defined calling conventions
// ============================================================================

/// System V AMD64 ABI (Linux, macOS, BSD).
pub const systemv_call_conv = CallConv{
    .param_regs = &.{ 7, 6, 2, 1, 8, 9 }, // rdi, rsi, rdx, rcx, r8, r9
    .float_param_regs = &.{ 0, 1, 2, 3, 4, 5, 6, 7 }, // xmm0-xmm7
    .return_regs = &.{ 0, 2 }, // rax, rdx
    .callee_saved = &.{ 3, 12, 13, 14, 15, 5 }, // rbx, r12, r13, r14, r15, rbp
    .stack_align = 16,
    .red_zone = 128,
};

/// Windows x64 calling convention.
pub const windows_call_conv = CallConv{
    .param_regs = &.{ 1, 2, 8, 9 }, // rcx, rdx, r8, r9
    .float_param_regs = &.{ 0, 1, 2, 3 }, // xmm0-xmm3
    .return_regs = &.{0}, // rax
    .callee_saved = &.{ 3, 5, 6, 7, 12, 13, 14, 15 }, // rbx, rbp, rsi, rdi, r12-r15
    .stack_align = 16,
    .red_zone = 0, // No red zone on Windows
};

/// AArch64 calling convention (AAPCS64).
pub const aarch64_call_conv = CallConv{
    .param_regs = &.{ 0, 1, 2, 3, 4, 5, 6, 7 }, // x0-x7
    .float_param_regs = &.{ 0, 1, 2, 3, 4, 5, 6, 7 }, // v0-v7
    .return_regs = &.{ 0, 1 }, // x0, x1
    .callee_saved = &.{ 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29 }, // x19-x29
    .stack_align = 16,
    .red_zone = 0,
};

// ============================================================================
// Tests
// ============================================================================

test "storage manager" {
    const allocator = std.testing.allocator;
    var sm = StorageManager.init(allocator);
    defer sm.deinit();

    // Add some free registers
    try sm.free_general_regs.append(allocator, 0); // rax
    try sm.free_general_regs.append(allocator, 1); // rcx

    // Allocate a register
    const reg = sm.allocGeneral();
    try std.testing.expect(reg != null);
    try std.testing.expectEqual(@as(GeneralReg, 1), reg.?);

    // Set storage for a value
    try sm.setStorage(1, .{ .general_reg = reg.? });
    try std.testing.expectEqual(Storage{ .general_reg = 1 }, sm.getStorage(1));
}

test "code buffer" {
    const allocator = std.testing.allocator;
    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    try buf.emit8(0x48);
    try buf.emit32(0x12345678);

    try std.testing.expectEqual(@as(u32, 5), buf.pos());
    try std.testing.expectEqualSlices(u8, &.{ 0x48, 0x78, 0x56, 0x34, 0x12 }, buf.getBytes());
}

test "target call conv" {
    const linux_x64 = Target{ .arch = .x86_64, .os = .linux };
    const cc = linux_x64.getCallConv();

    try std.testing.expectEqual(@as(u8, 16), cc.stack_align);
    try std.testing.expectEqual(@as(u32, 128), cc.red_zone);
}
