///! Object file generation (ELF and Mach-O).
///!
///! Combines patterns from:
///! - Go: cmd/link/internal/ld (object file writing)
///! - Roc: gen_dev/src/object.rs (Mach-O generation)
///!
///! Key patterns:
///! - Abstract ObjectFile interface for format-agnostic code
///! - Section and symbol management
///! - Relocation application during linking
///! - Both ELF (Linux) and Mach-O (macOS) support

const std = @import("std");
const be = @import("backend.zig");
const debug = @import("../debug.zig");
const pe_coff = @import("pe_coff.zig");

const Allocator = std.mem.Allocator;
const CodeBuffer = be.CodeBuffer;
const Relocation = be.Relocation;
const RelocKind = be.RelocKind;

// Scoped logger for object file generation
const log = debug.scoped(.object);

// ============================================================================
// Mach-O Relocation Types (from Go/Zig compilers)
// ============================================================================

/// ARM64 Mach-O relocation types
pub const MachORelocARM64 = enum(u4) {
    ARM64_RELOC_UNSIGNED = 0, // Absolute address
    ARM64_RELOC_SUBTRACTOR = 1, // Must be followed by UNSIGNED
    ARM64_RELOC_BRANCH26 = 2, // B/BL with 26-bit displacement
    ARM64_RELOC_PAGE21 = 3, // ADRP page address
    ARM64_RELOC_PAGEOFF12 = 4, // ADD page offset
    ARM64_RELOC_GOT_LOAD_PAGE21 = 5, // GOT page
    ARM64_RELOC_GOT_LOAD_PAGEOFF12 = 6, // GOT page offset
    ARM64_RELOC_POINTER_TO_GOT = 7, // Pointer to GOT
    ARM64_RELOC_TLVP_LOAD_PAGE21 = 8, // TLV page
    ARM64_RELOC_TLVP_LOAD_PAGEOFF12 = 9, // TLV page offset
    ARM64_RELOC_ADDEND = 10, // Addend for following reloc
};

/// x86_64 Mach-O relocation types
pub const MachORelocX86_64 = enum(u4) {
    X86_64_RELOC_UNSIGNED = 0, // Absolute address
    X86_64_RELOC_SIGNED = 1, // Signed 32-bit displacement
    X86_64_RELOC_BRANCH = 2, // CALL/JMP with 32-bit displacement
    X86_64_RELOC_GOT_LOAD = 3, // MOVQ load of GOT entry
    X86_64_RELOC_GOT = 4, // Other GOT references
    X86_64_RELOC_SUBTRACTOR = 5, // Must be followed by UNSIGNED
    X86_64_RELOC_SIGNED_1 = 6, // Signed with -1 addend
    X86_64_RELOC_SIGNED_2 = 7, // Signed with -2 addend
    X86_64_RELOC_SIGNED_4 = 8, // Signed with -4 addend
    X86_64_RELOC_TLV = 9, // Thread local variables
};

/// Mach-O relocation_info packed struct (8 bytes)
/// Based on Zig's std/macho.zig definition
pub const MachORelocationInfo = packed struct {
    r_address: i32, // Offset in section
    r_symbolnum: u24, // Symbol index (if r_extern=1) or section ordinal
    r_pcrel: u1, // PC-relative?
    r_length: u2, // 0=byte, 1=word, 2=long (4), 3=quad (8)
    r_extern: u1, // External symbol?
    r_type: u4, // Relocation type

    /// Write relocation entry to buffer (8 bytes, little-endian)
    pub fn write(self: MachORelocationInfo, writer: anytype) !void {
        // Write r_address (4 bytes)
        try writer.writeInt(i32, self.r_address, .little);
        // Pack remaining fields into u32
        var word: u32 = 0;
        word |= @as(u32, self.r_symbolnum);
        word |= @as(u32, self.r_pcrel) << 24;
        word |= @as(u32, self.r_length) << 25;
        word |= @as(u32, self.r_extern) << 27;
        word |= @as(u32, self.r_type) << 28;
        try writer.writeInt(u32, word, .little);
    }
};

/// Convert internal relocation kind to Mach-O ARM64 relocation type
fn relocKindToMachOARM64(kind: RelocKind) MachORelocARM64 {
    return switch (kind) {
        .pc_rel_32 => .ARM64_RELOC_BRANCH26,
        .aarch64_adrp => .ARM64_RELOC_PAGE21,
        .aarch64_add_lo12 => .ARM64_RELOC_PAGEOFF12,
        .abs_64 => .ARM64_RELOC_UNSIGNED,
        .got_rel, .plt_rel => .ARM64_RELOC_BRANCH26, // Default for calls
    };
}

/// Convert internal relocation kind to Mach-O x86_64 relocation type
fn relocKindToMachOX86_64(kind: RelocKind) MachORelocX86_64 {
    return switch (kind) {
        .pc_rel_32 => .X86_64_RELOC_BRANCH,
        .abs_64 => .X86_64_RELOC_UNSIGNED,
        .got_rel => .X86_64_RELOC_GOT,
        .plt_rel => .X86_64_RELOC_BRANCH,
        .aarch64_adrp, .aarch64_add_lo12 => .X86_64_RELOC_SIGNED, // Fallback
    };
}

/// Is this relocation PC-relative?
fn isRelocPCRel(kind: RelocKind) bool {
    return switch (kind) {
        .pc_rel_32, .got_rel, .plt_rel, .aarch64_adrp => true,
        .abs_64, .aarch64_add_lo12 => false,
    };
}

/// Get relocation length (log2 of size in bytes)
fn getRelocLength(kind: RelocKind) u2 {
    return switch (kind) {
        .pc_rel_32, .aarch64_adrp, .aarch64_add_lo12 => 2, // 4 bytes
        .abs_64 => 3, // 8 bytes
        .got_rel, .plt_rel => 2, // 4 bytes
    };
}

// ============================================================================
// ELF Relocation Types (from Go/Zig compilers)
// ============================================================================

/// x86_64 ELF relocation types (from elf.h / Zig std/elf.zig)
pub const ElfRelocX86_64 = enum(u32) {
    R_X86_64_NONE = 0, // No relocation
    R_X86_64_64 = 1, // Direct 64-bit absolute
    R_X86_64_PC32 = 2, // PC-relative 32-bit signed
    R_X86_64_GOT32 = 3, // 32-bit GOT entry
    R_X86_64_PLT32 = 4, // 32-bit PLT address
    R_X86_64_COPY = 5, // Copy symbol at runtime
    R_X86_64_GLOB_DAT = 6, // Create GOT entry
    R_X86_64_JUMP_SLOT = 7, // Create PLT entry
    R_X86_64_RELATIVE = 8, // Adjust by program base
    R_X86_64_GOTPCREL = 9, // 32-bit PC-rel offset to GOT
    R_X86_64_32 = 10, // Direct 32-bit zero-extended
    R_X86_64_32S = 11, // Direct 32-bit sign-extended
};

/// ELF64 Rela structure (24 bytes)
/// Based on Zig's std/elf.zig Elf64_Rela
pub const Elf64Rela = struct {
    r_offset: u64, // Address in section where relocation applies
    r_info: u64, // Encodes symbol index (high 32) + type (low 32)
    r_addend: i64, // Constant addend for calculation

    /// Create r_info from symbol index and relocation type
    pub fn makeInfo(sym: u32, reloc_type: u32) u64 {
        return (@as(u64, sym) << 32) | @as(u64, reloc_type);
    }

    /// Write rela entry to buffer (24 bytes, little-endian)
    pub fn write(self: Elf64Rela, writer: anytype) !void {
        try writer.writeInt(u64, self.r_offset, .little);
        try writer.writeInt(u64, self.r_info, .little);
        try writer.writeInt(i64, self.r_addend, .little);
    }
};

/// Convert internal relocation kind to ELF x86_64 relocation type
fn relocKindToElfX86_64(kind: RelocKind) ElfRelocX86_64 {
    return switch (kind) {
        .pc_rel_32 => .R_X86_64_PC32,
        .abs_64 => .R_X86_64_64,
        .got_rel => .R_X86_64_GOTPCREL,
        .plt_rel => .R_X86_64_PLT32,
        .aarch64_adrp, .aarch64_add_lo12 => .R_X86_64_PC32, // Fallback for cross-arch
    };
}

/// Get ELF relocation addend for a given relocation kind
/// For PC-relative, addend is typically -4 to account for instruction size
fn getElfAddend(kind: RelocKind, stored_addend: i64) i64 {
    return switch (kind) {
        // PC-relative needs -4 addend (end of 4-byte immediate)
        .pc_rel_32, .plt_rel => stored_addend,
        .got_rel => stored_addend - 4,
        .abs_64 => stored_addend,
        .aarch64_adrp, .aarch64_add_lo12 => stored_addend,
    };
}

// ============================================================================
// Object File Format
// ============================================================================

pub const ObjectFormat = enum {
    elf64,
    macho64,
    coff,

    pub fn fromTarget(_: be.Arch, os: be.OS) ObjectFormat {
        return switch (os) {
            .linux => .elf64,
            .macos => .macho64,
            .windows => .coff,
        };
    }
};

// ============================================================================
// Symbols
// ============================================================================

pub const SymbolKind = enum {
    /// Function symbol.
    func,
    /// Data symbol (global variable).
    data,
    /// External reference (undefined, resolved at link time).
    external,
    /// Section symbol.
    section,
};

pub const Symbol = struct {
    name: []const u8,
    kind: SymbolKind,
    /// Section index this symbol belongs to.
    section: u16,
    /// Offset within section.
    offset: u64,
    /// Size of symbol (for functions/data).
    size: u64,
    /// Is this symbol globally visible?
    global: bool,
};

// ============================================================================
// Sections
// ============================================================================

pub const SectionKind = enum {
    /// Executable code.
    text,
    /// Read-only data.
    rodata,
    /// Initialized read-write data.
    data,
    /// Uninitialized data (BSS).
    bss,
};

pub const Section = struct {
    name: []const u8,
    kind: SectionKind,
    data: std.ArrayList(u8),
    relocations: std.ArrayList(Relocation),
    /// Alignment requirement (power of 2).
    alignment: u32,
    /// Virtual address (filled during linking).
    vaddr: u64,

    pub fn init(_: Allocator, name: []const u8, kind: SectionKind) Section {
        return .{
            .name = name,
            .kind = kind,
            .data = .{ .items = &.{}, .capacity = 0 },
            .relocations = .{ .items = &.{}, .capacity = 0 },
            .alignment = 16,
            .vaddr = 0,
        };
    }

    pub fn deinit(self: *Section, allocator: Allocator) void {
        self.data.deinit(allocator);
        self.relocations.deinit(allocator);
    }

    pub fn append(self: *Section, allocator: Allocator, bytes: []const u8) !void {
        try self.data.appendSlice(allocator, bytes);
    }

    pub fn size(self: *const Section) u64 {
        return self.data.items.len;
    }
};

// ============================================================================
// Object File Builder
// ============================================================================

pub const ObjectFile = struct {
    allocator: Allocator,
    format: ObjectFormat,
    arch: be.Arch,
    sections: std.ArrayList(Section),
    symbols: std.ArrayList(Symbol),

    /// String table for symbol names.
    strtab: std.ArrayList(u8),

    pub fn init(allocator: Allocator, format: ObjectFormat) ObjectFile {
        return initWithArch(allocator, format, .aarch64);
    }

    pub fn initWithArch(allocator: Allocator, format: ObjectFormat, arch: be.Arch) ObjectFile {
        var obj = ObjectFile{
            .allocator = allocator,
            .format = format,
            .arch = arch,
            .sections = .{ .items = &.{}, .capacity = 0 },
            .symbols = .{ .items = &.{}, .capacity = 0 },
            .strtab = .{ .items = &.{}, .capacity = 0 },
        };

        // Add null byte at start of string table
        obj.strtab.append(allocator, 0) catch {};

        return obj;
    }

    pub fn deinit(self: *ObjectFile) void {
        for (self.sections.items) |*sec| {
            sec.deinit(self.allocator);
        }
        self.sections.deinit(self.allocator);
        self.symbols.deinit(self.allocator);
        self.strtab.deinit(self.allocator);
    }

    /// Add a new section.
    pub fn addSection(self: *ObjectFile, name: []const u8, kind: SectionKind) !u16 {
        const idx: u16 = @intCast(self.sections.items.len);
        try self.sections.append(self.allocator, Section.init(self.allocator, name, kind));
        log.debug("addSection: {s} (kind={s}, idx={d})", .{ name, @tagName(kind), idx });
        return idx;
    }

    /// Get a section by index.
    pub fn getSection(self: *ObjectFile, idx: u16) *Section {
        return &self.sections.items[idx];
    }

    /// Add a string to the string table, return offset.
    fn addString(self: *ObjectFile, str: []const u8) !u32 {
        const offset: u32 = @intCast(self.strtab.items.len);
        try self.strtab.appendSlice(self.allocator, str);
        try self.strtab.append(self.allocator, 0); // Null terminator
        return offset;
    }

    /// Add a symbol.
    pub fn addSymbol(self: *ObjectFile, sym: Symbol) !u32 {
        const idx: u32 = @intCast(self.symbols.items.len);
        try self.symbols.append(self.allocator, sym);
        log.debug("addSymbol: {s} (kind={s}, section={d}, offset={d})", .{
            sym.name,
            @tagName(sym.kind),
            sym.section,
            sym.offset,
        });
        return idx;
    }

    /// Add an external (undefined) symbol reference.
    /// Returns the symbol index for use in relocations.
    pub fn addExternalSymbol(self: *ObjectFile, name: []const u8) !u32 {
        // Check if already exists
        for (self.symbols.items, 0..) |sym, i| {
            if (std.mem.eql(u8, sym.name, name)) {
                return @intCast(i);
            }
        }
        // Add new external symbol
        return self.addSymbol(.{
            .name = name,
            .kind = .external,
            .section = 0, // NO_SECT
            .offset = 0,
            .size = 0,
            .global = true,
        });
    }

    /// Get or create a symbol index for a relocation target.
    /// For external symbols, creates an undefined reference.
    /// For local symbols, returns existing symbol index.
    pub fn getSymbolIndex(self: *ObjectFile, name: []const u8) !u32 {
        // Look up existing symbol
        for (self.symbols.items, 0..) |sym, i| {
            if (std.mem.eql(u8, sym.name, name)) {
                return @intCast(i);
            }
        }
        // Not found - add as external
        return self.addExternalSymbol(name);
    }

    /// Add code from a CodeBuffer to a section.
    pub fn addCode(self: *ObjectFile, section_idx: u16, buf: *const CodeBuffer) !void {
        var sec = self.getSection(section_idx);
        try sec.append(self.allocator, buf.getBytes());

        // Copy relocations
        for (buf.relocations.items) |reloc| {
            try sec.relocations.append(self.allocator, reloc);
        }

        log.debug("addCode: {d} bytes to section {d}", .{ buf.getBytes().len, section_idx });
    }

    /// Look up a symbol by name.
    fn findSymbol(self: *const ObjectFile, name: []const u8) ?*const Symbol {
        for (self.symbols.items) |*sym| {
            if (std.mem.eql(u8, sym.name, name)) {
                return sym;
            }
        }
        return null;
    }

    /// Apply local relocations (resolve symbols within the same object file).
    /// For ELF64 and MachO, we patch local function calls directly.
    /// For COFF, we leave all relocations for the Windows linker to handle.
    pub fn applyLocalRelocations(self: *ObjectFile) void {
        // Skip local patching for COFF - Windows linker handles all relocations
        if (self.format == .coff) return;

        for (self.sections.items) |*sec| {
            for (sec.relocations.items) |reloc| {
                // Look up the target symbol
                if (self.findSymbol(reloc.symbol)) |target_sym| {
                    // Both are in the same section - compute relative offset
                    const reloc_offset = reloc.offset;
                    const target_offset = target_sym.offset;

                    // Patch the instruction based on format
                    if (reloc.kind == .pc_rel_32 and sec.data.items.len > reloc_offset + 3) {
                        if (self.format == .elf64) {
                            // x86_64: CALL e8 uses 32-bit signed offset from END of instruction
                            // The relocation offset points to the 4-byte offset field (after e8 opcode)
                            // PC is at reloc_offset + 4 (end of instruction)
                            const pc: i64 = @as(i64, @intCast(reloc_offset)) + 4;
                            const byte_offset: i32 = @intCast(@as(i64, @intCast(target_offset)) - pc);

                            log.debug("applyLocalReloc x86_64: {s} at {d} -> target at {d}, offset={d}", .{
                                reloc.symbol,
                                reloc_offset,
                                target_offset,
                                byte_offset,
                            });

                            // Write 32-bit little-endian offset
                            const offset_u32: u32 = @bitCast(byte_offset);
                            sec.data.items[reloc_offset] = @truncate(offset_u32);
                            sec.data.items[reloc_offset + 1] = @truncate(offset_u32 >> 8);
                            sec.data.items[reloc_offset + 2] = @truncate(offset_u32 >> 16);
                            sec.data.items[reloc_offset + 3] = @truncate(offset_u32 >> 24);
                        } else {
                            // ARM64 BL instruction: offset is in instructions (4 bytes each)
                            // PC-relative: (target - site) / 4
                            const signed_offset: i64 = @as(i64, @intCast(target_offset)) - @as(i64, @intCast(reloc_offset));
                            const inst_offset: i32 = @intCast(@divTrunc(signed_offset, 4));

                            log.debug("applyLocalReloc arm64: {s} at {d} -> target at {d}, offset={d}", .{
                                reloc.symbol,
                                reloc_offset,
                                target_offset,
                                inst_offset,
                            });

                            // For ARM64 BL: instruction is at reloc_offset, offset goes in bits [25:0]
                            // Read existing instruction
                            const inst_bytes = sec.data.items[reloc_offset .. reloc_offset + 4];
                            var inst: u32 = @as(u32, inst_bytes[0]) |
                                (@as(u32, inst_bytes[1]) << 8) |
                                (@as(u32, inst_bytes[2]) << 16) |
                                (@as(u32, inst_bytes[3]) << 24);

                            // Mask out old offset (bits 25:0), insert new offset
                            inst &= 0xFC000000; // Keep opcode bits
                            inst |= @as(u32, @bitCast(inst_offset)) & 0x03FFFFFF;

                            // Write back
                            sec.data.items[reloc_offset] = @truncate(inst);
                            sec.data.items[reloc_offset + 1] = @truncate(inst >> 8);
                            sec.data.items[reloc_offset + 2] = @truncate(inst >> 16);
                            sec.data.items[reloc_offset + 3] = @truncate(inst >> 24);
                        }
                    }
                }
            }
        }
    }

    /// Write object file to buffer.
    pub fn write(self: *ObjectFile, writer: anytype) !void {
        switch (self.format) {
            .elf64 => try self.writeELF64(writer),
            .macho64 => try self.writeMachO64(writer),
            .coff => try self.writeCOFF(writer),
        }
    }

    /// Write to a file.
    pub fn writeToFile(self: *ObjectFile, path: []const u8) !void {
        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        // Write using ArrayList to buffer, then write all at once
        var output: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
        defer output.deinit(self.allocator);

        try self.write(output.writer(self.allocator));
        try file.writeAll(output.items);
        log.debug("wrote object file: {s}", .{path});
    }

    // ========================================================================
    // ELF64 Writer
    // ========================================================================

    fn writeELF64(self: *ObjectFile, writer: anytype) !void {
        // ELF64 constants
        const ELF_MAGIC = "\x7fELF";
        const ELFCLASS64: u8 = 2;
        const ELFDATA2LSB: u8 = 1; // Little-endian
        const EV_CURRENT: u8 = 1;
        const ELFOSABI_NONE: u8 = 0;
        const ET_REL: u16 = 1; // Relocatable
        const EM_X86_64: u16 = 62;

        // Section header types
        const SHT_PROGBITS: u32 = 1;
        const SHT_SYMTAB: u32 = 2;
        const SHT_STRTAB: u32 = 3;
        const SHT_RELA: u32 = 4;
        const SHT_NOBITS: u32 = 8;

        // Section flags
        const SHF_WRITE: u64 = 0x1;
        const SHF_ALLOC: u64 = 0x2;
        const SHF_EXECINSTR: u64 = 0x4;
        const SHF_INFO_LINK: u64 = 0x40;

        // Sizes
        const header_size: u64 = 64;
        const sym_size: u64 = 24;
        const rela_size: u64 = 24;

        // Count sections with relocations
        var num_rela_sections: u32 = 0;
        var section_reloc_counts: [16]u32 = .{0} ** 16;
        for (self.sections.items, 0..) |sec, i| {
            // Count external relocations (skip local function calls)
            var count: u32 = 0;
            for (sec.relocations.items) |reloc| {
                if (reloc.kind == .pc_rel_32) {
                    var is_local_func = false;
                    for (self.symbols.items) |sym| {
                        if (std.mem.eql(u8, sym.name, reloc.symbol) and sym.kind == .func) {
                            is_local_func = true;
                            break;
                        }
                    }
                    if (is_local_func) continue;
                }
                count += 1;
            }
            section_reloc_counts[i] = count;
            if (count > 0) num_rela_sections += 1;
        }

        // Ensure all external symbols from relocations are in symbol table
        for (self.sections.items) |sec| {
            for (sec.relocations.items) |reloc| {
                _ = self.getSymbolIndex(reloc.symbol) catch {};
            }
        }

        // Build symbol ordering: locals first, then globals
        // This is required by ELF - sh_info points to first global symbol
        var local_indices: [64]u32 = undefined;
        var global_indices: [64]u32 = undefined;
        var num_locals: u32 = 0;
        var num_globals: u32 = 0;

        for (self.symbols.items, 0..) |sym, i| {
            const is_global = sym.global or sym.kind == .external;
            if (is_global) {
                global_indices[num_globals] = @intCast(i);
                num_globals += 1;
            } else {
                local_indices[num_locals] = @intCast(i);
                num_locals += 1;
            }
        }

        // Map from original index to ELF symbol index (1-based, 0 is null)
        var sym_elf_index: [64]u32 = undefined;
        for (local_indices[0..num_locals], 0..) |orig_idx, i| {
            sym_elf_index[orig_idx] = @intCast(i + 1);
        }
        for (global_indices[0..num_globals], 0..) |orig_idx, i| {
            sym_elf_index[orig_idx] = @intCast(num_locals + i + 1);
        }

        // First global symbol index (1-based, after null + locals)
        const first_global_idx: u32 = num_locals + 1;

        // Build symbol string table (strtab)
        var strtab: [2048]u8 = undefined;
        var strtab_len: u32 = 1; // Start with null byte
        strtab[0] = 0;

        var sym_name_offsets: [64]u32 = undefined;
        for (self.symbols.items, 0..) |sym, i| {
            sym_name_offsets[i] = strtab_len;
            for (sym.name) |c| {
                strtab[strtab_len] = c;
                strtab_len += 1;
            }
            strtab[strtab_len] = 0;
            strtab_len += 1;
        }

        // Build section header string table (shstrtab)
        var shstrtab: [512]u8 = undefined;
        var shstrtab_len: u32 = 1;
        shstrtab[0] = 0;

        // Section name offsets
        var section_name_offsets: [16]u32 = undefined;
        var rela_name_offsets: [16]u32 = undefined;

        for (self.sections.items, 0..) |sec, i| {
            section_name_offsets[i] = shstrtab_len;
            const name = switch (sec.kind) {
                .text => ".text",
                .data => ".data",
                .rodata => ".rodata",
                .bss => ".bss",
            };
            for (name) |c| {
                shstrtab[shstrtab_len] = c;
                shstrtab_len += 1;
            }
            shstrtab[shstrtab_len] = 0;
            shstrtab_len += 1;
        }

        // Add .rela section names
        for (self.sections.items, 0..) |sec, i| {
            if (section_reloc_counts[i] > 0) {
                rela_name_offsets[i] = shstrtab_len;
                const name = switch (sec.kind) {
                    .text => ".rela.text",
                    .data => ".rela.data",
                    .rodata => ".rela.rodata",
                    .bss => ".rela.bss",
                };
                for (name) |c| {
                    shstrtab[shstrtab_len] = c;
                    shstrtab_len += 1;
                }
                shstrtab[shstrtab_len] = 0;
                shstrtab_len += 1;
            }
        }

        // Add standard section names
        const symtab_name_offset = shstrtab_len;
        for (".symtab") |c| {
            shstrtab[shstrtab_len] = c;
            shstrtab_len += 1;
        }
        shstrtab[shstrtab_len] = 0;
        shstrtab_len += 1;

        const strtab_name_offset = shstrtab_len;
        for (".strtab") |c| {
            shstrtab[shstrtab_len] = c;
            shstrtab_len += 1;
        }
        shstrtab[shstrtab_len] = 0;
        shstrtab_len += 1;

        const shstrtab_name_offset = shstrtab_len;
        for (".shstrtab") |c| {
            shstrtab[shstrtab_len] = c;
            shstrtab_len += 1;
        }
        shstrtab[shstrtab_len] = 0;
        shstrtab_len += 1;

        // Calculate section data sizes
        var section_data_size: u64 = 0;
        for (self.sections.items) |sec| {
            section_data_size += sec.size();
        }

        // Calculate relocation sizes
        var total_rela_size: u64 = 0;
        for (section_reloc_counts[0..self.sections.items.len]) |count| {
            total_rela_size += @as(u64, count) * rela_size;
        }

        // Symbol table: null + symbols
        const num_syms: u64 = 1 + self.symbols.items.len;
        const symtab_size: u64 = num_syms * sym_size;

        // Layout:
        // [header 64] [section data] [rela sections] [symtab] [strtab] [shstrtab] [section headers]
        const rela_offset = header_size + section_data_size;
        const symtab_offset = rela_offset + total_rela_size;
        const strtab_offset = symtab_offset + symtab_size;
        const shstrtab_offset = strtab_offset + strtab_len;
        const sh_offset = shstrtab_offset + shstrtab_len;

        // Section count: null + our sections + rela sections + symtab + strtab + shstrtab
        const num_sections: u16 = @intCast(1 + self.sections.items.len + num_rela_sections + 3);
        const symtab_idx: u16 = @intCast(1 + self.sections.items.len + num_rela_sections);
        const strtab_idx: u16 = symtab_idx + 1;
        const shstrtab_idx: u16 = strtab_idx + 1;

        // Write ELF header (64 bytes)
        try writer.writeAll(ELF_MAGIC);
        try writer.writeByte(ELFCLASS64);
        try writer.writeByte(ELFDATA2LSB);
        try writer.writeByte(EV_CURRENT);
        try writer.writeByte(ELFOSABI_NONE);
        try writer.writeByteNTimes(0, 8); // Padding

        try writer.writeInt(u16, ET_REL, .little);
        try writer.writeInt(u16, EM_X86_64, .little);
        try writer.writeInt(u32, 1, .little); // e_version
        try writer.writeInt(u64, 0, .little); // e_entry
        try writer.writeInt(u64, 0, .little); // e_phoff
        try writer.writeInt(u64, sh_offset, .little); // e_shoff
        try writer.writeInt(u32, 0, .little); // e_flags
        try writer.writeInt(u16, 64, .little); // e_ehsize
        try writer.writeInt(u16, 0, .little); // e_phentsize
        try writer.writeInt(u16, 0, .little); // e_phnum
        try writer.writeInt(u16, 64, .little); // e_shentsize
        try writer.writeInt(u16, num_sections, .little);
        try writer.writeInt(u16, shstrtab_idx, .little);

        // Write section data
        for (self.sections.items) |sec| {
            try writer.writeAll(sec.data.items);
        }

        // Write relocation entries
        for (self.sections.items) |sec| {
            for (sec.relocations.items) |reloc| {
                // Skip local function calls
                if (reloc.kind == .pc_rel_32) {
                    var is_local_func = false;
                    for (self.symbols.items) |sym| {
                        if (std.mem.eql(u8, sym.name, reloc.symbol) and sym.kind == .func) {
                            is_local_func = true;
                            break;
                        }
                    }
                    if (is_local_func) continue;
                }

                // Find symbol index using the mapping (accounts for local/global ordering)
                var sym_idx: u32 = 0;
                for (self.symbols.items, 0..) |sym, i| {
                    if (std.mem.eql(u8, sym.name, reloc.symbol)) {
                        sym_idx = sym_elf_index[i];
                        break;
                    }
                }

                const reloc_type = @intFromEnum(relocKindToElfX86_64(reloc.kind));
                const rela = Elf64Rela{
                    .r_offset = reloc.offset,
                    .r_info = Elf64Rela.makeInfo(sym_idx, reloc_type),
                    .r_addend = getElfAddend(reloc.kind, reloc.addend),
                };
                try rela.write(writer);
            }
        }

        // Write symbol table (null, then locals, then globals)
        try writer.writeByteNTimes(0, 24); // Null symbol

        // Helper to write a single symbol
        const writeSymbol = struct {
            fn write(w: anytype, sym: Symbol, name_offset: u32) !void {
                const STB_LOCAL_: u8 = 0;
                const STB_GLOBAL_: u8 = 1;
                const STT_NOTYPE_: u8 = 0;
                const STT_OBJECT_: u8 = 1;
                const STT_FUNC_: u8 = 2;
                const STT_SECTION_: u8 = 3;
                const STV_DEFAULT_: u8 = 0;
                const SHN_UNDEF_: u16 = 0;

                try w.writeInt(u32, name_offset, .little); // st_name

                const st_type: u8 = switch (sym.kind) {
                    .func => STT_FUNC_,
                    .data => STT_OBJECT_,
                    .external => STT_NOTYPE_,
                    .section => STT_SECTION_,
                };
                const st_bind: u8 = if (sym.global or sym.kind == .external) STB_GLOBAL_ else STB_LOCAL_;
                try w.writeByte((st_bind << 4) | st_type);

                try w.writeByte(STV_DEFAULT_); // st_other

                const st_shndx: u16 = if (sym.kind == .external) SHN_UNDEF_ else sym.section + 1;
                try w.writeInt(u16, st_shndx, .little);

                try w.writeInt(u64, sym.offset, .little); // st_value
                try w.writeInt(u64, sym.size, .little); // st_size
            }
        }.write;

        // Write local symbols first
        for (local_indices[0..num_locals]) |orig_idx| {
            const sym = self.symbols.items[orig_idx];
            try writeSymbol(writer, sym, sym_name_offsets[orig_idx]);
        }

        // Write global symbols
        for (global_indices[0..num_globals]) |orig_idx| {
            const sym = self.symbols.items[orig_idx];
            try writeSymbol(writer, sym, sym_name_offsets[orig_idx]);
        }

        // Write strtab
        try writer.writeAll(strtab[0..strtab_len]);

        // Write shstrtab
        try writer.writeAll(shstrtab[0..shstrtab_len]);

        // Write section headers
        // Null section
        try writer.writeByteNTimes(0, 64);

        // Our sections
        var data_offset: u64 = header_size;
        for (self.sections.items, 0..) |sec, i| {
            var sh_type: u32 = SHT_PROGBITS;
            var sh_flags: u64 = SHF_ALLOC;

            switch (sec.kind) {
                .text => sh_flags |= SHF_EXECINSTR,
                .data => sh_flags |= SHF_WRITE,
                .rodata => {},
                .bss => {
                    sh_type = SHT_NOBITS;
                    sh_flags |= SHF_WRITE;
                },
            }

            try writer.writeInt(u32, section_name_offsets[i], .little);
            try writer.writeInt(u32, sh_type, .little);
            try writer.writeInt(u64, sh_flags, .little);
            try writer.writeInt(u64, 0, .little); // sh_addr
            try writer.writeInt(u64, data_offset, .little);
            try writer.writeInt(u64, sec.size(), .little);
            try writer.writeInt(u32, 0, .little); // sh_link
            try writer.writeInt(u32, 0, .little); // sh_info
            try writer.writeInt(u64, sec.alignment, .little);
            try writer.writeInt(u64, 0, .little); // sh_entsize
            data_offset += sec.size();
        }

        // .rela sections
        var rela_file_offset: u64 = rela_offset;
        for (self.sections.items, 0..) |_, i| {
            const count = section_reloc_counts[i];
            if (count > 0) {
                try writer.writeInt(u32, rela_name_offsets[i], .little);
                try writer.writeInt(u32, SHT_RELA, .little);
                try writer.writeInt(u64, SHF_INFO_LINK, .little);
                try writer.writeInt(u64, 0, .little); // sh_addr
                try writer.writeInt(u64, rela_file_offset, .little);
                try writer.writeInt(u64, @as(u64, count) * rela_size, .little);
                try writer.writeInt(u32, symtab_idx, .little); // sh_link = symtab
                try writer.writeInt(u32, @intCast(i + 1), .little); // sh_info = section being relocated
                try writer.writeInt(u64, 8, .little); // sh_addralign
                try writer.writeInt(u64, rela_size, .little); // sh_entsize
                rela_file_offset += @as(u64, count) * rela_size;
            }
        }

        // .symtab section header
        try writer.writeInt(u32, symtab_name_offset, .little);
        try writer.writeInt(u32, SHT_SYMTAB, .little);
        try writer.writeInt(u64, 0, .little);
        try writer.writeInt(u64, 0, .little);
        try writer.writeInt(u64, symtab_offset, .little);
        try writer.writeInt(u64, symtab_size, .little);
        try writer.writeInt(u32, strtab_idx, .little); // sh_link = strtab
        try writer.writeInt(u32, first_global_idx, .little); // sh_info = first global symbol
        try writer.writeInt(u64, 8, .little);
        try writer.writeInt(u64, sym_size, .little);

        // .strtab section header
        try writer.writeInt(u32, strtab_name_offset, .little);
        try writer.writeInt(u32, SHT_STRTAB, .little);
        try writer.writeInt(u64, 0, .little);
        try writer.writeInt(u64, 0, .little);
        try writer.writeInt(u64, strtab_offset, .little);
        try writer.writeInt(u64, strtab_len, .little);
        try writer.writeInt(u32, 0, .little);
        try writer.writeInt(u32, 0, .little);
        try writer.writeInt(u64, 1, .little);
        try writer.writeInt(u64, 0, .little);

        // .shstrtab section header
        try writer.writeInt(u32, shstrtab_name_offset, .little);
        try writer.writeInt(u32, SHT_STRTAB, .little);
        try writer.writeInt(u64, 0, .little);
        try writer.writeInt(u64, 0, .little);
        try writer.writeInt(u64, shstrtab_offset, .little);
        try writer.writeInt(u64, shstrtab_len, .little);
        try writer.writeInt(u32, 0, .little);
        try writer.writeInt(u32, 0, .little);
        try writer.writeInt(u64, 1, .little);
        try writer.writeInt(u64, 0, .little);

        log.debug("writeELF64: {d} sections, {d} symbols, {d} rela sections", .{
            self.sections.items.len,
            self.symbols.items.len,
            num_rela_sections,
        });
    }

    // ========================================================================
    // Mach-O 64 Writer
    // ========================================================================

    fn writeMachO64(self: *ObjectFile, writer: anytype) !void {
        // Mach-O constants
        const MH_MAGIC_64: u32 = 0xFEEDFACF;
        const CPU_TYPE_ARM64: u32 = 0x0100000C;
        const CPU_TYPE_X86_64: u32 = 0x01000007;
        const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
        const CPU_SUBTYPE_X86_64_ALL: u32 = 3;
        const MH_OBJECT: u32 = 1;
        const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x2000;

        const LC_SEGMENT_64: u32 = 0x19;
        const LC_SYMTAB: u32 = 0x02;

        // Symbol table constants
        const N_EXT: u8 = 0x01; // External symbol
        const N_UNDF: u8 = 0x00; // Undefined (external reference)
        const N_SECT: u8 = 0x0e; // Symbol defined in section

        // Calculate sizes
        const header_size: u32 = 32;
        const segment_cmd_size: u32 = 72;
        const section_hdr_size: u32 = 80;
        const symtab_cmd_size: u32 = 24;
        const reloc_entry_size: u32 = 8;
        const nlist_size: u32 = 16;

        const num_sections: u32 = @intCast(self.sections.items.len);
        const load_cmds_size = segment_cmd_size + (num_sections * section_hdr_size) + symtab_cmd_size;

        // Calculate section data size
        var section_data_size: u64 = 0;
        for (self.sections.items) |sec| {
            section_data_size += sec.size();
        }

        // Count relocations per section
        // Skip local pc_rel_32 (BL) relocations - they're patched by applyLocalRelocations
        // Keep ADRP/ADD relocations even for local symbols - linker needs to fix addresses
        var section_reloc_counts: [16]u32 = .{0} ** 16;
        var total_reloc_count: u32 = 0;
        for (self.sections.items, 0..) |sec, sec_idx| {
            var count: u32 = 0;
            for (sec.relocations.items) |reloc| {
                // Only skip pc_rel_32 for local function symbols
                // ADRP/ADD relocations need to be emitted even for local symbols
                if (reloc.kind == .pc_rel_32) {
                    var is_local_func = false;
                    for (self.symbols.items) |sym| {
                        if (std.mem.eql(u8, sym.name, reloc.symbol)) {
                            if (sym.kind == .func) {
                                is_local_func = true;
                            }
                            break;
                        }
                    }
                    if (is_local_func) continue;
                }
                count += 1;
            }
            section_reloc_counts[sec_idx] = count;
            total_reloc_count += count;
        }
        const total_reloc_size: u64 = @as(u64, total_reloc_count) * reloc_entry_size;

        // Ensure all external symbols are in symbol table
        for (self.sections.items) |sec| {
            for (sec.relocations.items) |reloc| {
                _ = self.getSymbolIndex(reloc.symbol) catch {};
            }
        }

        // File layout:
        // [header 32] [load_cmds] [section_data] [relocations] [symtab] [strtab]
        const section_data_start: u64 = header_size + load_cmds_size;
        const reloc_start: u64 = section_data_start + section_data_size;
        const symtab_start: u64 = reloc_start + total_reloc_size;

        // Calculate symbol and string table sizes
        const nsyms: u32 = @intCast(self.symbols.items.len);
        const strtab_start: u64 = symtab_start + (@as(u64, nsyms) * nlist_size);

        var strtab_size: u32 = 1; // Start with null byte
        for (self.symbols.items) |sym| {
            strtab_size += @intCast(sym.name.len + 1);
        }

        // Select CPU type based on architecture
        const cpu_type: u32 = if (self.arch == .x86_64) CPU_TYPE_X86_64 else CPU_TYPE_ARM64;
        const cpu_subtype: u32 = if (self.arch == .x86_64) CPU_SUBTYPE_X86_64_ALL else CPU_SUBTYPE_ARM64_ALL;

        // Mach-O header (32 bytes for 64-bit)
        try writer.writeInt(u32, MH_MAGIC_64, .little);
        try writer.writeInt(u32, cpu_type, .little);
        try writer.writeInt(u32, cpu_subtype, .little);
        try writer.writeInt(u32, MH_OBJECT, .little);
        try writer.writeInt(u32, 2, .little); // ncmds (segment + symtab)
        try writer.writeInt(u32, load_cmds_size, .little); // sizeofcmds
        try writer.writeInt(u32, MH_SUBSECTIONS_VIA_SYMBOLS, .little); // flags
        try writer.writeInt(u32, 0, .little); // reserved

        // LC_SEGMENT_64 command
        try writer.writeInt(u32, LC_SEGMENT_64, .little);
        try writer.writeInt(u32, segment_cmd_size + (num_sections * section_hdr_size), .little);
        try writer.writeByteNTimes(0, 16); // segname (empty for object files)
        try writer.writeInt(u64, 0, .little); // vmaddr
        try writer.writeInt(u64, section_data_size, .little); // vmsize
        try writer.writeInt(u64, section_data_start, .little); // fileoff
        try writer.writeInt(u64, section_data_size, .little); // filesize
        try writer.writeInt(u32, 0x7, .little); // maxprot (rwx)
        try writer.writeInt(u32, 0x7, .little); // initprot
        try writer.writeInt(u32, num_sections, .little); // nsects
        try writer.writeInt(u32, 0, .little); // flags

        // Section headers with relocation info
        var section_file_offset: u64 = section_data_start;
        var section_reloc_offset: u64 = reloc_start;
        for (self.sections.items, 0..) |sec, sec_idx| {
            const nreloc: u32 = section_reloc_counts[sec_idx];
            const reloff: u32 = if (nreloc > 0) @intCast(section_reloc_offset) else 0;
            try self.writeMachOSectionWithRelocs(writer, sec, section_file_offset, reloff, nreloc);
            section_file_offset += sec.size();
            section_reloc_offset += @as(u64, nreloc) * reloc_entry_size;
        }

        // LC_SYMTAB command
        try writer.writeInt(u32, LC_SYMTAB, .little);
        try writer.writeInt(u32, symtab_cmd_size, .little);
        try writer.writeInt(u32, @intCast(symtab_start), .little); // symoff
        try writer.writeInt(u32, nsyms, .little); // nsyms
        try writer.writeInt(u32, @intCast(strtab_start), .little); // stroff
        try writer.writeInt(u32, strtab_size, .little); // strsize

        // Write section data
        for (self.sections.items) |sec| {
            try writer.writeAll(sec.data.items);
        }

        // Write relocations for each section
        // Skip local pc_rel_32 (BL) for function calls - already patched
        for (self.sections.items) |sec| {
            for (sec.relocations.items) |reloc| {
                // Only skip pc_rel_32 for local function symbols
                if (reloc.kind == .pc_rel_32) {
                    var is_local_func = false;
                    for (self.symbols.items) |sym| {
                        if (std.mem.eql(u8, sym.name, reloc.symbol)) {
                            if (sym.kind == .func) {
                                is_local_func = true;
                            }
                            break;
                        }
                    }
                    if (is_local_func) continue;
                }

                // Get symbol index for this relocation
                const sym_idx = self.getSymbolIndex(reloc.symbol) catch 0;

                // Build relocation entry
                const r_type: u4 = if (self.arch == .x86_64)
                    @intFromEnum(relocKindToMachOX86_64(reloc.kind))
                else
                    @intFromEnum(relocKindToMachOARM64(reloc.kind));

                const reloc_info = MachORelocationInfo{
                    .r_address = @intCast(reloc.offset),
                    .r_symbolnum = @intCast(sym_idx),
                    .r_pcrel = if (isRelocPCRel(reloc.kind)) 1 else 0,
                    .r_length = getRelocLength(reloc.kind),
                    .r_extern = 1, // External symbol reference
                    .r_type = r_type,
                };
                try reloc_info.write(writer);
            }
        }

        // Write symbol table (nlist_64 entries)
        var str_offset: u32 = 1; // Skip initial null
        for (self.symbols.items) |sym| {
            // nlist_64: n_strx (4), n_type (1), n_sect (1), n_desc (2), n_value (8)
            try writer.writeInt(u32, str_offset, .little); // n_strx

            // n_type: external references use N_UNDF | N_EXT, defined use N_SECT | N_EXT
            const n_type: u8 = if (sym.kind == .external) (N_UNDF | N_EXT) else (N_SECT | N_EXT);
            try writer.writeInt(u8, n_type, .little);

            // n_sect: 0 for undefined, 1-indexed for defined
            const n_sect: u8 = if (sym.kind == .external) 0 else @intCast(sym.section + 1);
            try writer.writeInt(u8, n_sect, .little);

            try writer.writeInt(u16, 0, .little); // n_desc
            try writer.writeInt(u64, sym.offset, .little); // n_value
            str_offset += @intCast(sym.name.len + 1);
        }

        // Write string table
        try writer.writeInt(u8, 0, .little); // Initial null byte
        for (self.symbols.items) |sym| {
            try writer.writeAll(sym.name);
            try writer.writeInt(u8, 0, .little); // Null terminator
        }

        log.debug("writeMachO64: {d} sections, {d} symbols, {d} relocations", .{
            num_sections,
            nsyms,
            total_reloc_count,
        });
    }

    fn writeMachOSectionWithRelocs(self: *ObjectFile, writer: anytype, sec: Section, file_offset: u64, reloff: u32, nreloc: u32) !void {
        _ = self;

        // Section name (16 bytes, null-padded)
        var sectname: [16]u8 = .{0} ** 16;
        const name_len = @min(sec.name.len, 16);
        @memcpy(sectname[0..name_len], sec.name[0..name_len]);

        // Segment name (16 bytes)
        var segname: [16]u8 = .{0} ** 16;
        const seg = switch (sec.kind) {
            .text => "__TEXT",
            .rodata => "__TEXT",
            .data => "__DATA",
            .bss => "__DATA",
        };
        @memcpy(segname[0..seg.len], seg);

        // Section type and attributes
        const S_REGULAR: u32 = 0x0;
        const S_ZEROFILL: u32 = 0x1;
        const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x80000000;
        const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x00000400;

        var sec_type: u32 = S_REGULAR;
        var sec_attrs: u32 = 0;

        switch (sec.kind) {
            .text => sec_attrs = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
            .bss => sec_type = S_ZEROFILL,
            else => {},
        }

        try writer.writeAll(&sectname);
        try writer.writeAll(&segname);
        try writer.writeInt(u64, 0, .little); // addr (filled at link time)
        try writer.writeInt(u64, sec.size(), .little); // size
        try writer.writeInt(u32, @intCast(file_offset), .little); // offset
        try writer.writeInt(u32, 4, .little); // align (2^4 = 16)
        try writer.writeInt(u32, reloff, .little); // reloff
        try writer.writeInt(u32, nreloc, .little); // nreloc
        try writer.writeInt(u32, sec_type | sec_attrs, .little); // flags
        try writer.writeInt(u32, 0, .little); // reserved1
        try writer.writeInt(u32, 0, .little); // reserved2
        try writer.writeInt(u32, 0, .little); // reserved3 (64-bit only)

        log.debug("section {s}: reloff={d}, nreloc={d}", .{ sec.name, reloff, nreloc });
    }

    // ========================================================================
    // COFF Writer (Windows)
    // ========================================================================

    fn writeCOFF(self: *ObjectFile, writer: anytype) !void {
        // Use the pe_coff module to write COFF format
        var coff = pe_coff.CoffWriter.init(self.allocator, self.arch);
        defer coff.deinit();

        // Add sections
        for (self.sections.items) |sec| {
            const name = pe_coff.getCoffSectionName(sec.kind);
            const is_code = (sec.kind == .text);
            _ = try coff.addSection(name, sec.data.items, sec.relocations.items, is_code);
        }

        // Add symbols
        for (self.symbols.items) |sym| {
            const section: i16 = switch (sym.kind) {
                .external => pe_coff.SectionNumber.IMAGE_SYM_UNDEFINED,
                else => @as(i16, @intCast(sym.section)) + 1, // COFF uses 1-based section indices
            };
            _ = try coff.addSymbol(
                sym.name,
                @intCast(sym.offset),
                section,
                sym.global or sym.kind == .external,
                sym.kind == .func,
            );
        }

        // Ensure symbols exist for all relocations
        for (self.sections.items) |sec| {
            for (sec.relocations.items) |reloc| {
                _ = try coff.getOrCreateSymbol(reloc.symbol);
            }
        }

        // Write the COFF file
        try coff.write(writer);

        log.debug("writeCOFF: {d} sections, {d} symbols", .{
            self.sections.items.len,
            self.symbols.items.len,
        });
    }
};

// ============================================================================
// Tests
// ============================================================================

test "object file creation" {
    const allocator = std.testing.allocator;
    var obj = ObjectFile.init(allocator, .elf64);
    defer obj.deinit();

    const text_idx = try obj.addSection("__text", .text);
    try std.testing.expectEqual(@as(u16, 0), text_idx);

    const data_idx = try obj.addSection("__data", .data);
    try std.testing.expectEqual(@as(u16, 1), data_idx);
}

test "add symbol" {
    const allocator = std.testing.allocator;
    var obj = ObjectFile.init(allocator, .macho64);
    defer obj.deinit();

    const text_idx = try obj.addSection("__text", .text);

    const sym_idx = try obj.addSymbol(.{
        .name = "main",
        .kind = .func,
        .section = text_idx,
        .offset = 0,
        .size = 64,
        .global = true,
    });

    try std.testing.expectEqual(@as(u32, 0), sym_idx);
    try std.testing.expectEqual(@as(usize, 1), obj.symbols.items.len);
}

test "add code to section" {
    const allocator = std.testing.allocator;
    var obj = ObjectFile.init(allocator, .elf64);
    defer obj.deinit();

    const text_idx = try obj.addSection("__text", .text);

    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();

    // Some dummy code bytes
    try buf.emit8(0x55); // push rbp
    try buf.emit8(0x48);
    try buf.emit8(0x89);
    try buf.emit8(0xE5); // mov rbp, rsp
    try buf.emit8(0xC3); // ret

    try obj.addCode(text_idx, &buf);

    const sec = obj.getSection(text_idx);
    try std.testing.expectEqual(@as(u64, 5), sec.size());
}

test "write elf64 object file" {
    const allocator = std.testing.allocator;
    var obj = ObjectFile.init(allocator, .elf64);
    defer obj.deinit();

    const text_idx = try obj.addSection("__text", .text);

    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();
    try buf.emit8(0xC3); // ret

    try obj.addCode(text_idx, &buf);

    // Write to buffer
    var output: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
    defer output.deinit(allocator);

    try obj.write(output.writer(allocator));

    // Check ELF magic
    try std.testing.expectEqualSlices(u8, "\x7fELF", output.items[0..4]);
}

test "write macho64 object file" {
    const allocator = std.testing.allocator;
    var obj = ObjectFile.init(allocator, .macho64);
    defer obj.deinit();

    const text_idx = try obj.addSection("__text", .text);

    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();
    try buf.emit32(0xD65F03C0); // ret (ARM64)

    try obj.addCode(text_idx, &buf);

    // Write to buffer
    var output: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
    defer output.deinit(allocator);

    try obj.write(output.writer(allocator));

    // Check Mach-O magic (little-endian)
    const magic: u32 = @bitCast(output.items[0..4].*);
    try std.testing.expectEqual(@as(u32, 0xFEEDFACF), magic);
}

test "write coff object file" {
    const allocator = std.testing.allocator;
    var obj = ObjectFile.initWithArch(allocator, .coff, .x86_64);
    defer obj.deinit();

    const text_idx = try obj.addSection(".text", .text);

    var buf = CodeBuffer.init(allocator);
    defer buf.deinit();
    // x86_64: mov eax, 42; ret
    try buf.emit8(0xB8); // mov eax, imm32
    try buf.emit32(42);
    try buf.emit8(0xC3); // ret

    try obj.addCode(text_idx, &buf);

    // Add main symbol
    _ = try obj.addSymbol(.{
        .name = "main",
        .kind = .func,
        .section = text_idx,
        .offset = 0,
        .size = 6,
        .global = true,
    });

    // Write to buffer
    var output: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
    defer output.deinit(allocator);

    try obj.write(output.writer(allocator));

    // Check COFF machine type (0x8664 = AMD64, little-endian)
    try std.testing.expectEqual(@as(u8, 0x64), output.items[0]);
    try std.testing.expectEqual(@as(u8, 0x86), output.items[1]);
}
