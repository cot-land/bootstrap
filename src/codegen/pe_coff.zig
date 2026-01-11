///! PE/COFF Object File Generation for Windows.
///!
///! This module implements COFF (Common Object File Format) generation
///! for Windows x86_64 targets. COFF is the object file format used by
///! Microsoft's toolchain (MSVC, link.exe).
///!
///! Key structures:
///! - COFF Header (20 bytes): Machine type, section count, timestamps
///! - Section Headers (40 bytes each): Name, size, relocations
///! - Symbol Table (18 bytes per symbol): Name, value, section, type
///! - String Table: For symbol names > 8 characters
///!
///! References:
///! - Microsoft PE/COFF Specification
///! - Go: cmd/link/internal/loadpe
///! - Zig: std/coff.zig

const std = @import("std");
const be = @import("backend.zig");
const debug = @import("../debug.zig");

const Allocator = std.mem.Allocator;
const Relocation = be.Relocation;
const RelocKind = be.RelocKind;

// Scoped logger for PE/COFF generation
const log = debug.scoped(.pe_coff);

// ============================================================================
// COFF Constants
// ============================================================================

/// COFF machine types
pub const MachineType = enum(u16) {
    IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
    IMAGE_FILE_MACHINE_AMD64 = 0x8664, // x86-64
    IMAGE_FILE_MACHINE_I386 = 0x14c, // x86
    IMAGE_FILE_MACHINE_ARM64 = 0xAA64, // ARM64 (Windows on ARM)
};

/// COFF header characteristics flags
pub const Characteristics = struct {
    pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
    pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
    pub const IMAGE_FILE_LINE_NUMS_STRIPPED: u16 = 0x0004;
    pub const IMAGE_FILE_LOCAL_SYMS_STRIPPED: u16 = 0x0008;
    pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
    pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
    pub const IMAGE_FILE_DEBUG_STRIPPED: u16 = 0x0200;
};

/// COFF section flags
pub const SectionFlags = struct {
    pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
    pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
    pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
    pub const IMAGE_SCN_LNK_INFO: u32 = 0x00000200;
    pub const IMAGE_SCN_LNK_REMOVE: u32 = 0x00000800;
    pub const IMAGE_SCN_LNK_COMDAT: u32 = 0x00001000;
    pub const IMAGE_SCN_ALIGN_1BYTES: u32 = 0x00100000;
    pub const IMAGE_SCN_ALIGN_2BYTES: u32 = 0x00200000;
    pub const IMAGE_SCN_ALIGN_4BYTES: u32 = 0x00300000;
    pub const IMAGE_SCN_ALIGN_8BYTES: u32 = 0x00400000;
    pub const IMAGE_SCN_ALIGN_16BYTES: u32 = 0x00500000;
    pub const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x01000000;
    pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x02000000;
    pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x04000000;
    pub const IMAGE_SCN_MEM_NOT_PAGED: u32 = 0x08000000;
    pub const IMAGE_SCN_MEM_SHARED: u32 = 0x10000000;
    pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
    pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
    pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
};

/// COFF symbol storage class
pub const StorageClass = enum(u8) {
    IMAGE_SYM_CLASS_NULL = 0,
    IMAGE_SYM_CLASS_EXTERNAL = 2, // External symbol
    IMAGE_SYM_CLASS_STATIC = 3, // Static symbol (local)
    IMAGE_SYM_CLASS_FUNCTION = 101, // Function definition
    IMAGE_SYM_CLASS_FILE = 103, // Source file name
    IMAGE_SYM_CLASS_SECTION = 104, // Section
    IMAGE_SYM_CLASS_LABEL = 6, // Label (for jumps)
};

/// COFF symbol type
pub const SymbolType = struct {
    pub const IMAGE_SYM_TYPE_NULL: u16 = 0;
    pub const IMAGE_SYM_DTYPE_NULL: u16 = 0;
    pub const IMAGE_SYM_DTYPE_FUNCTION: u16 = 0x20; // Function (shifted left 4)
};

/// Special section numbers for symbols
pub const SectionNumber = struct {
    pub const IMAGE_SYM_UNDEFINED: i16 = 0; // External, undefined
    pub const IMAGE_SYM_ABSOLUTE: i16 = -1; // Absolute value
    pub const IMAGE_SYM_DEBUG: i16 = -2; // Debug info
};

// ============================================================================
// COFF x86_64 Relocation Types
// ============================================================================

/// x86_64 COFF relocation types (IMAGE_REL_AMD64_*)
pub const CoffRelocAMD64 = enum(u16) {
    IMAGE_REL_AMD64_ABSOLUTE = 0x0000, // Reference is absolute, no relocation
    IMAGE_REL_AMD64_ADDR64 = 0x0001, // 64-bit address (VA)
    IMAGE_REL_AMD64_ADDR32 = 0x0002, // 32-bit address (VA)
    IMAGE_REL_AMD64_ADDR32NB = 0x0003, // 32-bit address w/o base (RVA)
    IMAGE_REL_AMD64_REL32 = 0x0004, // 32-bit relative address from byte after reloc
    IMAGE_REL_AMD64_REL32_1 = 0x0005, // 32-bit relative address from byte distance 1
    IMAGE_REL_AMD64_REL32_2 = 0x0006, // 32-bit relative address from byte distance 2
    IMAGE_REL_AMD64_REL32_3 = 0x0007, // 32-bit relative address from byte distance 3
    IMAGE_REL_AMD64_REL32_4 = 0x0008, // 32-bit relative address from byte distance 4
    IMAGE_REL_AMD64_REL32_5 = 0x0009, // 32-bit relative address from byte distance 5
    IMAGE_REL_AMD64_SECTION = 0x000A, // Section index
    IMAGE_REL_AMD64_SECREL = 0x000B, // 32-bit offset from base of section
    IMAGE_REL_AMD64_SECREL7 = 0x000C, // 7-bit unsigned offset from base of section
    IMAGE_REL_AMD64_TOKEN = 0x000D, // CLR token
    IMAGE_REL_AMD64_SREL32 = 0x000E, // 32-bit span-dependent value emitted
    IMAGE_REL_AMD64_PAIR = 0x000F, // Must follow span-dependent
    IMAGE_REL_AMD64_SSPAN32 = 0x0010, // 32-bit signed span-dependent value
};

/// Convert internal relocation kind to COFF AMD64 relocation type
pub fn relocKindToCoffAMD64(kind: RelocKind) CoffRelocAMD64 {
    return switch (kind) {
        .pc_rel_32 => .IMAGE_REL_AMD64_REL32,
        .abs_64 => .IMAGE_REL_AMD64_ADDR64,
        .got_rel => .IMAGE_REL_AMD64_REL32, // GOT not used same way on Windows
        .plt_rel => .IMAGE_REL_AMD64_REL32, // PLT not used on Windows
        .aarch64_adrp, .aarch64_add_lo12 => .IMAGE_REL_AMD64_REL32, // Fallback
    };
}

// ============================================================================
// COFF Header (20 bytes)
// ============================================================================

pub const CoffHeader = struct {
    machine: MachineType = .IMAGE_FILE_MACHINE_AMD64,
    number_of_sections: u16 = 0,
    time_date_stamp: u32 = 0,
    pointer_to_symbol_table: u32 = 0,
    number_of_symbols: u32 = 0,
    size_of_optional_header: u16 = 0, // 0 for object files
    characteristics: u16 = 0,

    pub const SIZE: u32 = 20;

    pub fn write(self: CoffHeader, writer: anytype) !void {
        try writer.writeInt(u16, @intFromEnum(self.machine), .little);
        try writer.writeInt(u16, self.number_of_sections, .little);
        try writer.writeInt(u32, self.time_date_stamp, .little);
        try writer.writeInt(u32, self.pointer_to_symbol_table, .little);
        try writer.writeInt(u32, self.number_of_symbols, .little);
        try writer.writeInt(u16, self.size_of_optional_header, .little);
        try writer.writeInt(u16, self.characteristics, .little);
    }
};

// ============================================================================
// COFF Section Header (40 bytes)
// ============================================================================

pub const CoffSectionHeader = struct {
    name: [8]u8 = .{0} ** 8, // Section name (8 bytes, null-padded or /offset)
    virtual_size: u32 = 0, // Size in memory (0 for object files)
    virtual_address: u32 = 0, // Address in memory (0 for object files)
    size_of_raw_data: u32 = 0, // Size of section data
    pointer_to_raw_data: u32 = 0, // File offset to section data
    pointer_to_relocations: u32 = 0, // File offset to relocations
    pointer_to_linenumbers: u32 = 0, // File offset to line numbers (deprecated)
    number_of_relocations: u16 = 0, // Number of relocations
    number_of_linenumbers: u16 = 0, // Number of line numbers (deprecated)
    characteristics: u32 = 0, // Section flags

    pub const SIZE: u32 = 40;

    /// Set section name. For names > 8 chars, use string table offset (/N format)
    pub fn setName(self: *CoffSectionHeader, name: []const u8) void {
        const copy_len = @min(name.len, 8);
        @memcpy(self.name[0..copy_len], name[0..copy_len]);
    }

    /// Set name using string table offset (for names > 8 chars)
    pub fn setNameFromOffset(self: *CoffSectionHeader, offset: u32) void {
        // Format: "/" followed by ASCII decimal offset
        self.name[0] = '/';
        var buf: [7]u8 = undefined;
        const str = std.fmt.bufPrint(&buf, "{d}", .{offset}) catch return;
        @memcpy(self.name[1 .. 1 + str.len], str);
    }

    pub fn write(self: CoffSectionHeader, writer: anytype) !void {
        try writer.writeAll(&self.name);
        try writer.writeInt(u32, self.virtual_size, .little);
        try writer.writeInt(u32, self.virtual_address, .little);
        try writer.writeInt(u32, self.size_of_raw_data, .little);
        try writer.writeInt(u32, self.pointer_to_raw_data, .little);
        try writer.writeInt(u32, self.pointer_to_relocations, .little);
        try writer.writeInt(u32, self.pointer_to_linenumbers, .little);
        try writer.writeInt(u16, self.number_of_relocations, .little);
        try writer.writeInt(u16, self.number_of_linenumbers, .little);
        try writer.writeInt(u32, self.characteristics, .little);
    }
};

// ============================================================================
// COFF Symbol Table Entry (18 bytes)
// ============================================================================

pub const CoffSymbol = struct {
    /// Symbol name (8 bytes) or string table reference
    /// If first 4 bytes are 0, bytes 4-7 are string table offset
    name: [8]u8 = .{0} ** 8,
    value: u32 = 0, // Symbol value (offset within section)
    section_number: i16 = 0, // Section index (1-based) or special value
    symbol_type: u16 = 0, // Type (0 for most symbols)
    storage_class: StorageClass = .IMAGE_SYM_CLASS_NULL,
    number_of_aux_symbols: u8 = 0, // Auxiliary symbol records following

    pub const SIZE: u32 = 18;

    /// Set symbol name. For names > 8 chars, use setNameFromOffset
    pub fn setName(self: *CoffSymbol, name: []const u8) void {
        const copy_len = @min(name.len, 8);
        @memcpy(self.name[0..copy_len], name[0..copy_len]);
    }

    /// Set name using string table offset (for names > 8 chars)
    pub fn setNameFromOffset(self: *CoffSymbol, offset: u32) void {
        // First 4 bytes = 0 indicates string table reference
        self.name[0] = 0;
        self.name[1] = 0;
        self.name[2] = 0;
        self.name[3] = 0;
        // Bytes 4-7 = offset into string table (little-endian)
        self.name[4] = @truncate(offset);
        self.name[5] = @truncate(offset >> 8);
        self.name[6] = @truncate(offset >> 16);
        self.name[7] = @truncate(offset >> 24);
    }

    pub fn write(self: CoffSymbol, writer: anytype) !void {
        try writer.writeAll(&self.name);
        try writer.writeInt(u32, self.value, .little);
        try writer.writeInt(i16, self.section_number, .little);
        try writer.writeInt(u16, self.symbol_type, .little);
        try writer.writeByte(@intFromEnum(self.storage_class));
        try writer.writeByte(self.number_of_aux_symbols);
    }
};

// ============================================================================
// COFF Relocation Entry (10 bytes)
// ============================================================================

pub const CoffRelocation = struct {
    virtual_address: u32 = 0, // Offset within section
    symbol_table_index: u32 = 0, // Index into symbol table
    reloc_type: u16 = 0, // Relocation type

    pub const SIZE: u32 = 10;

    pub fn write(self: CoffRelocation, writer: anytype) !void {
        try writer.writeInt(u32, self.virtual_address, .little);
        try writer.writeInt(u32, self.symbol_table_index, .little);
        try writer.writeInt(u16, self.reloc_type, .little);
    }
};

// ============================================================================
// COFF Object File Writer
// ============================================================================

/// COFF object file writer context
pub const CoffWriter = struct {
    allocator: Allocator,
    arch: be.Arch,

    /// Sections to write
    sections: std.ArrayList(CoffSectionData),

    /// Symbols
    symbols: std.ArrayList(CoffSymbolData),

    /// String table (for names > 8 chars)
    strtab: std.ArrayList(u8),

    pub const CoffSectionData = struct {
        header: CoffSectionHeader,
        data: []const u8,
        relocations: []const Relocation,
    };

    pub const CoffSymbolData = struct {
        name: []const u8,
        value: u32,
        section: i16, // 1-based, or special value
        is_external: bool,
        is_function: bool,
    };

    pub fn init(allocator: Allocator, arch: be.Arch) CoffWriter {
        var writer = CoffWriter{
            .allocator = allocator,
            .arch = arch,
            .sections = .{ .items = &.{}, .capacity = 0 },
            .symbols = .{ .items = &.{}, .capacity = 0 },
            .strtab = .{ .items = &.{}, .capacity = 0 },
        };

        // String table starts with 4-byte size (filled later)
        // The first 4 bytes are reserved for the table size
        writer.strtab.appendSlice(allocator, &.{ 0, 0, 0, 0 }) catch {};

        return writer;
    }

    pub fn deinit(self: *CoffWriter) void {
        self.sections.deinit(self.allocator);
        self.symbols.deinit(self.allocator);
        self.strtab.deinit(self.allocator);
    }

    /// Add a string to the string table, return offset
    pub fn addString(self: *CoffWriter, str: []const u8) !u32 {
        const offset: u32 = @intCast(self.strtab.items.len);
        try self.strtab.appendSlice(self.allocator, str);
        try self.strtab.append(self.allocator, 0); // Null terminator
        return offset;
    }

    /// Add a section
    pub fn addSection(
        self: *CoffWriter,
        name: []const u8,
        data: []const u8,
        relocations: []const Relocation,
        is_code: bool,
    ) !u16 {
        var header = CoffSectionHeader{};

        // Set section name
        if (name.len <= 8) {
            header.setName(name);
        } else {
            const offset = try self.addString(name);
            header.setNameFromOffset(offset);
        }

        // Set characteristics based on section type
        if (is_code) {
            header.characteristics = SectionFlags.IMAGE_SCN_CNT_CODE |
                SectionFlags.IMAGE_SCN_ALIGN_16BYTES |
                SectionFlags.IMAGE_SCN_MEM_EXECUTE |
                SectionFlags.IMAGE_SCN_MEM_READ;
        } else {
            header.characteristics = SectionFlags.IMAGE_SCN_CNT_INITIALIZED_DATA |
                SectionFlags.IMAGE_SCN_ALIGN_8BYTES |
                SectionFlags.IMAGE_SCN_MEM_READ |
                SectionFlags.IMAGE_SCN_MEM_WRITE;
        }

        header.size_of_raw_data = @intCast(data.len);
        header.number_of_relocations = @intCast(relocations.len);

        const idx: u16 = @intCast(self.sections.items.len);
        try self.sections.append(self.allocator, .{
            .header = header,
            .data = data,
            .relocations = relocations,
        });

        log.debug("addSection: {s} ({d} bytes, {d} relocs)", .{
            name,
            data.len,
            relocations.len,
        });

        return idx;
    }

    /// Add a symbol
    pub fn addSymbol(
        self: *CoffWriter,
        name: []const u8,
        value: u32,
        section: i16,
        is_external: bool,
        is_function: bool,
    ) !u32 {
        const idx: u32 = @intCast(self.symbols.items.len);
        try self.symbols.append(self.allocator, .{
            .name = name,
            .value = value,
            .section = section,
            .is_external = is_external,
            .is_function = is_function,
        });

        log.debug("addSymbol: {s} (value={d}, section={d}, external={}, func={})", .{
            name,
            value,
            section,
            is_external,
            is_function,
        });

        return idx;
    }

    /// Find symbol index by name
    pub fn findSymbol(self: *const CoffWriter, name: []const u8) ?u32 {
        for (self.symbols.items, 0..) |sym, i| {
            if (std.mem.eql(u8, sym.name, name)) {
                return @intCast(i);
            }
        }
        return null;
    }

    /// Get or create symbol for relocation target
    pub fn getOrCreateSymbol(self: *CoffWriter, name: []const u8) !u32 {
        if (self.findSymbol(name)) |idx| {
            return idx;
        }
        // Create as undefined external
        return self.addSymbol(name, 0, SectionNumber.IMAGE_SYM_UNDEFINED, true, false);
    }

    /// Write COFF object file
    pub fn write(self: *CoffWriter, writer: anytype) !void {
        const num_sections: u16 = @intCast(self.sections.items.len);

        // Calculate layout
        // [COFF Header 20] [Section Headers 40*N] [Section Data...] [Relocations...] [Symbols...] [String Table]

        var offset: u32 = CoffHeader.SIZE + (num_sections * CoffSectionHeader.SIZE);

        // Calculate section data offsets
        var section_data_offsets: [16]u32 = undefined;
        for (self.sections.items, 0..) |sec, i| {
            section_data_offsets[i] = offset;
            offset += @intCast(sec.data.len);
        }

        // Calculate relocation offsets
        var section_reloc_offsets: [16]u32 = undefined;
        for (self.sections.items, 0..) |sec, i| {
            if (sec.relocations.len > 0) {
                section_reloc_offsets[i] = offset;
                offset += @intCast(sec.relocations.len * CoffRelocation.SIZE);
            } else {
                section_reloc_offsets[i] = 0;
            }
        }

        // Symbol table offset
        const symtab_offset: u32 = offset;
        const num_symbols: u32 = @intCast(self.symbols.items.len);

        // First pass: add all long symbol names to string table BEFORE writing
        // This must happen before we finalize the string table size
        var symbol_str_offsets: [256]u32 = undefined;
        for (self.symbols.items, 0..) |sym, i| {
            if (sym.name.len > 8) {
                symbol_str_offsets[i] = try self.addString(sym.name);
            } else {
                symbol_str_offsets[i] = 0;
            }
        }

        // Now update string table size (first 4 bytes)
        const strtab_size: u32 = @intCast(self.strtab.items.len);
        self.strtab.items[0] = @truncate(strtab_size);
        self.strtab.items[1] = @truncate(strtab_size >> 8);
        self.strtab.items[2] = @truncate(strtab_size >> 16);
        self.strtab.items[3] = @truncate(strtab_size >> 24);

        // Write COFF header
        const header = CoffHeader{
            .machine = if (self.arch == .x86_64) .IMAGE_FILE_MACHINE_AMD64 else .IMAGE_FILE_MACHINE_ARM64,
            .number_of_sections = num_sections,
            .time_date_stamp = 0, // Reproducible builds
            .pointer_to_symbol_table = if (num_symbols > 0) symtab_offset else 0,
            .number_of_symbols = num_symbols,
            .size_of_optional_header = 0, // Object file, no optional header
            .characteristics = 0,
        };
        try header.write(writer);

        // Write section headers
        for (self.sections.items, 0..) |*sec, i| {
            sec.header.pointer_to_raw_data = section_data_offsets[i];
            sec.header.pointer_to_relocations = section_reloc_offsets[i];
            try sec.header.write(writer);
        }

        // Write section data
        for (self.sections.items) |sec| {
            try writer.writeAll(sec.data);
        }

        // Write relocations
        for (self.sections.items) |sec| {
            for (sec.relocations) |reloc| {
                const sym_idx = self.findSymbol(reloc.symbol) orelse blk: {
                    // Symbol not found - this shouldn't happen if symbols are added correctly
                    log.debug("Warning: relocation symbol not found: {s}", .{reloc.symbol});
                    break :blk 0;
                };

                const coff_reloc = CoffRelocation{
                    .virtual_address = reloc.offset,
                    .symbol_table_index = sym_idx,
                    .reloc_type = @intFromEnum(relocKindToCoffAMD64(reloc.kind)),
                };
                try coff_reloc.write(writer);
            }
        }

        // Write symbol table (using pre-computed string offsets)
        for (self.symbols.items, 0..) |sym, i| {
            var coff_sym = CoffSymbol{
                .value = sym.value,
                .section_number = sym.section,
                .symbol_type = if (sym.is_function) SymbolType.IMAGE_SYM_DTYPE_FUNCTION else SymbolType.IMAGE_SYM_TYPE_NULL,
                .storage_class = if (sym.is_external) .IMAGE_SYM_CLASS_EXTERNAL else .IMAGE_SYM_CLASS_STATIC,
                .number_of_aux_symbols = 0,
            };

            if (sym.name.len <= 8) {
                coff_sym.setName(sym.name);
            } else {
                coff_sym.setNameFromOffset(symbol_str_offsets[i]);
            }

            try coff_sym.write(writer);
        }

        // Write string table
        try writer.writeAll(self.strtab.items);

        log.debug("writeCOFF: {d} sections, {d} symbols, strtab={d} bytes", .{
            num_sections,
            num_symbols,
            strtab_size,
        });
    }
};

// ============================================================================
// Helper Functions for Integration
// ============================================================================

/// Get COFF section name for a given section kind
pub fn getCoffSectionName(kind: @import("object.zig").SectionKind) []const u8 {
    return switch (kind) {
        .text => ".text",
        .data => ".data",
        .rodata => ".rdata", // Windows uses .rdata for read-only data
        .bss => ".bss",
    };
}

/// Get COFF section flags for a given section kind
pub fn getCoffSectionFlags(kind: @import("object.zig").SectionKind) u32 {
    return switch (kind) {
        .text => SectionFlags.IMAGE_SCN_CNT_CODE |
            SectionFlags.IMAGE_SCN_ALIGN_16BYTES |
            SectionFlags.IMAGE_SCN_MEM_EXECUTE |
            SectionFlags.IMAGE_SCN_MEM_READ,
        .data => SectionFlags.IMAGE_SCN_CNT_INITIALIZED_DATA |
            SectionFlags.IMAGE_SCN_ALIGN_8BYTES |
            SectionFlags.IMAGE_SCN_MEM_READ |
            SectionFlags.IMAGE_SCN_MEM_WRITE,
        .rodata => SectionFlags.IMAGE_SCN_CNT_INITIALIZED_DATA |
            SectionFlags.IMAGE_SCN_ALIGN_8BYTES |
            SectionFlags.IMAGE_SCN_MEM_READ,
        .bss => SectionFlags.IMAGE_SCN_CNT_UNINITIALIZED_DATA |
            SectionFlags.IMAGE_SCN_ALIGN_8BYTES |
            SectionFlags.IMAGE_SCN_MEM_READ |
            SectionFlags.IMAGE_SCN_MEM_WRITE,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "COFF header write" {
    const allocator = std.testing.allocator;

    var output: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
    defer output.deinit(allocator);

    const header = CoffHeader{
        .machine = .IMAGE_FILE_MACHINE_AMD64,
        .number_of_sections = 1,
        .time_date_stamp = 0,
        .pointer_to_symbol_table = 100,
        .number_of_symbols = 2,
        .size_of_optional_header = 0,
        .characteristics = 0,
    };

    try header.write(output.writer(allocator));

    try std.testing.expectEqual(@as(usize, 20), output.items.len);
    // Check machine type (0x8664 = AMD64, little-endian)
    try std.testing.expectEqual(@as(u8, 0x64), output.items[0]);
    try std.testing.expectEqual(@as(u8, 0x86), output.items[1]);
}

test "COFF section header write" {
    const allocator = std.testing.allocator;

    var output: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
    defer output.deinit(allocator);

    var header = CoffSectionHeader{};
    header.setName(".text");
    header.size_of_raw_data = 64;
    header.characteristics = SectionFlags.IMAGE_SCN_CNT_CODE | SectionFlags.IMAGE_SCN_MEM_EXECUTE;

    try header.write(output.writer(allocator));

    try std.testing.expectEqual(@as(usize, 40), output.items.len);
    // Check name starts with ".text"
    try std.testing.expectEqualSlices(u8, ".text", output.items[0..5]);
}

test "COFF symbol write" {
    const allocator = std.testing.allocator;

    var output: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
    defer output.deinit(allocator);

    var sym = CoffSymbol{
        .value = 0,
        .section_number = 1,
        .symbol_type = SymbolType.IMAGE_SYM_DTYPE_FUNCTION,
        .storage_class = .IMAGE_SYM_CLASS_EXTERNAL,
        .number_of_aux_symbols = 0,
    };
    sym.setName("main");

    try sym.write(output.writer(allocator));

    try std.testing.expectEqual(@as(usize, 18), output.items.len);
    // Check name starts with "main"
    try std.testing.expectEqualSlices(u8, "main", output.items[0..4]);
}

test "COFF relocation write" {
    const allocator = std.testing.allocator;

    var output: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
    defer output.deinit(allocator);

    const reloc = CoffRelocation{
        .virtual_address = 10,
        .symbol_table_index = 1,
        .reloc_type = @intFromEnum(CoffRelocAMD64.IMAGE_REL_AMD64_REL32),
    };

    try reloc.write(output.writer(allocator));

    try std.testing.expectEqual(@as(usize, 10), output.items.len);
}

test "COFF writer basic" {
    const allocator = std.testing.allocator;

    var coff = CoffWriter.init(allocator, .x86_64);
    defer coff.deinit();

    // Add a .text section with some dummy code
    const code = [_]u8{
        0x48, 0x89, 0xE5, // mov rbp, rsp
        0xB8, 0x2A, 0x00, 0x00, 0x00, // mov eax, 42
        0xC3, // ret
    };
    _ = try coff.addSection(".text", &code, &.{}, true);

    // Add a symbol
    _ = try coff.addSymbol("main", 0, 1, true, true);

    // Write to buffer
    var output: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
    defer output.deinit(allocator);

    try coff.write(output.writer(allocator));

    // Verify minimum size (header + section header + code + symbol + strtab)
    try std.testing.expect(output.items.len >= 20 + 40 + 9 + 18 + 4);

    // Check COFF header machine type
    try std.testing.expectEqual(@as(u8, 0x64), output.items[0]);
    try std.testing.expectEqual(@as(u8, 0x86), output.items[1]);
}

test "relocation kind to COFF" {
    try std.testing.expectEqual(CoffRelocAMD64.IMAGE_REL_AMD64_REL32, relocKindToCoffAMD64(.pc_rel_32));
    try std.testing.expectEqual(CoffRelocAMD64.IMAGE_REL_AMD64_ADDR64, relocKindToCoffAMD64(.abs_64));
}
