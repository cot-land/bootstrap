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

const Allocator = std.mem.Allocator;
const CodeBuffer = be.CodeBuffer;
const Relocation = be.Relocation;
const RelocKind = be.RelocKind;

// Scoped logger for object file generation
const log = debug.scoped(.object);

// ============================================================================
// Object File Format
// ============================================================================

pub const ObjectFormat = enum {
    elf64,
    macho64,

    pub fn fromTarget(_: be.Arch, os: be.OS) ObjectFormat {
        return switch (os) {
            .linux => .elf64,
            .macos => .macho64,
            .windows => .elf64, // TODO: COFF support
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
    sections: std.ArrayList(Section),
    symbols: std.ArrayList(Symbol),

    /// String table for symbol names.
    strtab: std.ArrayList(u8),

    pub fn init(allocator: Allocator, format: ObjectFormat) ObjectFile {
        var obj = ObjectFile{
            .allocator = allocator,
            .format = format,
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
    pub fn applyLocalRelocations(self: *ObjectFile) void {
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
        // ELF64 header
        const ELF_MAGIC = "\x7fELF";
        const ELFCLASS64: u8 = 2;
        const ELFDATA2LSB: u8 = 1; // Little-endian
        const EV_CURRENT: u8 = 1;
        const ELFOSABI_NONE: u8 = 0;
        const ET_REL: u16 = 1; // Relocatable
        const EM_X86_64: u16 = 62;

        // ELF symbol table constants
        const STB_GLOBAL: u8 = 1;
        const STT_FUNC: u8 = 2;
        const STV_DEFAULT: u8 = 0;

        // Build symbol string table (strtab)
        var strtab: [1024]u8 = undefined;
        var strtab_len: u32 = 0;
        strtab[0] = 0; // Null byte at start
        strtab_len = 1;

        // Track symbol name offsets
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
        // Format: \0.text\0.symtab\0.strtab\0.shstrtab\0
        var shstrtab: [256]u8 = undefined;
        var shstrtab_len: u32 = 0;
        shstrtab[0] = 0; // Null byte at start
        shstrtab_len = 1;

        // Track name offsets for each section
        var section_name_offsets: [16]u32 = undefined;
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

        // Add .symtab name
        const symtab_name_offset = shstrtab_len;
        for (".symtab") |c| {
            shstrtab[shstrtab_len] = c;
            shstrtab_len += 1;
        }
        shstrtab[shstrtab_len] = 0;
        shstrtab_len += 1;

        // Add .strtab name
        const strtab_name_offset = shstrtab_len;
        for (".strtab") |c| {
            shstrtab[shstrtab_len] = c;
            shstrtab_len += 1;
        }
        shstrtab[shstrtab_len] = 0;
        shstrtab_len += 1;

        // Add .shstrtab name
        const shstrtab_name_offset = shstrtab_len;
        for (".shstrtab") |c| {
            shstrtab[shstrtab_len] = c;
            shstrtab_len += 1;
        }
        shstrtab[shstrtab_len] = 0;
        shstrtab_len += 1;

        // Calculate sizes
        const header_size: u64 = 64;
        var section_data_size: u64 = 0;
        for (self.sections.items) |sec| {
            section_data_size += sec.size();
        }

        // Symbol table: one null entry + one entry per symbol
        // Elf64_Sym is 24 bytes
        const sym_entry_size: u64 = 24;
        const num_syms: u64 = 1 + self.symbols.items.len; // null + symbols
        const symtab_size: u64 = num_syms * sym_entry_size;

        // Layout:
        // [header 64] [section data] [symtab] [strtab] [shstrtab]
        const symtab_offset = header_size + section_data_size;
        const strtab_offset_val = symtab_offset + symtab_size;
        const shstrtab_offset = strtab_offset_val + strtab_len;
        const sh_offset = shstrtab_offset + shstrtab_len;

        // Number of sections: null + our sections + symtab + strtab + shstrtab
        const num_sections: u16 = @intCast(self.sections.items.len + 4);
        const shstrtab_idx: u16 = num_sections - 1;
        const strtab_idx: u16 = num_sections - 2;

        // Write ELF header (64 bytes)
        try writer.writeAll(ELF_MAGIC);
        try writer.writeByte(ELFCLASS64);
        try writer.writeByte(ELFDATA2LSB);
        try writer.writeByte(EV_CURRENT);
        try writer.writeByte(ELFOSABI_NONE);
        try writer.writeByteNTimes(0, 8); // Padding

        try writer.writeInt(u16, ET_REL, .little); // e_type
        try writer.writeInt(u16, EM_X86_64, .little); // e_machine
        try writer.writeInt(u32, 1, .little); // e_version

        try writer.writeInt(u64, 0, .little); // e_entry (none for .o)
        try writer.writeInt(u64, 0, .little); // e_phoff (no program headers)
        try writer.writeInt(u64, sh_offset, .little); // e_shoff

        try writer.writeInt(u32, 0, .little); // e_flags
        try writer.writeInt(u16, 64, .little); // e_ehsize
        try writer.writeInt(u16, 0, .little); // e_phentsize
        try writer.writeInt(u16, 0, .little); // e_phnum
        try writer.writeInt(u16, 64, .little); // e_shentsize
        try writer.writeInt(u16, num_sections, .little); // e_shnum
        try writer.writeInt(u16, shstrtab_idx, .little); // e_shstrndx

        // Write section data
        for (self.sections.items) |sec| {
            try writer.writeAll(sec.data.items);
        }

        // Write symbol table
        // Null symbol entry (required first entry)
        try writer.writeByteNTimes(0, 24);

        // Write each symbol
        for (self.symbols.items, 0..) |sym, i| {
            // st_name: offset into strtab
            try writer.writeInt(u32, sym_name_offsets[i], .little);

            // st_info: type and binding
            const st_info: u8 = (STB_GLOBAL << 4) | STT_FUNC;
            try writer.writeByte(st_info);

            // st_other: visibility
            try writer.writeByte(STV_DEFAULT);

            // st_shndx: section index (1-based, our .text is section 1)
            try writer.writeInt(u16, sym.section + 1, .little);

            // st_value: symbol value/offset
            try writer.writeInt(u64, sym.offset, .little);

            // st_size: symbol size
            try writer.writeInt(u64, sym.size, .little);
        }

        // Write strtab data
        try writer.writeAll(strtab[0..strtab_len]);

        // Write shstrtab data
        try writer.writeAll(shstrtab[0..shstrtab_len]);

        // Write section headers
        // Null section header (required)
        try writer.writeByteNTimes(0, 64);

        // Our sections
        var data_offset: u64 = header_size;
        for (self.sections.items, 0..) |sec, i| {
            try self.writeELFSectionHeader(writer, sec, data_offset, section_name_offsets[i]);
            data_offset += sec.size();
        }

        // .symtab section header
        try writer.writeInt(u32, symtab_name_offset, .little); // sh_name
        try writer.writeInt(u32, 2, .little); // sh_type = SHT_SYMTAB
        try writer.writeInt(u64, 0, .little); // sh_flags
        try writer.writeInt(u64, 0, .little); // sh_addr
        try writer.writeInt(u64, symtab_offset, .little); // sh_offset
        try writer.writeInt(u64, symtab_size, .little); // sh_size
        try writer.writeInt(u32, strtab_idx, .little); // sh_link = strtab section index
        try writer.writeInt(u32, 1, .little); // sh_info = first global symbol index
        try writer.writeInt(u64, 8, .little); // sh_addralign
        try writer.writeInt(u64, sym_entry_size, .little); // sh_entsize

        // .strtab section header
        try writer.writeInt(u32, strtab_name_offset, .little); // sh_name
        try writer.writeInt(u32, 3, .little); // sh_type = SHT_STRTAB
        try writer.writeInt(u64, 0, .little); // sh_flags
        try writer.writeInt(u64, 0, .little); // sh_addr
        try writer.writeInt(u64, strtab_offset_val, .little); // sh_offset
        try writer.writeInt(u64, strtab_len, .little); // sh_size
        try writer.writeInt(u32, 0, .little); // sh_link
        try writer.writeInt(u32, 0, .little); // sh_info
        try writer.writeInt(u64, 1, .little); // sh_addralign
        try writer.writeInt(u64, 0, .little); // sh_entsize

        // .shstrtab section header
        try writer.writeInt(u32, shstrtab_name_offset, .little); // sh_name
        try writer.writeInt(u32, 3, .little); // sh_type = SHT_STRTAB
        try writer.writeInt(u64, 0, .little); // sh_flags
        try writer.writeInt(u64, 0, .little); // sh_addr
        try writer.writeInt(u64, shstrtab_offset, .little); // sh_offset
        try writer.writeInt(u64, shstrtab_len, .little); // sh_size
        try writer.writeInt(u32, 0, .little); // sh_link
        try writer.writeInt(u32, 0, .little); // sh_info
        try writer.writeInt(u64, 1, .little); // sh_addralign
        try writer.writeInt(u64, 0, .little); // sh_entsize
    }

    fn writeELFSectionHeader(self: *ObjectFile, writer: anytype, sec: Section, offset: u64, name_offset: u32) !void {
        _ = self;
        const SHT_PROGBITS: u32 = 1;
        const SHT_NOBITS: u32 = 8;

        const SHF_ALLOC: u64 = 0x2;
        const SHF_EXECINSTR: u64 = 0x4;
        const SHF_WRITE: u64 = 0x1;

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

        try writer.writeInt(u32, name_offset, .little); // sh_name
        try writer.writeInt(u32, sh_type, .little);
        try writer.writeInt(u64, sh_flags, .little);
        try writer.writeInt(u64, 0, .little); // sh_addr
        try writer.writeInt(u64, offset, .little);
        try writer.writeInt(u64, sec.size(), .little);
        try writer.writeInt(u32, 0, .little); // sh_link
        try writer.writeInt(u32, 0, .little); // sh_info
        try writer.writeInt(u64, sec.alignment, .little);
        try writer.writeInt(u64, 0, .little); // sh_entsize
    }

    // ========================================================================
    // Mach-O 64 Writer
    // ========================================================================

    fn writeMachO64(self: *ObjectFile, writer: anytype) !void {
        // Mach-O constants
        const MH_MAGIC_64: u32 = 0xFEEDFACF;
        const CPU_TYPE_ARM64: u32 = 0x0100000C;
        const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
        const MH_OBJECT: u32 = 1;

        const LC_SEGMENT_64: u32 = 0x19;
        const LC_SYMTAB: u32 = 0x02;

        // Calculate sizes
        const header_size: u32 = 32;
        const segment_cmd_size: u32 = 72;
        const section_size: u32 = 80;
        const symtab_cmd_size: u32 = 24;

        const num_sections: u32 = @intCast(self.sections.items.len);
        const load_cmds_size = segment_cmd_size + (num_sections * section_size) + symtab_cmd_size;

        var section_data_size: u64 = 0;
        for (self.sections.items) |sec| {
            section_data_size += sec.size();
        }

        // Mach-O header (32 bytes for 64-bit)
        try writer.writeInt(u32, MH_MAGIC_64, .little);
        try writer.writeInt(u32, CPU_TYPE_ARM64, .little);
        try writer.writeInt(u32, CPU_SUBTYPE_ARM64_ALL, .little);
        try writer.writeInt(u32, MH_OBJECT, .little);
        try writer.writeInt(u32, 2, .little); // ncmds (segment + symtab)
        try writer.writeInt(u32, load_cmds_size, .little); // sizeofcmds
        try writer.writeInt(u32, 0, .little); // flags
        try writer.writeInt(u32, 0, .little); // reserved

        // LC_SEGMENT_64 command
        try writer.writeInt(u32, LC_SEGMENT_64, .little);
        try writer.writeInt(u32, segment_cmd_size + (num_sections * section_size), .little);
        try writer.writeByteNTimes(0, 16); // segname (empty for object files)
        try writer.writeInt(u64, 0, .little); // vmaddr
        try writer.writeInt(u64, section_data_size, .little); // vmsize
        try writer.writeInt(u64, header_size + load_cmds_size, .little); // fileoff
        try writer.writeInt(u64, section_data_size, .little); // filesize
        try writer.writeInt(u32, 0x7, .little); // maxprot (rwx)
        try writer.writeInt(u32, 0x7, .little); // initprot
        try writer.writeInt(u32, num_sections, .little); // nsects
        try writer.writeInt(u32, 0, .little); // flags

        // Section headers
        var file_offset: u64 = header_size + load_cmds_size;
        for (self.sections.items) |sec| {
            try self.writeMachOSection(writer, sec, file_offset);
            file_offset += sec.size();
        }

        // Calculate symbol table and string table positions
        const symtab_offset: u32 = @intCast(file_offset); // After section data
        const nsyms: u32 = @intCast(self.symbols.items.len);
        const nlist_size: u32 = 16; // nlist_64 is 16 bytes
        const strtab_offset: u32 = symtab_offset + (nsyms * nlist_size);

        // Build string table
        var strtab_size: u32 = 1; // Start with null byte
        for (self.symbols.items) |sym| {
            strtab_size += @intCast(sym.name.len + 1);
        }

        // LC_SYMTAB command
        try writer.writeInt(u32, LC_SYMTAB, .little);
        try writer.writeInt(u32, symtab_cmd_size, .little);
        try writer.writeInt(u32, symtab_offset, .little); // symoff
        try writer.writeInt(u32, nsyms, .little); // nsyms
        try writer.writeInt(u32, strtab_offset, .little); // stroff
        try writer.writeInt(u32, strtab_size, .little); // strsize

        // Write section data
        for (self.sections.items) |sec| {
            try writer.writeAll(sec.data.items);
        }

        // Write symbol table (nlist_64 entries)
        const N_EXT: u8 = 0x01; // External symbol
        const N_SECT: u8 = 0x0e; // Symbol defined in section

        var str_offset: u32 = 1; // Skip initial null
        for (self.symbols.items) |sym| {
            // nlist_64: n_strx (4), n_type (1), n_sect (1), n_desc (2), n_value (8)
            try writer.writeInt(u32, str_offset, .little); // n_strx
            try writer.writeInt(u8, N_SECT | N_EXT, .little); // n_type (external, in section)
            try writer.writeInt(u8, @intCast(sym.section + 1), .little); // n_sect (1-indexed)
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
    }

    fn writeMachOSection(self: *ObjectFile, writer: anytype, sec: Section, file_offset: u64) !void {
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
        try writer.writeInt(u32, 0, .little); // reloff
        try writer.writeInt(u32, 0, .little); // nreloc
        try writer.writeInt(u32, sec_type | sec_attrs, .little); // flags
        try writer.writeInt(u32, 0, .little); // reserved1
        try writer.writeInt(u32, 0, .little); // reserved2
        try writer.writeInt(u32, 0, .little); // reserved3 (64-bit only)
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
