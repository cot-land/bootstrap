# Stage 7: Linking

**Files:** `src/codegen/object.zig`, `src/driver.zig`

**Purpose:** Package machine code into an executable file

---

## What is Linking?

Code generation produced raw machine code bytes. But that's not enough to run a program. We need to:

1. **Package the code** in a format the operating system understands
2. **Resolve references** to external functions (like `print`)
3. **Combine with runtime** (startup code, library functions)
4. **Create an executable** file the OS can load and run

```
Code Buffer:                      Executable:
+------------------+              +------------------+
| mov x0, #42      |              | Header (metadata)|
| bl _print        | ─────────>   +------------------+
| ret              |              | .text (code)     |
+------------------+              +------------------+
                                  | .rodata (strings)|
                                  +------------------+
                                  | Symbol table     |
                                  +------------------+
```

---

## Object File Formats

Different operating systems use different formats:

| OS | Format | Description |
|----|--------|-------------|
| macOS | **Mach-O** | Apple's format, used on macOS and iOS |
| Linux | **ELF** | Executable and Linkable Format |
| Windows | **PE/COFF** | Portable Executable |

Cot generates object files (`.o` files), then uses the system linker to create the final executable.

---

## Mach-O Structure (macOS)

A Mach-O file has three parts:

```
+------------------------+
|     Header             |  <- Magic number, architecture, load commands count
+------------------------+
|   Load Commands        |  <- Describe segments, symbols, etc.
|   - LC_SEGMENT_64      |
|   - LC_SYMTAB          |
|   - LC_DYSYMTAB        |
+------------------------+
|   Segment Data         |
|   - __TEXT segment     |  <- Code (.text section)
|   - __DATA segment     |  <- Writable data
+------------------------+
|   Symbol Table         |  <- Names and addresses
+------------------------+
|   String Table         |  <- Symbol name strings
+------------------------+
|   Relocations          |  <- Patches for the linker
+------------------------+
```

### Key Structures

```zig
/// Mach-O header (32 bytes for 64-bit)
const MachHeader64 = packed struct {
    magic: u32,          // 0xFEEDFACF for 64-bit
    cputype: i32,        // CPU_TYPE_ARM64 or CPU_TYPE_X86_64
    cpusubtype: i32,     // CPU_SUBTYPE_ARM64_ALL etc.
    filetype: u32,       // MH_OBJECT (1) for .o files
    ncmds: u32,          // Number of load commands
    sizeofcmds: u32,     // Total size of load commands
    flags: u32,          // Flags
    reserved: u32,       // Reserved (64-bit only)
};
```

### Sections

Code and data go into **sections** within **segments**:

| Segment | Section | Contents |
|---------|---------|----------|
| `__TEXT` | `__text` | Executable code |
| `__TEXT` | `__cstring` | C strings (null-terminated) |
| `__DATA` | `__data` | Writable global data |
| `__DATA` | `__const` | Read-only constants |

---

## ELF Structure (Linux)

```
+------------------------+
|     ELF Header         |  <- Magic, architecture, entry point
+------------------------+
|   Program Headers      |  <- How to load into memory
+------------------------+
|   Section Headers      |  <- Describe each section
+------------------------+
|   Sections             |
|   - .text              |  <- Code
|   - .rodata            |  <- Read-only data
|   - .data              |  <- Writable data
|   - .symtab            |  <- Symbol table
|   - .strtab            |  <- String table
|   - .rela.text         |  <- Relocations for .text
+------------------------+
```

### Key Structures

```zig
/// ELF64 header (64 bytes)
const Elf64Header = packed struct {
    e_ident: [16]u8,     // Magic "\x7FELF", class, endian, etc.
    e_type: u16,         // ET_REL (1) for .o files
    e_machine: u16,      // EM_X86_64 or EM_AARCH64
    e_version: u32,      // EV_CURRENT (1)
    e_entry: u64,        // Entry point (0 for .o files)
    e_phoff: u64,        // Program header offset
    e_shoff: u64,        // Section header offset
    e_flags: u32,        // Processor-specific flags
    e_ehsize: u16,       // ELF header size (64)
    e_phentsize: u16,    // Program header entry size
    e_phnum: u16,        // Number of program headers
    e_shentsize: u16,    // Section header entry size (64)
    e_shnum: u16,        // Number of section headers
    e_shstrndx: u16,     // Section name string table index
};
```

---

## Relocations

Relocations tell the linker "patch this location with this symbol's address":

```zig
pub const Relocation = struct {
    offset: u32,           // Where in the code to patch
    symbol: []const u8,    // What symbol to look up
    kind: RelocKind,       // How to calculate the patch
    addend: i64,           // Constant to add
};

pub const RelocKind = enum {
    pc_rel_32,        // PC-relative 32-bit (calls)
    abs_64,           // Absolute 64-bit address
    aarch64_adrp,     // ARM64 ADRP page address
    aarch64_add_lo12, // ARM64 ADD low 12 bits
    got_rel,          // GOT-relative
    plt_rel,          // PLT-relative
};
```

### ARM64 Relocations

ARM64 uses **PC-relative addressing** for function calls:

```asm
bl _print    ; Branch-and-link to print
```

The `bl` instruction encodes a 26-bit signed offset (±128MB range). The linker calculates:

```
offset = symbol_address - instruction_address
encoded = (offset >> 2) & 0x03FFFFFF
```

For data access, ARM64 uses **ADRP + ADD**:

```asm
adrp x0, _str@PAGE       ; Load page address (upper bits)
add x0, x0, _str@PAGEOFF ; Add page offset (lower 12 bits)
```

### x86_64 Relocations

x86_64 typically uses 32-bit PC-relative offsets:

```asm
call _print    ; 5 bytes: E8 xx xx xx xx
```

The linker patches the 4-byte offset:

```
offset = symbol_address - (instruction_address + 4)
```

---

## Symbol Tables

Symbols are names that refer to code or data:

```zig
/// Mach-O symbol table entry (nlist_64)
const NList64 = packed struct {
    n_strx: u32,   // String table index (name)
    n_type: u8,    // Symbol type flags
    n_sect: u8,    // Section number (1-based)
    n_desc: i16,   // Additional info
    n_value: u64,  // Symbol value (address)
};
```

Symbol types:
- **N_EXT** (0x01): External (visible to linker)
- **N_UNDF** (0x00): Undefined (needs to be resolved)
- **N_SECT** (0x0E): Defined in a section

For our `add` function:

```
Symbol: "_add"
  type: N_EXT | N_SECT  (external, defined)
  sect: 1               (__TEXT,__text)
  value: 0              (offset in section)
```

For a call to `print`:

```
Symbol: "_print"
  type: N_EXT | N_UNDF  (external, undefined)
  sect: 0
  value: 0
```

---

## The Linking Process

Cot uses `zig cc` as the linker:

```zig
fn link(self: *Driver, obj_path: []const u8, out_path: []const u8) !void {
    var args = ArrayList([]const u8){};

    // Use Zig's C compiler driver
    try args.append("zig");
    try args.append("cc");

    // Input object file
    try args.append(obj_path);

    // Link with runtime library
    try args.append("-L.");
    try args.append("-lcot_runtime");

    // Output path
    try args.append("-o");
    try args.append(out_path);

    // Execute linker
    const result = try std.process.Child.run(.{
        .argv = args.items,
        .allocator = self.allocator,
    });
}
```

The linker:
1. Reads all input `.o` files
2. Resolves undefined symbols (finds definitions)
3. Applies relocations (patches addresses)
4. Writes the final executable

---

## Object File Generation

Here's how we generate a Mach-O object file:

```zig
pub fn writeMachO(
    allocator: Allocator,
    code: *CodeBuffer,
    rodata: []const u8,
    symbols: []const Symbol,
    relocs: []const Relocation,
    arch: Arch,
    output: anytype,
) !void {
    // 1. Write Mach-O header
    const header = MachHeader64{
        .magic = 0xFEEDFACF,
        .cputype = if (arch == .aarch64) CPU_TYPE_ARM64 else CPU_TYPE_X86_64,
        .filetype = MH_OBJECT,
        .ncmds = 4,  // segment + symtab + dysymtab + build version
        // ...
    };
    try writeStruct(output, header);

    // 2. Write segment load command with sections
    try writeSegmentCommand(output, code.len, rodata.len);

    // 3. Write symbol table command
    try writeSymtabCommand(output, symbols.len);

    // 4. Write section data
    try output.writeAll(code.data[0..code.pos]);
    try output.writeAll(rodata);

    // 5. Write relocations
    for (relocs) |reloc| {
        try writeRelocation(output, reloc, arch);
    }

    // 6. Write symbol table
    for (symbols) |sym| {
        try writeSymbol(output, sym);
    }

    // 7. Write string table
    for (symbols) |sym| {
        try output.writeAll(sym.name);
        try output.writeByte(0);
    }
}
```

---

## String Literals

String literals go in the read-only data section:

```zig
/// Track string literal info for rodata section
pub const StringInfo = struct {
    offset: u32,           // Offset in rodata
    len: u32,              // String length
    symbol_name: []const u8, // Symbol name ("_str_0", etc.)
};

// During codegen, when we see a string literal:
fn addStringLiteral(self: *Driver, str: []const u8) !u32 {
    const idx = self.string_literals.items.len;
    try self.string_literals.append(str);

    // Also add symbol for relocation
    try self.symbols.append(.{
        .name = try std.fmt.allocPrint(self.allocator, "_str_{d}", .{idx}),
        .offset = self.rodata_offset,
        .section = .rodata,
    });

    self.rodata_offset += @intCast(str.len + 1);
    return @intCast(idx);
}
```

When code references a string, we emit:

```asm
; ARM64: Load string address
adrp x0, _str_0@PAGE
add x0, x0, _str_0@PAGEOFF
mov x1, #5            ; String length
```

The linker resolves `_str_0` to the actual address in rodata.

---

## Runtime Functions

The Cot runtime provides essential functions:

| Function | Purpose |
|----------|---------|
| `cot_print_int` | Print an integer |
| `cot_print_str` | Print a string |
| `cot_str_concat` | Concatenate strings |
| `cot_str_eq` | Compare strings |
| `cot_map_new` | Create hash map |
| `cot_list_new` | Create dynamic array |

These are compiled separately and linked:

```bash
# Build runtime
zig build-lib -O ReleaseFast runtime/cot_runtime.zig -static

# Link with user code
zig cc user_code.o -L. -lcot_runtime -o program
```

---

## Complete Example

Let's trace the complete pipeline for:

```cot
fn main() i64 {
    return 42;
}
```

### Generated Object File

```
=== Mach-O Object File ===

Header:
  magic: 0xFEEDFACF (64-bit)
  cputype: ARM64
  filetype: MH_OBJECT

Sections:
  __TEXT,__text: 24 bytes at offset 0x200
    [code for _main]

Symbols:
  [0] _main: TEXT section, offset 0, external

Relocations:
  (none - no external calls)
```

### Linking

```bash
zig cc main.o -o main
```

The linker:
1. Creates executable header
2. Adds startup code (`_start` calls `main`)
3. Links C library (for `exit`)
4. Resolves addresses
5. Writes executable

### Final Executable

```bash
./main
echo $?
42
```

---

## Key Takeaways

1. **Object files** package code with metadata for the linker.

2. **Mach-O** (macOS) and **ELF** (Linux) have different structures but similar concepts.

3. **Relocations** mark places the linker needs to patch with symbol addresses.

4. **Symbols** are named references (functions, variables) with attributes.

5. **The linker** resolves undefined symbols and applies relocations.

6. **Runtime functions** are linked separately and called via relocations.

---

## What's Next

You've now seen the entire compiler pipeline from source code to executable! To deepen your understanding:

- **[CPU Basics](../cpu/20_CPU_BASICS.md)** - How the CPU actually executes your code
- **[Worked Example](../30_WORKED_EXAMPLE.md)** - Trace a complete program through every stage

---

## Appendix: Useful Commands

```bash
# View Mach-O structure
otool -l program.o

# View sections
otool -s __TEXT __text program.o

# Disassemble
otool -d program.o      # or objdump -d program.o

# View symbols
nm program.o

# View relocations
otool -r program.o

# View ELF structure
readelf -a program.o
```
