//! Cot Compiler Driver - v2 (Proper Two-Phase Architecture)
//!
//! This is a complete rewrite following Go's compiler design:
//! 1. Regalloc pass assigns Func.locations[v.id] to every value
//! 2. Codegen just looks up locations - no guessing
//!
//! Reference: ~/learning/go/src/cmd/compile/internal/ssa/regalloc.go

const std = @import("std");
const Allocator = std.mem.Allocator;

// Import compiler phases
const source = @import("source.zig");
const scanner = @import("scanner.zig");
const parser = @import("parser.zig");
const ast = @import("ast.zig");
const check = @import("check.zig");
const types = @import("types.zig");
const ir = @import("ir.zig");
const lower = @import("lower.zig");
const ssa = @import("ssa.zig");
const errors = @import("errors.zig");

// Import codegen backends
const be = @import("codegen/backend.zig");
const object = @import("codegen/object.zig");
const aarch64 = @import("codegen/aarch64.zig");
const x86_64 = @import("codegen/x86_64.zig");

// Import integrated codegen modules (Zig-style - regalloc during codegen)
const amd64_codegen = @import("codegen/amd64_codegen.zig");
const arm64_codegen = @import("codegen/arm64_codegen.zig");

// Re-export Location from ssa
pub const Location = ssa.Location;

// Re-export StringInfo from backend
pub const StringInfo = be.StringInfo;

// ============================================================================
// Target Configuration
// ============================================================================

pub const Target = struct {
    arch: be.Arch,
    os: be.OS,

    pub fn native() Target {
        return .{
            .arch = switch (@import("builtin").cpu.arch) {
                .x86_64 => .x86_64,
                .aarch64 => .aarch64,
                else => .x86_64,
            },
            .os = switch (@import("builtin").os.tag) {
                .macos => .macos,
                .linux => .linux,
                .windows => .windows,
                else => .linux,
            },
        };
    }
};

// ============================================================================
// Compile Options
// ============================================================================

pub const CompileOptions = struct {
    input_path: []const u8,
    output_path: ?[]const u8 = null,
    target: Target = Target.native(),

    // Debug flags
    debug_ir: bool = false,
    debug_ssa: bool = false,
    debug_codegen: bool = false,
    disasm: bool = false,

    pub fn getOutputPath(self: *const CompileOptions) []const u8 {
        if (self.output_path) |p| return p;
        // Default: input name without extension
        const base = std.fs.path.basename(self.input_path);
        if (std.mem.lastIndexOf(u8, base, ".")) |dot| {
            return base[0..dot];
        }
        return base;
    }
};

// ============================================================================
// Compile Result
// ============================================================================

pub const CompileResult = struct {
    success: bool,
    output_path: ?[]const u8 = null,
    error_count: u32 = 0,
};

// ============================================================================
// Driver - Main Compiler Orchestration
// ============================================================================

pub const Driver = struct {
    allocator: Allocator,
    options: CompileOptions,

    // Compilation artifacts (owned)
    src: ?*source.Source = null,
    tree: ?*ast.Ast = null,
    type_reg: ?*types.TypeRegistry = null,
    type_checker: ?*check.Checker = null,
    ir_data: ?*ir.IR = null,
    err_reporter: ?*errors.ErrorReporter = null,
    global_scope: ?*check.Scope = null,

    // String literals from lowering (for rodata section)
    string_literals: std.ArrayList([]const u8) = .{ .items = &.{}, .capacity = 0 },

    pub fn init(allocator: Allocator, options: CompileOptions) Driver {
        return .{
            .allocator = allocator,
            .options = options,
        };
    }

    pub fn deinit(self: *Driver) void {
        if (self.src) |s| {
            s.deinit();
            self.allocator.destroy(s);
        }
        if (self.tree) |t| {
            t.deinit();
            self.allocator.destroy(t);
        }
        if (self.type_reg) |tr| {
            tr.deinit();
            self.allocator.destroy(tr);
        }
        if (self.type_checker) |tc| {
            tc.deinit();
            self.allocator.destroy(tc);
        }
        if (self.err_reporter) |er| {
            self.allocator.destroy(er);
        }
        if (self.global_scope) |gs| {
            gs.deinit();
            self.allocator.destroy(gs);
        }
        if (self.ir_data) |i| {
            self.allocator.destroy(i);
        }
    }

    fn errorResult(self: *Driver) CompileResult {
        const count = if (self.err_reporter) |er| er.count else 1;
        return .{
            .success = false,
            .error_count = count,
        };
    }

    // ========================================================================
    // BOOTSTRAP IMPORT SYSTEM (TEMPORARY)
    // ========================================================================
    //
    // This is a simple textual import system for bootstrapping only.
    // It does basic file concatenation similar to C's #include.
    //
    // For Cot 1.0, this will be replaced with a proper module system
    // following Go's package/import design with:
    // - Package declarations
    // - Explicit exports
    // - Dependency resolution
    // - Cycle detection
    // - Separate compilation
    //
    // Syntax: import "path/to/file.cot"
    //
    // Limitations:
    // - No symbol resolution (just textual inclusion)
    // - No cycle detection
    // - No duplicate detection (caller must manage)
    // - Imports must be at the start of the file
    // ========================================================================

    /// Process import statements and return combined source content.
    /// Returns the content with all imports resolved (imported content prepended).
    fn processImports(self: *Driver, content: []const u8, base_path: []const u8) ![]const u8 {
        var result: std.ArrayList(u8) = .{ .items = &.{}, .capacity = 0 };
        errdefer result.deinit(self.allocator);

        var imported_files: std.StringHashMap(void) = std.StringHashMap(void).init(self.allocator);
        defer imported_files.deinit();

        // Track the base file to prevent self-import
        try imported_files.put(base_path, {});

        // Find and process imports at the start of the file
        var pos: usize = 0;
        var content_start: usize = 0;

        while (pos < content.len) {
            // Skip whitespace and comments
            pos = skipWhitespaceAndComments(content, pos);
            if (pos >= content.len) break;

            // Check for import keyword
            if (pos + 6 <= content.len and std.mem.eql(u8, content[pos .. pos + 6], "import")) {
                pos += 6;

                // Skip whitespace after 'import'
                pos = skipWhitespace(content, pos);
                if (pos >= content.len) break;

                // Expect string literal
                if (content[pos] != '"') {
                    // Not a valid import, treat as regular content
                    break;
                }
                pos += 1;

                // Find end of string
                const path_start = pos;
                while (pos < content.len and content[pos] != '"' and content[pos] != '\n') {
                    pos += 1;
                }
                if (pos >= content.len or content[pos] != '"') {
                    std.debug.print("Error: unterminated import string\n", .{});
                    return error.InvalidImport;
                }
                const import_path = content[path_start..pos];
                pos += 1; // skip closing quote

                // Skip optional semicolon and newline
                pos = skipWhitespace(content, pos);
                if (pos < content.len and content[pos] == ';') pos += 1;
                if (pos < content.len and content[pos] == '\n') pos += 1;

                content_start = pos;

                // Check if already imported
                if (imported_files.get(import_path) != null) {
                    continue; // Skip duplicate import
                }
                try imported_files.put(try self.allocator.dupe(u8, import_path), {});

                // Resolve import path relative to base file
                const resolved_path = try self.resolveImportPath(base_path, import_path);
                defer self.allocator.free(resolved_path);

                // Read imported file
                const imported_content = self.readFile(resolved_path) catch |err| {
                    std.debug.print("Error: cannot read import '{s}': {}\n", .{ import_path, err });
                    return err;
                };

                // Recursively process imports in the imported file
                const processed_import = try self.processImports(imported_content, resolved_path);
                defer if (processed_import.ptr != imported_content.ptr) self.allocator.free(processed_import);

                // Append imported content with a marker comment
                try result.appendSlice(self.allocator, "// --- imported from: ");
                try result.appendSlice(self.allocator, import_path);
                try result.appendSlice(self.allocator, " ---\n");
                try result.appendSlice(self.allocator, processed_import);
                try result.appendSlice(self.allocator, "\n// --- end import ---\n\n");

                // Free the imported content if it wasn't reused
                self.allocator.free(imported_content);
            } else {
                // Not an import, done processing imports
                break;
            }
        }

        // If no imports were processed, return original content
        if (result.items.len == 0) {
            return content;
        }

        // Append remaining content (after imports)
        try result.appendSlice(self.allocator, content[content_start..]);

        return try result.toOwnedSlice(self.allocator);
    }

    fn skipWhitespace(content: []const u8, start: usize) usize {
        var pos = start;
        while (pos < content.len and (content[pos] == ' ' or content[pos] == '\t' or content[pos] == '\r')) {
            pos += 1;
        }
        return pos;
    }

    fn skipWhitespaceAndComments(content: []const u8, start: usize) usize {
        var pos = start;
        while (pos < content.len) {
            // Skip whitespace
            if (content[pos] == ' ' or content[pos] == '\t' or content[pos] == '\r' or content[pos] == '\n') {
                pos += 1;
                continue;
            }
            // Skip line comments
            if (pos + 1 < content.len and content[pos] == '/' and content[pos + 1] == '/') {
                while (pos < content.len and content[pos] != '\n') {
                    pos += 1;
                }
                continue;
            }
            // Skip block comments
            if (pos + 1 < content.len and content[pos] == '/' and content[pos + 1] == '*') {
                pos += 2;
                while (pos + 1 < content.len) {
                    if (content[pos] == '*' and content[pos + 1] == '/') {
                        pos += 2;
                        break;
                    }
                    pos += 1;
                }
                continue;
            }
            break;
        }
        return pos;
    }

    fn resolveImportPath(self: *Driver, base_path: []const u8, import_path: []const u8) ![]const u8 {
        // Get directory of base file
        const base_dir = std.fs.path.dirname(base_path) orelse ".";

        // Join with import path
        return try std.fs.path.join(self.allocator, &[_][]const u8{ base_dir, import_path });
    }

    fn readFile(self: *Driver, path: []const u8) ![]const u8 {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();
        return try file.readToEndAlloc(self.allocator, 1024 * 1024 * 10);
    }

    // ========================================================================
    // END BOOTSTRAP IMPORT SYSTEM
    // ========================================================================

    /// Main compilation entry point
    pub fn compile(self: *Driver) CompileResult {
        // Phase 1: Read source file
        const file = std.fs.cwd().openFile(self.options.input_path, .{}) catch {
            std.debug.print("Error: cannot open {s}\n", .{self.options.input_path});
            return .{ .success = false, .error_count = 1 };
        };
        defer file.close();

        const raw_content = file.readToEndAlloc(self.allocator, 1024 * 1024 * 10) catch {
            std.debug.print("Error: cannot read {s}\n", .{self.options.input_path});
            return .{ .success = false, .error_count = 1 };
        };

        // Process imports (BOOTSTRAP ONLY - textual inclusion)
        // This will be replaced with proper module system in Cot 1.0
        const content = self.processImports(raw_content, self.options.input_path) catch |err| {
            std.debug.print("Error processing imports: {}\n", .{err});
            self.allocator.free(raw_content);
            return .{ .success = false, .error_count = 1 };
        };
        // Free raw_content if processImports created new content
        if (content.ptr != raw_content.ptr) {
            self.allocator.free(raw_content);
        }

        self.src = self.allocator.create(source.Source) catch {
            return .{ .success = false, .error_count = 1 };
        };
        self.src.?.* = source.Source.init(self.allocator, self.options.input_path, content);

        // Initialize error reporter
        self.err_reporter = self.allocator.create(errors.ErrorReporter) catch {
            return .{ .success = false, .error_count = 1 };
        };
        self.err_reporter.?.* = errors.ErrorReporter.init(self.src.?, null);

        // Phase 2: Parse
        self.tree = self.allocator.create(ast.Ast) catch {
            return .{ .success = false, .error_count = 1 };
        };
        self.tree.?.* = ast.Ast.init(self.allocator);

        var scan = scanner.Scanner.init(self.src.?);
        var p = parser.Parser.init(self.allocator, &scan, self.tree.?, self.err_reporter.?);
        _ = p.parseFile() catch {
            return self.errorResult();
        };

        if (self.err_reporter.?.count > 0) {
            return self.errorResult();
        }

        // Phase 3: Type check
        self.type_reg = self.allocator.create(types.TypeRegistry) catch {
            return .{ .success = false, .error_count = 1 };
        };
        self.type_reg.?.* = types.TypeRegistry.init(self.allocator) catch {
            return .{ .success = false, .error_count = 1 };
        };

        self.global_scope = self.allocator.create(check.Scope) catch {
            return .{ .success = false, .error_count = 1 };
        };
        self.global_scope.?.* = check.Scope.init(self.allocator, null);

        self.type_checker = self.allocator.create(check.Checker) catch {
            return .{ .success = false, .error_count = 1 };
        };
        self.type_checker.?.* = check.Checker.init(
            self.allocator,
            self.tree.?,
            self.type_reg.?,
            self.err_reporter.?,
            self.global_scope.?,
        );

        self.type_checker.?.checkFile() catch {
            return self.errorResult();
        };

        if (self.err_reporter.?.count > 0) {
            return self.errorResult();
        }

        // Phase 4: Lower to IR
        var lowerer = lower.Lowerer.init(
            self.allocator,
            self.tree.?,
            self.type_reg.?,
            self.err_reporter.?,
            self.type_checker.?,
        );
        defer lowerer.deinit();

        const ir_result = lowerer.lower() catch {
            return self.errorResult();
        };
        self.ir_data = self.allocator.create(ir.IR) catch {
            return .{ .success = false, .error_count = 1 };
        };
        self.ir_data.?.* = ir_result;

        // Copy string literals from lowerer before it's deinitialized
        self.string_literals = lowerer.string_literals;

        if (self.options.debug_ir) {
            self.dumpIR();
        }

        // Phase 5: Convert to SSA
        var ssa_funcs = self.convertToSSA() catch {
            return .{ .success = false, .error_count = 1 };
        };
        defer {
            for (ssa_funcs.items) |*f| {
                f.deinit();
            }
            ssa_funcs.deinit(self.allocator);
        }

        if (self.options.debug_ssa) {
            self.dumpSSA(&ssa_funcs);
        }

        // Phase 6: Code Generation (integrated register allocation)
        const obj_path = self.generateCode(&ssa_funcs) catch {
            return .{ .success = false, .error_count = 1 };
        };

        // Debug: run disassembler on object file
        if (self.options.disasm) {
            self.runDisasm(obj_path);
        }

        // Phase 8: Link
        const exe_path = self.link(obj_path) catch |err| {
            std.debug.print("Link error: {}\n", .{err});
            return .{ .success = false, .error_count = 1 };
        };

        return .{
            .success = true,
            .output_path = exe_path,
            .error_count = 0,
        };
    }

    fn runDisasm(self: *Driver, obj_path: []const u8) void {
        _ = self;
        std.debug.print("\n=== DISASSEMBLY ({s}) ===\n", .{obj_path});

        var child = std.process.Child.init(&.{ "objdump", "-d", obj_path }, std.heap.page_allocator);
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;

        _ = child.spawnAndWait() catch |err| {
            std.debug.print("Failed to run objdump: {}\n", .{err});
            std.debug.print("(Make sure objdump is installed)\n", .{});
            return;
        };

        std.debug.print("=== END DISASSEMBLY ===\n\n", .{});
    }

    // ========================================================================
    // Phase 4: IR to SSA Conversion
    // ========================================================================

    fn convertToSSA(self: *Driver) !std.ArrayList(ssa.Func) {
        var funcs = std.ArrayList(ssa.Func){ .items = &.{}, .capacity = 0 };
        const ir_data = self.ir_data orelse return funcs;

        for (ir_data.funcs) |ir_func| {
            var ssa_func = ssa.Func.init(
                self.allocator,
                ir_func.name,
                ir_func.type_idx,
                ir_func.return_type,
            );

            // Copy parameter count and frame size
            ssa_func.param_count = @intCast(ir_func.params.len);
            ssa_func.frame_size = @intCast(ir_func.frame_size);

            // Copy local variable info for codegen offset calculations
            var local_infos = std.ArrayList(ssa.LocalInfo){ .items = &.{}, .capacity = 0 };
            for (ir_func.locals) |local| {
                try local_infos.append(self.allocator, .{
                    .name = local.name,
                    .type_idx = local.type_idx,
                    .size = local.size,
                    .offset = local.offset,
                });
            }
            ssa_func.locals = try self.allocator.dupe(ssa.LocalInfo, local_infos.items);
            local_infos.deinit(self.allocator);

            // Convert IR nodes to SSA values
            try self.convertIRToSSA(&ssa_func, ir_func);

            try funcs.append(self.allocator, ssa_func);
        }

        return funcs;
    }

    fn convertIRToSSA(self: *Driver, func: *ssa.Func, ir_func: ir.Func) !void {
        _ = self;

        // Map IR node index -> SSA value ID
        var ir_to_ssa = std.AutoHashMap(u32, ssa.ValueID).init(func.allocator);
        defer ir_to_ssa.deinit();

        // Map IR block -> SSA block
        var ir_block_to_ssa = std.AutoHashMap(u32, u32).init(func.allocator);
        defer ir_block_to_ssa.deinit();

        // Track which blocks have already been terminated (for dead code handling)
        var terminated_blocks = std.AutoHashMap(u32, bool).init(func.allocator);
        defer terminated_blocks.deinit();

        // Create SSA blocks for each IR block
        for (ir_func.blocks, 0..) |_, idx| {
            const block_id = func.newBlock();
            try ir_block_to_ssa.put(@intCast(idx), block_id);
        }

        // Convert each IR node - handle terminators specially (Go-style)
        for (ir_func.nodes, 0..) |*node, idx| {
            const ssa_block_id = ir_block_to_ssa.get(node.block) orelse 0;

            // Skip if this block has already been terminated (dead code)
            if (terminated_blocks.get(node.block) orelse false) {
                continue;
            }

            var ssa_block = func.getBlock(ssa_block_id);

            switch (node.data) {
                // Terminators set block metadata, not values
                .branch => |br| {
                    ssa_block.kind = .@"if";

                    // Get condition SSA value
                    if (ir_to_ssa.get(br.condition)) |cond_ssa| {
                        ssa_block.setControl(cond_ssa);
                    }

                    // Set successors
                    if (ir_block_to_ssa.get(br.then_block)) |then_ssa| {
                        _ = ssa_block.addSucc(then_ssa);
                    }
                    if (ir_block_to_ssa.get(br.else_block)) |else_ssa| {
                        _ = ssa_block.addSucc(else_ssa);
                    }

                    // Mark block as terminated
                    try terminated_blocks.put(node.block, true);
                },

                .jump => |jmp| {
                    ssa_block.kind = .plain;
                    if (ir_block_to_ssa.get(jmp.target)) |target_ssa| {
                        _ = ssa_block.addSucc(target_ssa);
                    }

                    // Mark block as terminated
                    try terminated_blocks.put(node.block, true);
                },

                .ret => |ret| {
                    ssa_block.kind = .ret;
                    if (ret.value) |ret_val| {
                        if (ir_to_ssa.get(ret_val)) |ssa_val| {
                            ssa_block.setControl(ssa_val);
                        }
                    }

                    // Mark block as terminated - any subsequent code in this block is dead
                    try terminated_blocks.put(node.block, true);
                },

                // Non-terminators become SSA values
                else => {
                    const ssa_id = try convertIRNode(func, node, &ir_to_ssa, ssa_block_id);
                    try ir_to_ssa.put(@intCast(idx), ssa_id);
                },
            }
        }

        // Set entry block
        if (ir_block_to_ssa.get(ir_func.entry)) |entry| {
            func.entry = entry;
        }
    }

    // ========================================================================
    // Code Generation (Integrated Register Allocation)
    // ========================================================================
    // Zig-style: register allocation happens DURING codegen, not as a separate pass

    fn generateCode(self: *Driver, funcs: *std.ArrayList(ssa.Func)) ![]const u8 {
        const arch = self.options.target.arch;
        const os = self.options.target.os;

        // Create object file
        const format = object.ObjectFormat.fromTarget(arch, os);
        var obj = object.ObjectFile.init(self.allocator, format);
        defer obj.deinit();

        // Add text section
        const section_name = if (os == .macos) "__text" else ".text";
        const text_idx = try obj.addSection(section_name, .text);

        // Add rodata section for string literals
        const rodata_name = if (os == .macos) "__cstring" else ".rodata";
        const rodata_idx = try obj.addSection(rodata_name, .rodata);

        // Build string info array and populate rodata
        var string_infos = std.ArrayList(StringInfo){ .items = &.{}, .capacity = 0 };
        defer string_infos.deinit(self.allocator);

        var rodata_buf = be.CodeBuffer.init(self.allocator);
        defer rodata_buf.deinit();

        for (self.string_literals.items, 0..) |str, i| {
            const offset: u32 = @intCast(rodata_buf.pos());

            // Create symbol name for this string literal
            const sym_name = if (os == .macos)
                try std.fmt.allocPrint(self.allocator, "_str_{d}", .{i})
            else
                try std.fmt.allocPrint(self.allocator, "str_{d}", .{i});

            // Add symbol for this string in rodata section
            _ = try obj.addSymbol(.{
                .name = sym_name,
                .kind = .data,
                .section = rodata_idx,
                .offset = offset,
                .size = @intCast(str.len),
                .global = false, // Local symbol
            });

            try string_infos.append(self.allocator, .{
                .offset = offset,
                .len = @intCast(str.len),
                .symbol_name = sym_name,
            });

            // Write string bytes to rodata (no null terminator needed for slices)
            for (str) |byte| {
                try rodata_buf.emit8(byte);
            }
        }

        // Add rodata to object file
        if (rodata_buf.pos() > 0) {
            try obj.addCode(rodata_idx, &rodata_buf);
        }

        // Generate code for each function
        var code_buf = be.CodeBuffer.init(self.allocator);
        defer code_buf.deinit();

        for (funcs.items) |*func| {
            const sym_offset = code_buf.pos();

            // Add symbol
            const sym_name = if (os == .macos)
                try std.fmt.allocPrint(self.allocator, "_{s}", .{func.name})
            else
                func.name;

            _ = try obj.addSymbol(.{
                .name = sym_name,
                .kind = .func,
                .section = text_idx,
                .offset = sym_offset,
                .size = 0,
                .global = true,
            });

            // Generate function code
            switch (arch) {
                .x86_64 => try self.generateX86Function(&code_buf, func, string_infos.items),
                .aarch64 => try self.generateAArch64Function(&code_buf, func, string_infos.items),
            }
        }

        // Add code to object file
        try obj.addCode(text_idx, &code_buf);

        // Apply local relocations (patch local function calls) before writing
        obj.applyLocalRelocations();

        // Write to file - use input basename for .o file (not -o name)
        const input_stem = std.fs.path.stem(self.options.input_path);
        const obj_path = try std.fmt.allocPrint(self.allocator, "{s}.o", .{input_stem});

        try obj.writeToFile(obj_path);

        return obj_path;
    }

    // ========================================================================
    // x86_64 Code Generation (Integrated Register Allocation)
    // ========================================================================

    fn generateX86Function(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, string_infos: []const StringInfo) !void {
        const type_reg = self.type_reg orelse return error.NoTypeRegistry;

        // Create CodeGen with integrated register allocation
        var cg = amd64_codegen.CodeGen.init(
            self.allocator,
            buf,
            func,
            type_reg,
            self.options.target.os,
            string_infos,
        );
        defer cg.deinit();

        // Compute liveness for smart spill decisions
        try cg.computeLiveness();

        // Generate prologue
        try cg.genPrologue();

        // Track block start offsets for jumps
        var block_offsets = std.ArrayList(u32){ .items = &.{}, .capacity = 0 };
        defer block_offsets.deinit(self.allocator);

        // Track jump patches needed
        const JumpPatch = struct { patch_offset: u32, target_block: u32 };
        var jump_patches = std.ArrayList(JumpPatch){ .items = &.{}, .capacity = 0 };
        defer jump_patches.deinit(self.allocator);

        // Generate each block
        for (func.blocks.items, 0..) |*block, block_idx| {
            try block_offsets.append(self.allocator, @intCast(buf.pos()));

            // Generate values in this block
            for (block.values.items) |vid| {
                const value = &func.values.items[vid];
                try cg.genValue(value);
                cg.advanceInst(); // Track instruction progress for liveness
            }

            // Generate block terminator
            try cg.genBlockEnd(block);

            // Handle jumps for non-return blocks
            if (block.kind == .plain and block.numSuccs() > 0) {
                const target = block.succs()[0].block;
                const next_block: ?u32 = if (block_idx + 1 < func.blocks.items.len)
                    @intCast(block_idx + 1)
                else
                    null;
                if (next_block == null or target != next_block.?) {
                    try buf.emit8(0xE9); // JMP rel32
                    try buf.emit32(0);
                    try jump_patches.append(self.allocator, .{
                        .patch_offset = @intCast(buf.pos()),
                        .target_block = target,
                    });
                }
            } else if (block.kind == .@"if" and block.numSuccs() >= 2 and block.control != ssa.null_value) {
                const cond_mcv = cg.getValue(block.control);
                try cg.loadToReg(amd64_codegen.scratch0, cond_mcv);
                try x86_64.testRegReg(buf, amd64_codegen.scratch0, amd64_codegen.scratch0);

                const then_block = block.succs()[0].block;
                const else_block = block.succs()[1].block;
                const next_block: ?u32 = if (block_idx + 1 < func.blocks.items.len)
                    @intCast(block_idx + 1)
                else
                    null;

                if (next_block != null and else_block == next_block.?) {
                    // JNZ to then_block, fallthrough to else
                    try buf.emit8(0x0F);
                    try buf.emit8(0x85);
                    try buf.emit32(0);
                    try jump_patches.append(self.allocator, .{
                        .patch_offset = @intCast(buf.pos()),
                        .target_block = then_block,
                    });
                } else {
                    // JNZ to then_block, JMP to else_block
                    try buf.emit8(0x0F);
                    try buf.emit8(0x85);
                    try buf.emit32(0);
                    try jump_patches.append(self.allocator, .{
                        .patch_offset = @intCast(buf.pos()),
                        .target_block = then_block,
                    });

                    try buf.emit8(0xE9);
                    try buf.emit32(0);
                    try jump_patches.append(self.allocator, .{
                        .patch_offset = @intCast(buf.pos()),
                        .target_block = else_block,
                    });
                }
            }
        }

        // Patch all jumps
        for (jump_patches.items) |patch| {
            const target_offset = if (patch.target_block < block_offsets.items.len)
                block_offsets.items[patch.target_block]
            else
                @as(u32, @intCast(buf.pos()));
            const rel_offset: i32 = @as(i32, @intCast(target_offset)) - @as(i32, @intCast(patch.patch_offset));
            buf.patch32(patch.patch_offset - 4, @bitCast(rel_offset));
        }
    }

    // ========================================================================
    // AArch64 Code Generation (Integrated Register Allocation)
    // ========================================================================

    fn generateAArch64Function(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, string_infos: []const StringInfo) !void {
        const type_reg = self.type_reg orelse return error.NoTypeRegistry;

        // Pre-analyze SSA to estimate spill requirements before codegen
        // This avoids the complexity of body-first with separate epilogue patching
        const estimated_spill = estimateSpillRequirements(func, type_reg);

        // Stack size: frame_size (locals) + 16 (fp/lr) + 80 (callee-saved) + estimated spill
        // We always reserve 80 bytes for callee-saved registers (x19-x28 = 10 regs * 8 bytes)
        // but only save/restore the ones actually used (Go's approach for simplicity).
        // This avoids the complexity of two-phase codegen with offset adjustment.
        const callee_saved_reserved: u32 = 80;
        const stack_size = alignTo(func.frame_size + 16 + callee_saved_reserved + estimated_spill, 16);

        // Simple approach: Always save ALL callee-saved registers in prologue.
        // This wastes some stack/instructions but is correct and simple.
        // (Optimizing to only save used registers requires two-phase codegen.)

        var cg = arm64_codegen.CodeGen.init(
            self.allocator,
            buf,
            func,
            type_reg,
            self.options.target.os,
            string_infos,
            stack_size,
        );
        defer cg.deinit();

        // Compute liveness for smart spill decisions
        try cg.computeLiveness();

        // Generate prologue (saves ALL callee-saved registers)
        try cg.genPrologue();

        // Track block start offsets for jumps
        var block_offsets = std.ArrayList(u32){ .items = &.{}, .capacity = 0 };
        defer block_offsets.deinit(self.allocator);

        // Track jump patches needed
        const JumpPatch = struct { patch_offset: u32, target_block: u32 };
        var jump_patches = std.ArrayList(JumpPatch){ .items = &.{}, .capacity = 0 };
        defer jump_patches.deinit(self.allocator);

        // Generate each block
        for (func.blocks.items, 0..) |*block, block_idx| {
            try block_offsets.append(self.allocator, @intCast(buf.pos()));

            // Generate values in this block
            for (block.values.items) |vid| {
                const value = &func.values.items[vid];
                try cg.genValue(value);
                cg.advanceInst();
            }

            // Generate block terminator
            try cg.genBlockEnd(block);

            // Handle jumps for non-return blocks
            if (block.kind == .plain and block.numSuccs() > 0) {
                const target = block.succs()[0].block;
                const next_block: ?u32 = if (block_idx + 1 < func.blocks.items.len)
                    @intCast(block_idx + 1)
                else
                    null;
                if (next_block == null or target != next_block.?) {
                    try aarch64.bImm(buf, 0);
                    try jump_patches.append(self.allocator, .{
                        .patch_offset = @intCast(buf.pos()),
                        .target_block = target,
                    });
                }
            } else if (block.kind == .@"if" and block.numSuccs() >= 2 and block.control != ssa.null_value) {
                const cond_mcv = cg.getValue(block.control);
                try cg.loadToReg(arm64_codegen.scratch0, cond_mcv);

                const then_block = block.succs()[0].block;
                const else_block = block.succs()[1].block;
                const next_block: ?u32 = if (block_idx + 1 < func.blocks.items.len)
                    @intCast(block_idx + 1)
                else
                    null;

                if (next_block != null and else_block == next_block.?) {
                    try aarch64.cbnz(buf, arm64_codegen.scratch0, 0);
                    try jump_patches.append(self.allocator, .{
                        .patch_offset = @intCast(buf.pos()),
                        .target_block = then_block,
                    });
                } else {
                    try aarch64.cbnz(buf, arm64_codegen.scratch0, 0);
                    try jump_patches.append(self.allocator, .{
                        .patch_offset = @intCast(buf.pos()),
                        .target_block = then_block,
                    });

                    try aarch64.bImm(buf, 0);
                    try jump_patches.append(self.allocator, .{
                        .patch_offset = @intCast(buf.pos()),
                        .target_block = else_block,
                    });
                }
            }
        }

        // Patch all jumps
        for (jump_patches.items) |patch| {
            const target_offset = if (patch.target_block < block_offsets.items.len)
                block_offsets.items[patch.target_block]
            else
                @as(u32, @intCast(buf.pos()));
            const inst_addr = patch.patch_offset - 4;
            const rel_offset: i32 = (@as(i32, @intCast(target_offset)) - @as(i32, @intCast(inst_addr))) >> 2;
            aarch64.patchBranch(buf, patch.patch_offset, rel_offset);
        }
    }

    /// Pre-analyze SSA to estimate spill space requirements.
    /// This counts operations that need temporary stack space:
    /// - list_push with large elements (>8 bytes) needs temp storage
    /// - Register spills for complex expressions
    fn estimateSpillRequirements(func: *ssa.Func, type_reg: *types.TypeRegistry) u32 {
        var estimated: u32 = 64; // Base spill space for register pressure

        for (func.blocks.items) |*block| {
            for (block.values.items) |vid| {
                const value = &func.values.items[vid];
                switch (value.op) {
                    .list_push => {
                        // list_push with large elements needs temp space
                        if (value.args().len >= 2) {
                            const elem_val = &func.values.items[value.args()[1]];
                            const elem_size = type_reg.sizeOf(elem_val.type_idx);
                            if (elem_size > 8) {
                                estimated += alignTo(elem_size, 8);
                            }
                        }
                    },
                    .union_init => {
                        // union_init builds large unions (>16 bytes) on stack
                        const union_size = type_reg.sizeOf(value.type_idx);
                        if (union_size > 16) {
                            estimated += alignTo(union_size, 8);
                        } else {
                            estimated += 8;
                        }
                    },
                    .call => {
                        // Function calls may need to spill caller-saved registers
                        estimated += 64;
                    },
                    .eq, .ne => {
                        // String comparisons generate calls to cot_str_eq
                        // which need spill space for caller-saved registers
                        const args = value.args();
                        if (args.len >= 1) {
                            const left_val = &func.values.items[args[0]];
                            const left_type = type_reg.get(left_val.type_idx);
                            if (left_type == .slice) {
                                estimated += 32; // Spill space for string comparison call
                            }
                        }
                    },
                    .list_get => {
                        // list_get with large elements needs space to copy result
                        const elem_size = type_reg.sizeOf(value.type_idx);
                        if (elem_size > 8) {
                            estimated += alignTo(elem_size, 8);
                        }
                    },
                    .list_set => {
                        // list_set with large elements needs temp space for value
                        if (value.args().len >= 3) {
                            const elem_val = &func.values.items[value.args()[2]];
                            const elem_size = type_reg.sizeOf(elem_val.type_idx);
                            if (elem_size > 8) {
                                estimated += alignTo(elem_size, 8);
                            }
                        }
                    },
                    .select => {
                        // select on slice types uses 16 bytes of spill space
                        const ret_type = type_reg.get(value.type_idx);
                        if (ret_type == .slice) {
                            estimated += 16;
                        }
                    },
                    else => {},
                }
            }
        }

        return estimated;
    }

    // ========================================================================
    // Phase 7: Linking
    // ========================================================================

    fn link(self: *Driver, obj_path: []const u8) ![]const u8 {
        const output = self.options.getOutputPath();

        // Check for runtime library
        const runtime_lib = "./zig-out/lib/libcot_runtime.a";
        const cwd = std.fs.cwd();
        const has_runtime = blk: {
            cwd.access(runtime_lib, .{}) catch break :blk false;
            break :blk true;
        };
        std.debug.print("Link: has_runtime={}, lib={s}\n", .{ has_runtime, runtime_lib });

        // Use zig cc as linker
        if (has_runtime) {
            var child = std.process.Child.init(
                &.{ "zig", "cc", "-o", output, obj_path, runtime_lib },
                self.allocator,
            );
            _ = child.spawnAndWait() catch return error.LinkFailed;
        } else {
            var child = std.process.Child.init(
                &.{ "zig", "cc", "-o", output, obj_path },
                self.allocator,
            );
            _ = child.spawnAndWait() catch return error.LinkFailed;
        }

        return output;
    }

    // ========================================================================
    // Debug Output
    // ========================================================================

    fn dumpIR(self: *Driver) void {
        std.debug.print("\n=== IR DUMP ===\n", .{});
        if (self.ir_data) |ir_data| {
            // Dump structs
            if (ir_data.structs.len > 0) {
                std.debug.print("\nStructs:\n", .{});
                for (ir_data.structs) |s| {
                    std.debug.print("  struct {s}\n", .{s.name});
                }
            }

            // Dump functions
            for (ir_data.funcs) |func| {
                std.debug.print("\nfunc {s} (frame_size={d}):\n", .{ func.name, func.frame_size });

                // Dump locals
                if (func.locals.len > 0) {
                    std.debug.print("  locals:\n", .{});
                    for (func.locals, 0..) |local, i| {
                        std.debug.print("    [{d}] {s}: type={d}, size={d}, offset={d}\n", .{ i, local.name, local.type_idx, local.size, local.offset });
                    }
                }

                // Dump nodes (IR ops)
                std.debug.print("  ops:\n", .{});
                for (func.nodes, 0..) |node, i| {
                    std.debug.print("    [{d}] {s} type={d}", .{ i, @tagName(node.data), node.type_idx });
                    // Show call args
                    if (node.data == .call) {
                        const c = node.data.call;
                        std.debug.print(" args=[", .{});
                        for (c.args, 0..) |arg, j| {
                            if (j > 0) std.debug.print(",", .{});
                            std.debug.print("{d}", .{arg});
                        }
                        std.debug.print("]", .{});
                    }
                    std.debug.print("\n", .{});
                }
            }
        }
        std.debug.print("=== END IR ===\n\n", .{});
    }

    fn dumpSSA(self: *Driver, funcs: *std.ArrayList(ssa.Func)) void {
        _ = self;
        std.debug.print("\n=== SSA DUMP ===\n", .{});
        for (funcs.items) |*func| {
            std.debug.print("\nfunc {s}:\n", .{func.name});
            for (func.blocks.items, 0..) |*block, block_idx| {
                std.debug.print("  b{d}:\n", .{block_idx});
                for (block.values.items) |vid| {
                    const val = &func.values.items[vid];
                    std.debug.print("    v{d} = {s}", .{ val.id, @tagName(val.op) });
                    if (val.args_len > 0) {
                        std.debug.print(" [", .{});
                        for (val.args(), 0..) |arg, i| {
                            if (i > 0) std.debug.print(",", .{});
                            std.debug.print("v{d}", .{arg});
                        }
                        std.debug.print("]", .{});
                    }
                    if (val.aux_int != 0) {
                        std.debug.print(" aux={d}", .{val.aux_int});
                    }
                    std.debug.print("\n", .{});
                }
            }
        }
        std.debug.print("=== END SSA ===\n\n", .{});
    }

};

// ============================================================================
// IR Node to SSA Conversion
// ============================================================================

fn convertIRNode(func: *ssa.Func, node: *const ir.Node, ir_to_ssa: *std.AutoHashMap(u32, ssa.ValueID), block: u32) !ssa.ValueID {
    // Note: terminators (branch, jump, ret) are handled in convertIRToSSA as block metadata
    // Map IR2 tagged union to SSA op and extract arguments

    var ssa_op: ssa.Op = undefined;
    var aux_int: i64 = 0;
    var aux_str: []const u8 = "";

    // First pass: determine SSA op and copy auxiliary data
    switch (node.data) {
        // Constants
        .const_int => |ci| {
            ssa_op = .const_int;
            aux_int = ci.value;
        },
        .const_float => |cf| {
            ssa_op = .const_float;
            // Store float as bits in aux_int
            aux_int = @bitCast(cf.value);
        },
        .const_bool => |cb| {
            ssa_op = .const_bool;
            aux_int = if (cb.value) 1 else 0;
        },
        .const_null => {
            ssa_op = .const_nil;
        },
        .const_slice => |cs| {
            ssa_op = .const_slice;
            aux_int = cs.string_index;
        },

        // Binary operations
        .binary => |bin| {
            ssa_op = switch (bin.op) {
                .add => .add,
                .sub => .sub,
                .mul => .mul,
                .div => .div,
                .mod => .mod,
                .eq => .eq,
                .ne => .ne,
                .lt => .lt,
                .le => .le,
                .gt => .gt,
                .ge => .ge,
                .@"and" => .@"and",
                .@"or" => .@"or",
                .bit_and => .bit_and,
                .bit_or => .bit_or,
                .bit_xor => .bit_xor,
                .shl => .shl,
                .shr => .shr,
            };
        },

        // Unary operations
        .unary => |un| {
            ssa_op = switch (un.op) {
                .neg => .neg,
                .not => .not,
                .bit_not => .bit_not,
            };
        },

        // Local variable access
        .local_ref, .load_local => {
            ssa_op = .load;
        },
        .addr_local => {
            ssa_op = .addr;
        },
        .store_local => {
            ssa_op = .store;
        },

        // Field access
        .field_local => |fl| {
            ssa_op = .field_local;
            aux_int = fl.offset;
        },
        .store_local_field => |sf| {
            ssa_op = .store;
            aux_int = sf.offset;
        },
        .field_value => |fv| {
            ssa_op = .field_value;
            aux_int = fv.offset;
        },

        // Pointer operations
        .ptr_load => {
            ssa_op = .ptr_load;
        },
        .ptr_store => {
            ssa_op = .ptr_store;
        },
        .ptr_field => |pf| {
            ssa_op = .ptr_field;
            aux_int = pf.offset;
        },
        .ptr_field_store => |pfs| {
            ssa_op = .ptr_field_store;
            aux_int = pfs.offset;
        },
        .ptr_load_value => {
            ssa_op = .ptr_load;
        },
        .ptr_store_value => {
            ssa_op = .ptr_store;
        },

        // Address arithmetic
        .addr_offset => |ao| {
            ssa_op = .addr_const;
            aux_int = ao.offset;
        },
        .addr_index => |ai| {
            // addr_index computes address without loading
            ssa_op = .addr_add;
            aux_int = ai.elem_size;
        },

        // Array/slice indexing
        .index_local => |il| {
            ssa_op = .index_local;
            aux_int = il.elem_size;
        },
        .index_value => |iv| {
            ssa_op = .index_value;
            aux_int = iv.elem_size;
        },
        .slice_local => |sl| {
            ssa_op = .slice_local;
            aux_int = sl.elem_size;
        },
        .slice_value => |sv| {
            ssa_op = .slice_value;
            aux_int = sv.elem_size;
        },
        .slice_index => |si| {
            ssa_op = .slice_index;
            aux_int = si.elem_size;
        },

        // Control flow
        .call => |c| {
            ssa_op = .call;
            aux_str = c.func_name;
        },
        .select => {
            ssa_op = .select;
        },
        .phi => {
            ssa_op = .phi;
        },

        // Union operations
        .union_init => |ui| {
            ssa_op = .union_init;
            aux_int = ui.variant_idx;
        },
        .union_tag => {
            ssa_op = .union_tag;
        },
        .union_payload => |up| {
            ssa_op = .union_payload;
            aux_int = up.variant_idx;
        },

        // List operations
        .list_new => {
            ssa_op = .list_new;
        },
        .list_push => {
            ssa_op = .list_push;
        },
        .list_get => {
            ssa_op = .list_get;
        },
        .list_set => {
            ssa_op = .list_set;
        },
        .list_len => {
            ssa_op = .list_len;
        },
        .list_free => {
            ssa_op = .list_free;
        },
        .list_data_ptr => {
            ssa_op = .list_data_ptr;
        },
        .list_byte_size => {
            ssa_op = .list_byte_size;
        },

        // Map operations
        .map_new => {
            ssa_op = .map_new;
        },
        .map_set => {
            ssa_op = .map_set;
        },
        .map_get => {
            ssa_op = .map_get;
        },
        .map_has => {
            ssa_op = .map_has;
        },
        .map_size => {
            ssa_op = .map_size;
        },
        .map_free => {
            ssa_op = .map_free;
        },

        // String operations
        .str_concat => {
            ssa_op = .str_concat;
        },

        // File I/O
        .file_read => {
            ssa_op = .file_read;
        },
        .file_write => {
            ssa_op = .file_write;
        },
        .file_exists => {
            ssa_op = .file_exists;
        },
        .file_free => {
            ssa_op = .file_free;
        },
        .file_write_list_bytes => {
            ssa_op = .file_write_list_bytes;
        },

        // Command line args
        .args_count => {
            ssa_op = .args_count;
        },
        .args_get => {
            ssa_op = .args_get;
        },

        // Conversions
        .convert => {
            ssa_op = .copy;
        },
        .ptr_cast => {
            ssa_op = .copy;
        },

        // Misc
        .nop => {
            ssa_op = .copy;
        },

        // Terminators handled elsewhere
        .branch, .jump, .ret => unreachable,
    }

    const value_id = try func.newValue(ssa_op, node.type_idx, block);
    var value = func.getValue(value_id);

    // Copy auxiliary data
    value.aux_int = aux_int;
    if (aux_str.len > 0) {
        value.aux_str = aux_str;
    }

    // Second pass: convert arguments based on op type
    switch (node.data) {
        .const_int, .const_float, .const_bool, .const_null, .const_slice => {
            // No arguments for constants
        },

        .binary => |bin| {
            if (ir_to_ssa.get(bin.left)) |left_ssa| {
                try value.addArg(left_ssa, func.allocator);
            }
            if (ir_to_ssa.get(bin.right)) |right_ssa| {
                try value.addArg(right_ssa, func.allocator);
            }
        },

        .unary => |un| {
            if (ir_to_ssa.get(un.operand)) |op_ssa| {
                try value.addArg(op_ssa, func.allocator);
            }
        },

        .local_ref => |lr| {
            value.args_storage[0] = lr.local_idx;
            value.args_len = 1;
        },
        .addr_local => |al| {
            value.args_storage[0] = al.local_idx;
            value.args_len = 1;
        },
        .load_local => |ll| {
            value.args_storage[0] = ll.local_idx;
            value.args_len = 1;
        },
        .store_local => |sl| {
            value.args_storage[0] = sl.local_idx;
            if (ir_to_ssa.get(sl.value)) |val_ssa| {
                value.args_storage[1] = val_ssa;
            }
            value.args_len = 2;
        },

        .field_local => |fl| {
            value.args_storage[0] = fl.local_idx;
            value.args_len = 1;
        },
        .store_local_field => |sf| {
            value.args_storage[0] = sf.local_idx;
            if (ir_to_ssa.get(sf.value)) |val_ssa| {
                value.args_storage[1] = val_ssa;
            }
            value.args_len = 2;
        },
        .field_value => |fv| {
            if (ir_to_ssa.get(fv.base)) |base_ssa| {
                value.args_storage[0] = base_ssa;
                value.args_len = 1;
            }
        },

        .ptr_load => |pl| {
            value.args_storage[0] = pl.ptr_local;
            value.args_len = 1;
        },
        .ptr_store => |ps| {
            value.args_storage[0] = ps.ptr_local;
            if (ir_to_ssa.get(ps.value)) |val_ssa| {
                value.args_storage[1] = val_ssa;
            }
            value.args_len = 2;
        },
        .ptr_field => |pf| {
            value.args_storage[0] = pf.ptr_local;
            value.args_len = 1;
        },
        .ptr_field_store => |pfs| {
            value.args_storage[0] = pfs.ptr_local;
            if (ir_to_ssa.get(pfs.value)) |val_ssa| {
                value.args_storage[1] = val_ssa;
            }
            value.args_len = 2;
        },
        .ptr_load_value => |plv| {
            if (ir_to_ssa.get(plv.ptr)) |ptr_ssa| {
                try value.addArg(ptr_ssa, func.allocator);
            }
        },
        .ptr_store_value => |psv| {
            if (ir_to_ssa.get(psv.ptr)) |ptr_ssa| {
                try value.addArg(ptr_ssa, func.allocator);
            }
            if (ir_to_ssa.get(psv.value)) |val_ssa| {
                try value.addArg(val_ssa, func.allocator);
            }
        },

        .addr_offset => |ao| {
            if (ir_to_ssa.get(ao.base)) |base_ssa| {
                value.args_storage[0] = base_ssa;
                value.args_len = 1;
            }
        },
        .addr_index => |ai| {
            if (ir_to_ssa.get(ai.base)) |base_ssa| {
                value.args_storage[0] = base_ssa;
            }
            if (ir_to_ssa.get(ai.index)) |idx_ssa| {
                value.args_storage[1] = idx_ssa;
            }
            value.args_len = 2;
        },

        .index_local => |il| {
            value.args_storage[0] = il.local_idx;
            if (ir_to_ssa.get(il.index)) |idx_ssa| {
                value.args_storage[1] = idx_ssa;
            }
            value.args_len = 2;
        },
        .index_value => |iv| {
            if (ir_to_ssa.get(iv.base)) |base_ssa| {
                value.args_storage[0] = base_ssa;
            }
            if (ir_to_ssa.get(iv.index)) |idx_ssa| {
                value.args_storage[1] = idx_ssa;
            }
            value.args_len = 2;
        },
        .slice_local => |sl| {
            value.args_storage[0] = sl.local_idx;
            if (ir_to_ssa.get(sl.start)) |start_ssa| {
                value.args_storage[1] = start_ssa;
            }
            if (ir_to_ssa.get(sl.end)) |end_ssa| {
                value.args_storage[2] = end_ssa;
            }
            value.args_len = 3;
        },
        .slice_value => |sv| {
            if (ir_to_ssa.get(sv.base)) |base_ssa| {
                value.args_storage[0] = base_ssa;
            }
            if (ir_to_ssa.get(sv.start)) |start_ssa| {
                value.args_storage[1] = start_ssa;
            }
            if (ir_to_ssa.get(sv.end)) |end_ssa| {
                value.args_storage[2] = end_ssa;
            }
            value.args_len = 3;
        },
        .slice_index => |si| {
            value.args_storage[0] = si.slice_local;
            if (ir_to_ssa.get(si.index)) |idx_ssa| {
                value.args_storage[1] = idx_ssa;
            }
            value.args_len = 2;
        },

        .call => |c| {
            for (c.args) |ir_arg| {
                if (ir_to_ssa.get(ir_arg)) |ssa_arg| {
                    try value.addArg(ssa_arg, func.allocator);
                }
            }
        },

        .select => |s| {
            if (ir_to_ssa.get(s.condition)) |cond_ssa| {
                try value.addArg(cond_ssa, func.allocator);
            }
            if (ir_to_ssa.get(s.then_value)) |then_ssa| {
                try value.addArg(then_ssa, func.allocator);
            }
            if (ir_to_ssa.get(s.else_value)) |else_ssa| {
                try value.addArg(else_ssa, func.allocator);
            }
        },

        .phi => |p| {
            for (p.sources) |src| {
                if (ir_to_ssa.get(src.value)) |val_ssa| {
                    try value.addArg(val_ssa, func.allocator);
                }
            }
        },

        .union_init => |ui| {
            if (ui.payload) |payload| {
                if (ir_to_ssa.get(payload)) |payload_ssa| {
                    try value.addArg(payload_ssa, func.allocator);
                }
            }
        },
        .union_tag => |ut| {
            if (ir_to_ssa.get(ut.value)) |val_ssa| {
                try value.addArg(val_ssa, func.allocator);
            }
        },
        .union_payload => |up| {
            if (ir_to_ssa.get(up.value)) |val_ssa| {
                try value.addArg(val_ssa, func.allocator);
            }
        },

        .list_new, .map_new, .args_count => {
            // No arguments
        },
        .list_push => |lp| {
            if (ir_to_ssa.get(lp.handle)) |h_ssa| {
                try value.addArg(h_ssa, func.allocator);
            }
            if (ir_to_ssa.get(lp.value)) |v_ssa| {
                try value.addArg(v_ssa, func.allocator);
            }
        },
        .list_get => |lg| {
            if (ir_to_ssa.get(lg.handle)) |h_ssa| {
                try value.addArg(h_ssa, func.allocator);
            }
            if (ir_to_ssa.get(lg.index)) |i_ssa| {
                try value.addArg(i_ssa, func.allocator);
            }
        },
        .list_set => |ls| {
            if (ir_to_ssa.get(ls.handle)) |h_ssa| {
                try value.addArg(h_ssa, func.allocator);
            }
            if (ir_to_ssa.get(ls.index)) |i_ssa| {
                try value.addArg(i_ssa, func.allocator);
            }
            if (ir_to_ssa.get(ls.value)) |v_ssa| {
                try value.addArg(v_ssa, func.allocator);
            }
        },
        .list_len, .list_free => |ll| {
            if (ir_to_ssa.get(ll.handle)) |h_ssa| {
                try value.addArg(h_ssa, func.allocator);
            }
        },
        .list_data_ptr => |ldp| {
            if (ir_to_ssa.get(ldp.handle)) |h_ssa| {
                try value.addArg(h_ssa, func.allocator);
            }
        },
        .list_byte_size => |lbs| {
            if (ir_to_ssa.get(lbs.handle)) |h_ssa| {
                try value.addArg(h_ssa, func.allocator);
            }
        },

        .map_set => |ms| {
            if (ir_to_ssa.get(ms.handle)) |h_ssa| {
                try value.addArg(h_ssa, func.allocator);
            }
            if (ir_to_ssa.get(ms.key_ptr)) |kp_ssa| {
                try value.addArg(kp_ssa, func.allocator);
            }
            if (ir_to_ssa.get(ms.key_len)) |kl_ssa| {
                try value.addArg(kl_ssa, func.allocator);
            }
            if (ir_to_ssa.get(ms.value)) |v_ssa| {
                try value.addArg(v_ssa, func.allocator);
            }
        },
        .map_get => |mg| {
            if (ir_to_ssa.get(mg.handle)) |h_ssa| {
                try value.addArg(h_ssa, func.allocator);
            }
            if (ir_to_ssa.get(mg.key_ptr)) |kp_ssa| {
                try value.addArg(kp_ssa, func.allocator);
            }
            if (ir_to_ssa.get(mg.key_len)) |kl_ssa| {
                try value.addArg(kl_ssa, func.allocator);
            }
        },
        .map_has => |mh| {
            if (ir_to_ssa.get(mh.handle)) |h_ssa| {
                try value.addArg(h_ssa, func.allocator);
            }
            if (ir_to_ssa.get(mh.key_ptr)) |kp_ssa| {
                try value.addArg(kp_ssa, func.allocator);
            }
            if (ir_to_ssa.get(mh.key_len)) |kl_ssa| {
                try value.addArg(kl_ssa, func.allocator);
            }
        },
        .map_size, .map_free => |mz| {
            if (ir_to_ssa.get(mz.handle)) |h_ssa| {
                try value.addArg(h_ssa, func.allocator);
            }
        },

        .str_concat => |sc| {
            if (ir_to_ssa.get(sc.left)) |l_ssa| {
                try value.addArg(l_ssa, func.allocator);
            }
            if (ir_to_ssa.get(sc.right)) |r_ssa| {
                try value.addArg(r_ssa, func.allocator);
            }
        },

        .file_read => |fr| {
            if (ir_to_ssa.get(fr.path)) |p_ssa| {
                try value.addArg(p_ssa, func.allocator);
            }
        },
        .file_write => |fw| {
            if (ir_to_ssa.get(fw.path)) |p_ssa| {
                try value.addArg(p_ssa, func.allocator);
            }
            if (ir_to_ssa.get(fw.data_ptr)) |dp_ssa| {
                try value.addArg(dp_ssa, func.allocator);
            }
            if (ir_to_ssa.get(fw.data_len)) |dl_ssa| {
                try value.addArg(dl_ssa, func.allocator);
            }
        },
        .file_exists => |fe| {
            if (ir_to_ssa.get(fe.path)) |p_ssa| {
                try value.addArg(p_ssa, func.allocator);
            }
        },
        .file_free => |ff| {
            if (ir_to_ssa.get(ff.ptr)) |p_ssa| {
                try value.addArg(p_ssa, func.allocator);
            }
        },
        .file_write_list_bytes => |fwlb| {
            if (ir_to_ssa.get(fwlb.path)) |p_ssa| {
                try value.addArg(p_ssa, func.allocator);
            }
            if (ir_to_ssa.get(fwlb.handle)) |h_ssa| {
                try value.addArg(h_ssa, func.allocator);
            }
        },

        .args_get => |ag| {
            if (ir_to_ssa.get(ag.index)) |i_ssa| {
                try value.addArg(i_ssa, func.allocator);
            }
        },

        .convert => |cv| {
            if (ir_to_ssa.get(cv.operand)) |op_ssa| {
                try value.addArg(op_ssa, func.allocator);
            }
        },
        .ptr_cast => |pc| {
            if (ir_to_ssa.get(pc.operand)) |op_ssa| {
                try value.addArg(op_ssa, func.allocator);
            }
        },

        .nop => {},

        // Terminators handled elsewhere
        .branch, .jump, .ret => unreachable,
    }

    return value_id;
}

// ============================================================================
// Helper Functions
// ============================================================================

fn alignTo(value: u32, alignment: u32) u32 {
    return (value + alignment - 1) & ~(alignment - 1);
}

fn convertStackOffset(x86_offset: i32, stack_size: u32) u12 {
    // Convert negative rbp-relative offset to positive sp-relative
    const abs_offset: u32 = @intCast(-x86_offset);
    const sp_relative = stack_size - abs_offset;
    return @intCast(sp_relative / 8);
}

// ============================================================================
// Public Entry Points
// ============================================================================

pub fn compileFile(allocator: Allocator, path: []const u8) CompileResult {
    return compileWithOptions(allocator, .{ .input_path = path });
}

pub fn compileWithOptions(allocator: Allocator, options: CompileOptions) CompileResult {
    var driver = Driver.init(allocator, options);
    defer driver.deinit();
    return driver.compile();
}

// ============================================================================
// Tests
// ============================================================================

test "Location type" {
    const reg_loc = Location{ .reg = 5 };
    try std.testing.expect(reg_loc.isReg());
    try std.testing.expectEqual(@as(?u8, 5), reg_loc.getReg());
    try std.testing.expectEqual(@as(?i32, null), reg_loc.getStack());

    const stack_loc = Location{ .stack = -16 };
    try std.testing.expect(!stack_loc.isReg());
    try std.testing.expectEqual(@as(?u8, null), stack_loc.getReg());
    try std.testing.expectEqual(@as(?i32, -16), stack_loc.getStack());
}

test "alignTo" {
    try std.testing.expectEqual(@as(u32, 0), alignTo(0, 16));
    try std.testing.expectEqual(@as(u32, 16), alignTo(1, 16));
    try std.testing.expectEqual(@as(u32, 16), alignTo(16, 16));
    try std.testing.expectEqual(@as(u32, 32), alignTo(17, 16));
}
