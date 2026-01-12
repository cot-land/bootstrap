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

    /// Main compilation entry point
    pub fn compile(self: *Driver) CompileResult {
        // Phase 1: Read source file
        const file = std.fs.cwd().openFile(self.options.input_path, .{}) catch {
            std.debug.print("Error: cannot open {s}\n", .{self.options.input_path});
            return .{ .success = false, .error_count = 1 };
        };
        defer file.close();

        const content = file.readToEndAlloc(self.allocator, 1024 * 1024 * 10) catch {
            std.debug.print("Error: cannot read {s}\n", .{self.options.input_path});
            return .{ .success = false, .error_count = 1 };
        };

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
            ssa_func.frame_size = ir_func.frame_size;

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

        // Create SSA blocks for each IR block
        for (ir_func.blocks, 0..) |_, idx| {
            const block_id = func.newBlock();
            try ir_block_to_ssa.put(@intCast(idx), block_id);
        }

        // Convert each IR node - handle terminators specially (Go-style)
        for (ir_func.nodes, 0..) |*node, idx| {
            const ssa_block_id = ir_block_to_ssa.get(node.block) orelse 0;
            var ssa_block = func.getBlock(ssa_block_id);

            switch (node.op) {
                // Terminators set block metadata, not values
                .branch => {
                    // args[0] = condition, args[1] = then_block, args[2] = else_block
                    ssa_block.kind = .@"if";

                    // Get condition SSA value
                    if (node.args_len >= 1) {
                        if (ir_to_ssa.get(node.args()[0])) |cond_ssa| {
                            ssa_block.setControl(cond_ssa);
                        }
                    }

                    // Set successors (then_block = succs[0], else_block = succs[1])
                    if (node.args_len >= 3) {
                        const then_ir_block = node.args()[1];
                        const else_ir_block = node.args()[2];
                        if (ir_block_to_ssa.get(then_ir_block)) |then_ssa| {
                            _ = ssa_block.addSucc(then_ssa);
                        }
                        if (ir_block_to_ssa.get(else_ir_block)) |else_ssa| {
                            _ = ssa_block.addSucc(else_ssa);
                        }
                    }
                },

                .jump => {
                    // aux = target block
                    ssa_block.kind = .plain;
                    const target_ir_block: u32 = @intCast(node.aux);
                    if (ir_block_to_ssa.get(target_ir_block)) |target_ssa| {
                        _ = ssa_block.addSucc(target_ssa);
                    }
                },

                .ret => {
                    ssa_block.kind = .ret;
                    // args[0] = return value (if any)
                    if (node.args_len >= 1) {
                        if (ir_to_ssa.get(node.args()[0])) |ret_val| {
                            ssa_block.setControl(ret_val);
                        }
                    }
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
        // +16 for fp/lr, +32 for spill slots (frame_size already includes space for struct return temps)
        // Spill padding ensures spill slots don't overlap with locals
        const spill_padding: u32 = 32; // 4 spill slots
        const stack_size = alignTo(func.frame_size + 16 + spill_padding, 16);

        // Create CodeGen with integrated register allocation
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
                    // B (unconditional branch)
                    try aarch64.bImm(buf, 0);
                    try jump_patches.append(self.allocator, .{
                        .patch_offset = @intCast(buf.pos()),
                        .target_block = target,
                    });
                }
            } else if (block.kind == .@"if" and block.numSuccs() >= 2 and block.control != ssa.null_value) {
                const cond_mcv = cg.getValue(block.control);
                try cg.loadToReg(arm64_codegen.scratch0, cond_mcv);
                // CBZ/CBNZ - if zero branch to else, otherwise fall through to then
                // Or use CMP + conditional branch

                const then_block = block.succs()[0].block;
                const else_block = block.succs()[1].block;
                const next_block: ?u32 = if (block_idx + 1 < func.blocks.items.len)
                    @intCast(block_idx + 1)
                else
                    null;

                if (next_block != null and else_block == next_block.?) {
                    // CBNZ to then_block, fallthrough to else
                    try aarch64.cbnz(buf, arm64_codegen.scratch0, 0);
                    try jump_patches.append(self.allocator, .{
                        .patch_offset = @intCast(buf.pos()),
                        .target_block = then_block,
                    });
                } else {
                    // CBNZ to then_block, B to else_block
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
            // ARM64 branch offset is relative to instruction address (patch_offset - 4)
            const inst_addr = patch.patch_offset - 4;
            const rel_offset: i32 = (@as(i32, @intCast(target_offset)) - @as(i32, @intCast(inst_addr))) >> 2;
            aarch64.patchBranch(buf, patch.patch_offset, rel_offset);
        }
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
                    std.debug.print("    [{d}] {s}", .{ i, @tagName(node.op) });
                    if (node.args_len > 0) {
                        std.debug.print(" args=[", .{});
                        const args = node.args();
                        for (args, 0..) |arg, j| {
                            if (j > 0) std.debug.print(",", .{});
                            std.debug.print("{d}", .{arg});
                        }
                        std.debug.print("]", .{});
                    }
                    if (node.aux != 0) {
                        std.debug.print(" aux={d}", .{node.aux});
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
    const ssa_op: ssa.Op = switch (node.op) {
        // Constants
        .const_int => .const_int,
        .const_bool => .const_bool,
        .const_float => .const_float,
        .const_null => .const_nil,
        .const_slice => .const_slice,

        // Arithmetic
        .add => .add,
        .sub => .sub,
        .mul => .mul,
        .div => .div,
        .mod => .mod,
        .neg => .neg,

        // Comparison
        .eq => .eq,
        .ne => .ne,
        .lt => .lt,
        .le => .le,
        .gt => .gt,
        .ge => .ge,

        // Logical
        .@"and" => .@"and",
        .@"or" => .@"or",
        .not => .not,

        // Memory
        .local => .load, // Load local variable (aux = local index)
        .load => .load,
        .store => .store,
        .addr_local => .addr,
        .addr_field => .field, // Field address becomes field op in SSA
        .ptr_field => .ptr_field,

        // Function
        .call => .call,
        .param => .arg,
        .select => .select,

        // Struct/Array
        .field => .field,
        .index => .index,
        .addr_index => .index, // Dynamic array indexing becomes index op

        // Slice operations
        .slice => .slice_make,
        .slice_index => .slice_index,

        // Union operations
        .union_init => .union_init,
        .union_tag => .union_tag,
        .union_payload => .union_payload,

        // Map operations (FFI)
        .map_new => .map_new,
        .map_set => .map_set,
        .map_get => .map_get,
        .map_has => .map_has,
        .map_size => .map_size,
        .map_free => .map_free,

        // List operations (FFI)
        .list_new => .list_new,
        .list_push => .list_push,
        .list_get => .list_get,
        .list_len => .list_len,
        .list_free => .list_free,

        // String operations
        .str_concat => .str_concat,

        else => .copy,
    };

    const value_id = try func.newValue(ssa_op, node.type_idx, block);
    var value = func.getValue(value_id);

    // Copy auxiliary data
    value.aux_int = node.aux;
    if (node.aux_str.len > 0) {
        value.aux_str = node.aux_str;
    }

    // Convert arguments based on op type
    switch (node.op) {
        .local => {
            // local: aux = local index (stored as arg[0] for codegen)
            value.args_storage[0] = @intCast(node.aux); // local index from aux
            value.args_len = 1;
        },
        .load => {
            // load: args[0] = local index (raw)
            if (node.args_len > 0) {
                value.args_storage[0] = node.args()[0]; // local index, raw
                value.args_len = 1;
            }
        },
        .store => {
            // store: args[0] = local index (raw), args[1] = value to store (SSA ref)
            // aux_int = field offset (already copied from node.aux above)
            if (node.args_len > 0) {
                value.args_storage[0] = node.args()[0]; // local index, raw
                value.args_len = 1;
            }
            if (node.args_len > 1) {
                if (ir_to_ssa.get(node.args()[1])) |ssa_val| {
                    value.args_storage[1] = ssa_val;
                    value.args_len = 2;
                }
            }
        },
        .field, .ptr_field, .addr_field => {
            // field/ptr_field/addr_field: args[0] = local index (raw, not SSA ref), aux = field offset
            // Keep args[0] as local index directly
            if (node.args_len > 0) {
                value.args_storage[0] = node.args()[0]; // local index, not SSA converted
                value.args_len = 1;
            }
            // aux_int already copied above (contains field offset)
        },
        .slice => {
            // slice: args[0] = local index (raw), args[1] = start (SSA), args[2] = end (SSA)
            // aux = element size
            if (node.args_len > 0) {
                value.args_storage[0] = node.args()[0]; // local index, raw
            }
            if (node.args_len > 1) {
                if (ir_to_ssa.get(node.args()[1])) |ssa_val| {
                    value.args_storage[1] = ssa_val; // start value (SSA ref)
                }
            }
            if (node.args_len > 2) {
                if (ir_to_ssa.get(node.args()[2])) |ssa_val| {
                    value.args_storage[2] = ssa_val; // end value (SSA ref)
                }
            }
            value.args_len = 3;
        },
        .slice_index => {
            // slice_index: args[0] = local index (raw), args[1] = index (SSA)
            // aux = element size
            if (node.args_len > 0) {
                value.args_storage[0] = node.args()[0]; // local index, raw
            }
            if (node.args_len > 1) {
                if (ir_to_ssa.get(node.args()[1])) |ssa_val| {
                    value.args_storage[1] = ssa_val; // index value (SSA ref)
                }
            }
            value.args_len = 2;
        },
        .index, .addr_index => {
            // index/addr_index: args[0] = local index (raw), args[1] = index value (SSA)
            // aux = element size
            if (node.args_len > 0) {
                value.args_storage[0] = node.args()[0]; // local index, raw
            }
            if (node.args_len > 1) {
                if (ir_to_ssa.get(node.args()[1])) |ssa_val| {
                    value.args_storage[1] = ssa_val; // index value (SSA ref)
                }
            }
            value.args_len = 2;
        },
        else => {
            // All other ops: convert all args to SSA refs
            var arg_count: u8 = 0;
            for (node.args()) |ir_arg| {
                if (ir_to_ssa.get(ir_arg)) |ssa_arg| {
                    if (arg_count < 3) {
                        value.args_storage[arg_count] = ssa_arg;
                        arg_count += 1;
                    }
                }
            }
            value.args_len = arg_count;
        },
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
