///! Compilation driver - orchestrates the full pipeline.
///!
///! Inspired by:
///! - Go: cmd/compile/internal/gc/main.go (phase orchestration)
///! - Zig: src/Compilation.zig (configuration object pattern)
///! - Kotlin: AbstractCliPipeline (phased execution)
///! - Roc: crates/compiler/build (explicit linking phase)
///!
///! Pipeline: Source → Scan → Parse → Check → IR → SSA → Codegen → Object → Link

const std = @import("std");
const builtin = @import("builtin");

const source = @import("source.zig");
const scanner = @import("scanner.zig");
const parser = @import("parser.zig");
const errors = @import("errors.zig");
const ast = @import("ast.zig");
const types = @import("types.zig");
const check = @import("check.zig");
const ir = @import("ir.zig");
const lower = @import("lower.zig");
const ssa = @import("ssa.zig");
const be = @import("codegen/backend.zig");
const x86_64 = @import("codegen/x86_64.zig");
const aarch64 = @import("codegen/aarch64.zig");
const object = @import("codegen/object.zig");
const debug = @import("debug.zig");
const regalloc = @import("regalloc.zig");

const Allocator = std.mem.Allocator;

// Scoped logger for driver
const log = debug.scoped(.codegen);

// Branch patch info for fixing branch offsets after code generation
const BranchPatch = struct {
    position: u32,        // Byte offset in code buffer where offset needs patching
    is_conditional: bool, // true for jcc/b.cond, false for jmp/b
    target_block: u32,    // Target block ID
};

// ============================================================================
// Frame Layout Constants - CRITICAL FOR PREVENTING MEMORY CORRUPTION
// ============================================================================
//
// These constants define the stack frame layout for each architecture.
// NEVER use magic numbers for stack offsets - always use these constants.
//
// AArch64 Stack Layout (after prologue with calls):
//   [sp + 0]                    = saved x29 (frame pointer)
//   [sp + 8]                    = saved x30 (link register / return address)
//   [sp + AARCH64_SAVED_REGS]   = start of local variables
//   [sp + frame_size + 16]      = end of locals (original sp before sub)
//
// x86_64 Stack Layout (after prologue):
//   [rbp + 0]                   = saved rbp (old frame pointer)
//   [rbp + 8]                   = return address (pushed by call)
//   [rbp - 8]                   = first local variable
//   [rbp - frame_size]          = end of locals
//
pub const FrameLayout = struct {
    // AArch64: fp (x29) + lr (x30) = 16 bytes saved by stp instruction
    pub const AARCH64_SAVED_REGS: i32 = 16;

    // x86_64: rbp is saved, return address is at rbp+8
    // Locals are at negative offsets from rbp, no adjustment needed
    pub const X86_64_SAVED_REGS: i32 = 0;

    /// Convert x86-style negative offset to AArch64 positive sp-relative offset.
    /// This accounts for:
    /// 1. The frame_size (allocated stack space)
    /// 2. The saved registers (fp + lr = 16 bytes)
    ///
    /// Example: local at x86 offset -8 with frame_size 16:
    ///   result = 16 + (-8) + 16 = 24
    ///   This places the local at [sp + 24], safely past saved regs at [sp + 0..15]
    pub fn aarch64LocalOffset(x86_offset: i32, frame_size: u32) i32 {
        const result = @as(i32, @intCast(frame_size)) + x86_offset + AARCH64_SAVED_REGS;
        // Safety assertion: offset must not overlap with saved registers
        std.debug.assert(result >= AARCH64_SAVED_REGS);
        return result;
    }

    /// Get x86_64 local offset (no conversion needed, locals are at negative offsets from rbp)
    pub fn x86_64LocalOffset(x86_offset: i32) i32 {
        return x86_offset;
    }
};

// ============================================================================
// Storage Manager - Tracks where each SSA value is stored
// ============================================================================
//
// This replaces ad-hoc scratch slot handling with systematic value tracking.
// Every value-producing operation gets a stack slot allocated automatically.
// When a value is needed as an operand, we load from its assigned slot.
//
// Benefits:
// - No more forgetting to handle new value-producing ops
// - Prevents value clobbering across function calls
// - Serves as blueprint for self-hosted cot compiler
//
// Design inspired by Roc's storage.rs pattern.
//
pub const StorageManager = struct {
    // Maps value_id -> stack offset (negative offset from rbp for x86_64)
    value_storage: std.AutoHashMap(u32, i32),
    // Next available scratch slot offset (grows more negative)
    // Starts at -0x80 to leave room for locals above
    next_slot: i32,
    // Allocator for the hash map
    allocator: std.mem.Allocator,

    // Scratch area starts at -0x80 from rbp (leaves 128 bytes for locals)
    pub const SCRATCH_BASE: i32 = -0x80;
    // Each slot is 8 bytes
    pub const SLOT_SIZE: i32 = 8;

    pub fn init(allocator: std.mem.Allocator) StorageManager {
        return .{
            .value_storage = std.AutoHashMap(u32, i32).init(allocator),
            .next_slot = SCRATCH_BASE,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *StorageManager) void {
        self.value_storage.deinit();
    }

    /// Reset for a new function
    pub fn reset(self: *StorageManager) void {
        self.value_storage.clearRetainingCapacity();
        self.next_slot = SCRATCH_BASE;
    }

    /// Allocate storage for a value. Returns the stack offset.
    /// Idempotent - if already allocated, returns existing slot.
    pub fn allocate(self: *StorageManager, value_id: u32) !i32 {
        if (self.value_storage.get(value_id)) |existing| {
            return existing;
        }
        const slot = self.next_slot;
        self.next_slot -= SLOT_SIZE;
        try self.value_storage.put(value_id, slot);
        return slot;
    }

    /// Get storage for a value. Returns null if not allocated.
    pub fn get(self: *const StorageManager, value_id: u32) ?i32 {
        return self.value_storage.get(value_id);
    }

    /// Check if a value has storage allocated
    pub fn has(self: *const StorageManager, value_id: u32) bool {
        return self.value_storage.contains(value_id);
    }

    /// Get the minimum stack size needed for scratch slots
    /// (positive value, represents how far below rbp we go)
    pub fn requiredStackSize(self: *const StorageManager) u32 {
        // next_slot is negative, e.g., -0x100 means we need 0x100 bytes
        const used = SCRATCH_BASE - self.next_slot;
        // Add base offset (0x80) plus some padding
        return @intCast(@max(128, @as(u32, @intCast(-SCRATCH_BASE)) + @as(u32, @intCast(used))));
    }

    /// Convert x86_64 offset to AArch64 sp-relative offset
    /// For scratch slots: offset is negative, we convert to positive sp-relative
    /// Scratch slots are placed AFTER locals to avoid overlap
    pub fn aarch64Offset(self: *const StorageManager, x86_offset: i32, frame_size: u32) u12 {
        _ = self;
        // x86 offset: -0x80 - index * 8
        // So index = (SCRATCH_BASE - x86_offset) / SLOT_SIZE
        const index: i32 = @divExact(SCRATCH_BASE - x86_offset, SLOT_SIZE);

        // AArch64 layout: [sp+0]=fp, [sp+8]=lr, [sp+16..frame_size+16]=locals
        // Put scratch AFTER locals to avoid overlap
        // base = (frame_size / 8) + 2 (2 = 16 bytes for saved fp/lr, divided by 8)
        const base: u12 = @intCast(@divExact(@as(i32, @intCast(frame_size)), 8) + 2);
        return base + @as(u12, @intCast(index));
    }
};

// ============================================================================
// Compilation Options (Zig pattern: single config struct)
// ============================================================================

pub const Target = struct {
    arch: be.Arch,
    os: be.OS,

    pub fn native() Target {
        return .{
            .arch = switch (builtin.cpu.arch) {
                .x86_64 => .x86_64,
                .aarch64 => .aarch64,
                else => .x86_64, // Fallback
            },
            .os = switch (builtin.os.tag) {
                .linux => .linux,
                .macos => .macos,
                .windows => .windows,
                else => .linux, // Fallback
            },
        };
    }
};

pub const OutputKind = enum {
    /// Produce executable binary
    executable,
    /// Produce object file (.o)
    object,
    /// Produce assembly listing
    assembly,
};

pub const CompileOptions = struct {
    /// Source file path
    input_path: []const u8,
    /// Output file path (null = derive from input)
    output_path: ?[]const u8 = null,
    /// Target architecture and OS
    target: Target = Target.native(),
    /// What to produce
    output_kind: OutputKind = .executable,
    /// Optimization level (0 = none, 1 = basic, 2 = full)
    opt_level: u8 = 0,
    /// Include debug info
    debug_info: bool = true,
    /// Verbose output
    verbose: bool = false,
    /// Debug: dump IR after lowering
    debug_ir: bool = false,
    /// Debug: dump SSA after conversion
    debug_ssa: bool = false,
    /// Debug: dump codegen operations
    debug_codegen: bool = false,
    /// Debug: run objdump on output
    disasm: bool = false,

    /// Derive output path from input if not specified
    pub fn getOutputPath(self: *const CompileOptions) []const u8 {
        if (self.output_path) |p| return p;

        // Strip extension and add appropriate suffix
        const base = std.fs.path.stem(self.input_path);
        return switch (self.output_kind) {
            .executable => base,
            .object => base, // Would need .o suffix
            .assembly => base, // Would need .s suffix
        };
    }
};

// ============================================================================
// Compilation Result
// ============================================================================

pub const CompileError = error{
    ReadError,
    ScanError,
    ParseError,
    TypeError,
    CodegenError,
    LinkError,
    OutOfMemory,
};

pub const CompileResult = struct {
    /// Whether compilation succeeded
    success: bool,
    /// Output file path (if successful)
    output_path: ?[]const u8 = null,
    /// Number of errors encountered
    error_count: u32 = 0,
    /// Number of warnings
    warning_count: u32 = 0,
};

// ============================================================================
// Compilation Phases (Kotlin pattern: explicit phases)
// ============================================================================

pub const Phase = enum {
    read,
    scan,
    parse,
    check,
    ir_gen,
    ssa_build,
    codegen,
    link,

    pub fn name(self: Phase) []const u8 {
        return switch (self) {
            .read => "read",
            .scan => "scan",
            .parse => "parse",
            .check => "typecheck",
            .ir_gen => "ir",
            .ssa_build => "ssa",
            .codegen => "codegen",
            .link => "link",
        };
    }
};

// ============================================================================
// Driver
// ============================================================================

pub const Driver = struct {
    allocator: Allocator,
    options: CompileOptions,

    // Phase artifacts
    src: ?*source.Source = null,
    tree: ?*ast.Ast = null,
    type_reg: ?*types.TypeRegistry = null,
    ir_data: ?*ir.IR = null,
    type_checker: ?*check.Checker = null,
    global_scope: ?*check.Scope = null,

    // Diagnostics
    err_reporter: ?*errors.ErrorReporter = null,
    current_phase: Phase = .read,

    // Value storage tracking for codegen (prevents value clobbering)
    storage: StorageManager,

    // Register allocator for optimal register assignment (optional, created during codegen)
    reg_alloc: ?regalloc.RegAllocator = null,

    pub fn init(allocator: Allocator, options: CompileOptions) Driver {
        return .{
            .allocator = allocator,
            .options = options,
            .storage = StorageManager.init(allocator),
            .reg_alloc = null,
        };
    }

    pub fn deinit(self: *Driver) void {
        // Clean up register allocator
        if (self.reg_alloc) |*ra| {
            ra.deinit();
        }

        // Clean up storage manager
        self.storage.deinit();

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
        if (self.ir_data) |i| {
            // TODO: IR.deinit() when implemented
            self.allocator.destroy(i);
        }
        if (self.type_checker) |tc| {
            tc.deinit();
            self.allocator.destroy(tc);
        }
        if (self.global_scope) |gs| {
            gs.deinit();
            self.allocator.destroy(gs);
        }
        if (self.err_reporter) |er| {
            // ErrorReporter has no deinit (stack-based)
            self.allocator.destroy(er);
        }
    }

    /// Run full compilation pipeline
    pub fn compile(self: *Driver) CompileResult {
        if (self.options.verbose) {
            std.debug.print("Compiling: {s}\n", .{self.options.input_path});
            std.debug.print("Target: {s}-{s}\n", .{
                @tagName(self.options.target.arch),
                @tagName(self.options.target.os),
            });
        }

        // Phase 1: Read source
        self.current_phase = .read;
        self.src = self.readSource() catch |err| {
            std.debug.print("Error reading {s}: {}\n", .{ self.options.input_path, err });
            return .{ .success = false, .error_count = 1 };
        };

        // Initialize error reporter
        self.err_reporter = self.allocator.create(errors.ErrorReporter) catch {
            return .{ .success = false, .error_count = 1 };
        };
        self.err_reporter.?.* = errors.ErrorReporter.init(self.src.?, null);

        // Phase 2: Parse
        self.current_phase = .parse;
        self.tree = self.parse() catch {
            return self.errorResult();
        };

        if (self.err_reporter.?.count > 0) {
            return self.errorResult();
        }

        // Phase 3: Type check
        self.current_phase = .check;
        self.type_reg = self.typeCheck() catch {
            return self.errorResult();
        };

        if (self.err_reporter.?.count > 0) {
            return self.errorResult();
        }

        // Phase 4: Generate IR
        self.current_phase = .ir_gen;
        self.ir_data = self.generateIR() catch {
            return self.errorResult();
        };

        // Phase 5: Build SSA
        self.current_phase = .ssa_build;
        var ssa_funcs = self.buildSSA() catch {
            return self.errorResult();
        };
        defer {
            for (ssa_funcs.items) |*f| {
                f.deinit();
            }
            ssa_funcs.deinit(self.allocator);
        }

        // Phase 6: Code generation
        self.current_phase = .codegen;
        const obj_path = self.generateCode(&ssa_funcs) catch {
            return self.errorResult();
        };

        // Debug: run disassembler on object file
        if (self.options.disasm) {
            self.runDisasm(obj_path);
        }

        // Phase 7: Link (if producing executable)
        if (self.options.output_kind == .executable) {
            self.current_phase = .link;
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

        return .{
            .success = true,
            .output_path = obj_path,
            .error_count = 0,
        };
    }

    fn errorResult(self: *Driver) CompileResult {
        const count = if (self.err_reporter) |er| er.count else 1;
        return .{
            .success = false,
            .error_count = count,
        };
    }

    fn runDisasm(self: *Driver, obj_path: []const u8) void {
        _ = self;
        std.debug.print("\n=== DISASSEMBLY ({s}) ===\n", .{obj_path});

        // Run objdump -d on the object file
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
    // Phase Implementations
    // ========================================================================

    fn readSource(self: *Driver) !*source.Source {
        const file = std.fs.cwd().openFile(self.options.input_path, .{}) catch {
            return error.ReadError;
        };
        defer file.close();

        const content = file.readToEndAlloc(self.allocator, 1024 * 1024 * 10) catch {
            return error.ReadError;
        };

        const src = try self.allocator.create(source.Source);
        src.* = source.Source.init(self.allocator, self.options.input_path, content);

        if (self.options.verbose) {
            std.debug.print("  Read {d} bytes\n", .{content.len});
        }

        return src;
    }

    fn parse(self: *Driver) !*ast.Ast {
        const tree = try self.allocator.create(ast.Ast);
        tree.* = ast.Ast.init(self.allocator);

        // Create scanner from source
        var scan = scanner.Scanner.init(self.src.?);

        var p = parser.Parser.init(self.allocator, &scan, tree, self.err_reporter.?);
        _ = p.parseFile() catch {
            return error.ParseError;
        };

        if (self.options.verbose) {
            std.debug.print("  Parsed {d} nodes\n", .{tree.nodes.items.len});
        }

        return tree;
    }

    fn typeCheck(self: *Driver) !*types.TypeRegistry {
        const reg = try self.allocator.create(types.TypeRegistry);
        reg.* = try types.TypeRegistry.init(self.allocator);

        // Create global scope for type checking (heap-allocated for persistence)
        const global_scope = try self.allocator.create(check.Scope);
        global_scope.* = check.Scope.init(self.allocator, null);
        self.global_scope = global_scope;

        // Create type checker (heap-allocated for persistence)
        const checker = try self.allocator.create(check.Checker);
        checker.* = check.Checker.init(
            self.allocator,
            self.tree.?,
            reg,
            self.err_reporter.?,
            global_scope,
        );
        self.type_checker = checker;

        checker.checkFile() catch {
            return error.TypeError;
        };

        // Only print success if no errors
        if (self.options.verbose and self.err_reporter.?.count == 0) {
            std.debug.print("  Type check passed\n", .{});
        }

        return reg;
    }

    fn generateIR(self: *Driver) !*ir.IR {
        const ir_data = try self.allocator.create(ir.IR);

        // Use Lowerer to convert AST to IR
        ir_data.* = try lower.lowerAst(
            self.allocator,
            self.tree.?,
            self.type_reg.?,
            self.err_reporter.?,
            self.type_checker.?,
        );

        if (self.options.verbose) {
            std.debug.print("  Generated IR ({d} functions)\n", .{ir_data.funcs.len});
        }

        // Debug: dump IR
        if (self.options.debug_ir) {
            self.dumpIR(ir_data);
        }

        return ir_data;
    }

    fn dumpIR(self: *Driver, ir_data: *ir.IR) void {
        _ = self;
        std.debug.print("\n=== IR DUMP ===\n", .{});

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
        std.debug.print("=== END IR ===\n\n", .{});
    }

    fn buildSSA(self: *Driver) !std.ArrayList(ssa.Func) {
        var funcs: std.ArrayList(ssa.Func) = .{ .items = &.{}, .capacity = 0 };

        const ir_data = self.ir_data orelse {
            // No IR - create empty main function
            const main_func = ssa.Func.init(self.allocator, "main", 0, types.TypeRegistry.VOID);
            try funcs.append(self.allocator, main_func);
            return funcs;
        };

        // Convert each IR function to SSA
        for (ir_data.funcs) |ir_func| {
            var ssa_func = ssa.Func.init(
                self.allocator,
                ir_func.name,
                ir_func.type_idx,
                ir_func.return_type,
            );

            // Store parameter count and frame size for code generation
            ssa_func.param_count = @intCast(ir_func.params.len);
            ssa_func.frame_size = ir_func.frame_size;

            // Copy local variable info for codegen offset calculations
            var local_infos = std.ArrayList(ssa.LocalInfo){ .items = &.{}, .capacity = 0 };
            for (ir_func.locals) |local| {
                try local_infos.append(self.allocator, .{
                    .name = local.name,
                    .size = local.size,
                    .offset = local.offset,
                });
            }
            ssa_func.locals = try self.allocator.dupe(ssa.LocalInfo, local_infos.items);

            // Create SSA blocks for each IR block
            // Map from IR block index to SSA block index
            var ir_block_to_ssa = std.AutoHashMap(u32, u32).init(self.allocator);
            defer ir_block_to_ssa.deinit();

            for (ir_func.blocks, 0..) |_, ir_block_idx| {
                const ssa_block = ssa_func.newBlock();
                try ir_block_to_ssa.put(@intCast(ir_block_idx), ssa_block);
            }

            // Entry block is the SSA block corresponding to IR entry block
            ssa_func.entry = ir_block_to_ssa.get(ir_func.entry) orelse 0;

            // Map IR node indices to SSA value IDs
            var ir_to_ssa = std.AutoHashMap(u32, ssa.ValueID).init(self.allocator);
            defer ir_to_ssa.deinit();

            // Convert IR nodes to SSA values, placing them in correct blocks
            for (ir_func.nodes, 0..) |*ir_node, idx| {
                // Look up which SSA block this node belongs to
                const ssa_block = ir_block_to_ssa.get(ir_node.block) orelse 0;
                const ssa_id = try self.convertIRNodeToSSA(&ssa_func, ir_node, ir_func, ssa_block, &ir_to_ssa, &ir_block_to_ssa);
                try ir_to_ssa.put(@intCast(idx), ssa_id);
            }

            try funcs.append(self.allocator, ssa_func);
        }

        if (self.options.verbose) {
            std.debug.print("  Built SSA ({d} functions)\n", .{funcs.items.len});
        }

        // Debug: dump SSA
        if (self.options.debug_ssa) {
            self.dumpSSA(&funcs);
        }

        return funcs;
    }

    fn dumpSSA(self: *Driver, funcs: *std.ArrayList(ssa.Func)) void {
        _ = self;
        std.debug.print("\n=== SSA DUMP ===\n", .{});

        for (funcs.items) |*func| {
            std.debug.print("\nfunc {s} (entry=block{d}):\n", .{ func.name, func.entry });

            // Dump blocks
            for (func.blocks.items, 0..) |block, block_idx| {
                std.debug.print("  block{d}:\n", .{block_idx});

                // Dump values in this block
                for (block.values.items) |value_id| {
                    const value = func.getValue(value_id);
                    std.debug.print("    v{d} = {s}", .{ value_id, @tagName(value.op) });

                    // Print args
                    const args = value.args();
                    if (args.len > 0) {
                        std.debug.print(" (", .{});
                        for (args, 0..) |arg, i| {
                            if (i > 0) std.debug.print(", ", .{});
                            std.debug.print("v{d}", .{arg});
                        }
                        std.debug.print(")", .{});
                    }

                    // Print aux info
                    if (value.aux_int != 0) {
                        std.debug.print(" aux={d}", .{value.aux_int});
                    }
                    if (value.aux_str.len > 0) {
                        std.debug.print(" \"{s}\"", .{value.aux_str});
                    }
                    std.debug.print("\n", .{});
                }
            }
        }
        std.debug.print("=== END SSA ===\n\n", .{});
    }

    fn convertIRNodeToSSA(self: *Driver, func: *ssa.Func, node: *const ir.Node, ir_func: ir.Func, block: u32, ir_to_ssa: *std.AutoHashMap(u32, ssa.ValueID), ir_block_to_ssa: *std.AutoHashMap(u32, u32)) !ssa.ValueID {
        _ = self;

        // Handle load specially - if loading from a parameter, emit arg op
        if (node.op == .load) {
            const local_idx: u32 = @intCast(node.aux);
            if (local_idx < ir_func.params.len) {
                // This is a parameter - emit arg op instead of load
                const value_id = try func.newValue(.arg, node.type_idx, block);
                var value = func.getValue(value_id);
                value.aux_int = @intCast(local_idx);  // Parameter index
                return value_id;
            }
        }

        // Handle call specially - need to preserve function name and args
        if (node.op == .call) {
            const value_id = try func.newValue(.call, node.type_idx, block);
            var value = func.getValue(value_id);
            value.aux_str = node.aux_str;  // Function name
            value.aux_int = @intCast(node.args_len);  // Number of arguments

            // Store SSA value IDs of arguments in args_storage
            var arg_count: u8 = 0;
            for (node.args()) |ir_arg_idx| {
                if (ir_to_ssa.get(ir_arg_idx)) |ssa_arg_id| {
                    if (arg_count < 3) {
                        value.args_storage[arg_count] = ssa_arg_id;
                        arg_count += 1;
                    }
                }
            }
            value.args_len = arg_count;
            return value_id;
        }

        // Handle binary operations and comparisons - need to track operands
        if (node.op == .add or node.op == .sub or node.op == .mul or node.op == .div or
            node.op == .eq or node.op == .ne or node.op == .lt or node.op == .le or
            node.op == .gt or node.op == .ge or node.op == .@"or" or node.op == .@"and")
        {
            const ssa_op: ssa.Op = switch (node.op) {
                .add => .add,
                .sub => .sub,
                .mul => .mul,
                .div => .div,
                .eq => .eq,
                .ne => .ne,
                .lt => .lt,
                .le => .le,
                .gt => .gt,
                .ge => .ge,
                .@"or" => .@"or",
                .@"and" => .@"and",
                else => .add,
            };
            const value_id = try func.newValue(ssa_op, node.type_idx, block);
            var value = func.getValue(value_id);

            // Map IR args to SSA args
            var arg_count: u8 = 0;
            for (node.args()) |ir_arg_idx| {
                if (ir_to_ssa.get(ir_arg_idx)) |ssa_arg_id| {
                    if (arg_count < 3) {
                        value.args_storage[arg_count] = ssa_arg_id;
                        arg_count += 1;
                    }
                }
            }
            value.args_len = arg_count;
            return value_id;
        }

        // Handle return - may have an argument
        if (node.op == .ret) {
            const value_id = try func.newValue(.ret, node.type_idx, block);
            var value = func.getValue(value_id);
            if (node.args_len > 0) {
                if (ir_to_ssa.get(node.args()[0])) |ssa_arg_id| {
                    value.args_storage[0] = ssa_arg_id;
                    value.args_len = 1;
                }
            }
            return value_id;
        }

        // Handle select (ternary) - args[0] = cond, args[1] = then, args[2] = else
        if (node.op == .select) {
            const value_id = try func.newValue(.select, node.type_idx, block);
            var value = func.getValue(value_id);
            var arg_count: u8 = 0;
            for (node.args()) |ir_arg_idx| {
                if (ir_to_ssa.get(ir_arg_idx)) |ssa_arg_id| {
                    if (arg_count < 3) {
                        value.args_storage[arg_count] = ssa_arg_id;
                        arg_count += 1;
                    }
                }
            }
            value.args_len = arg_count;
            return value_id;
        }

        // Handle branch - conditional jump with true/false targets
        if (node.op == .branch) {
            const value_id = try func.newValue(.branch, node.type_idx, block);
            var value = func.getValue(value_id);
            // args[0] = condition, args[1] = true_block, args[2] = false_block (from IR)
            if (node.args_len > 0) {
                if (ir_to_ssa.get(node.args()[0])) |cond_id| {
                    value.args_storage[0] = cond_id;
                    value.args_len = 1;
                }
            }
            // Pack both block IDs into aux_int: lower 32 bits = true, upper 32 bits = false
            // Translate IR block IDs to SSA block IDs
            var true_block: u32 = 0;
            var false_block: u32 = 0;
            if (node.args_len > 1) {
                const ir_true_block = node.args()[1];
                true_block = ir_block_to_ssa.get(ir_true_block) orelse ir_true_block;
            }
            if (node.args_len > 2) {
                const ir_false_block = node.args()[2];
                false_block = ir_block_to_ssa.get(ir_false_block) orelse ir_false_block;
            }
            value.aux_int = @as(i64, true_block) | (@as(i64, false_block) << 32);
            return value_id;
        }

        // Handle jump - unconditional jump
        if (node.op == .jump) {
            const value_id = try func.newValue(.jump, node.type_idx, block);
            var value = func.getValue(value_id);
            // Translate IR block ID to SSA block ID
            const ir_target_block: u32 = @intCast(node.aux);
            const ssa_target_block = ir_block_to_ssa.get(ir_target_block) orelse ir_target_block;
            value.aux_int = @intCast(ssa_target_block);
            return value_id;
        }

        // Handle addr_field - load field from local at offset
        // Despite the name "addr_field", this is actually "load field from local"
        // args[0] = local index (raw), aux = field offset
        // Use .field op with local index in args[0]
        if (node.op == .addr_field) {
            const value_id = try func.newValue(.field, node.type_idx, block);
            var value = func.getValue(value_id);
            // Store local_idx in args_storage[0] as a raw value (not SSA ref)
            // and field_offset in aux_int
            if (node.args_len > 0) {
                value.args_storage[0] = node.args()[0];  // local index
                value.args_len = 1;
            }
            value.aux_int = node.aux;  // field offset
            return value_id;
        }

        // Handle field - direct field access
        // args[0] can be either:
        //   - a local index (for direct slice.len access)
        //   - an IR node index (for nested field access like span.start.offset)
        // We differentiate by checking if args[0] is in the ir_to_ssa map
        if (node.op == .field) {
            const value_id = try func.newValue(.field, node.type_idx, block);
            var value = func.getValue(value_id);
            if (node.args_len > 0) {
                const ir_arg = node.args()[0];
                // Check if this is an IR node reference that needs SSA conversion
                if (ir_to_ssa.get(@intCast(ir_arg))) |ssa_arg| {
                    // args[0] is an IR node index, convert to SSA value ID
                    value.args_storage[0] = ssa_arg;
                } else {
                    // args[0] is a raw local index, keep as is
                    value.args_storage[0] = ir_arg;
                }
                value.args_len = 1;
            }
            value.aux_int = node.aux;  // field offset
            return value_id;
        }

        // Handle ptr_field - load field through pointer
        // args[0] = local index holding pointer, aux = field offset
        if (node.op == .ptr_field) {
            const value_id = try func.newValue(.ptr_field, node.type_idx, block);
            var value = func.getValue(value_id);
            // Store local_idx in args_storage[0] as a raw value (not SSA ref)
            // and field_offset in aux_int
            if (node.args_len > 0) {
                value.args_storage[0] = node.args()[0]; // local index holding ptr
                value.args_len = 1;
            }
            value.aux_int = node.aux; // field offset
            return value_id;
        }

        // Handle slice - slice construction from array
        // IR args: [0] = local index (raw), [1] = start (IR node), [2] = end (IR node)
        // aux = element size
        if (node.op == .slice) {
            const value_id = try func.newValue(.slice_make, node.type_idx, block);
            var value = func.getValue(value_id);
            // args[0] is raw local index
            if (node.args_len > 0) {
                value.args_storage[0] = node.args()[0];  // local index (raw)
            }
            // args[1] is IR node ID for start that needs SSA conversion
            if (node.args_len > 1) {
                if (ir_to_ssa.get(node.args()[1])) |ssa_val| {
                    value.args_storage[1] = ssa_val;  // start value (SSA ref)
                }
            }
            // args[2] is IR node ID for end that needs SSA conversion
            if (node.args_len > 2) {
                if (ir_to_ssa.get(node.args()[2])) |ssa_val| {
                    value.args_storage[2] = ssa_val;  // end value (SSA ref)
                }
            }
            value.args_len = 3;
            value.aux_int = node.aux;  // element size
            return value_id;
        }

        // Handle addr_index - dynamic array indexing
        // args[0] = local index (raw), args[1] = index value (SSA ref), aux = elem_size
        if (node.op == .addr_index) {
            const value_id = try func.newValue(.index, node.type_idx, block);
            var value = func.getValue(value_id);
            // args[0] is raw local index
            if (node.args_len > 0) {
                value.args_storage[0] = node.args()[0];  // local index (raw)
            }
            // args[1] is IR node ID that needs SSA conversion
            if (node.args_len > 1) {
                if (ir_to_ssa.get(node.args()[1])) |ssa_val| {
                    value.args_storage[1] = ssa_val;  // index value (SSA ref)
                }
            }
            value.args_len = 2;
            value.aux_int = node.aux;  // element size
            return value_id;
        }

        // Handle slice_index - slice element access
        // args[0] = slice local index (raw), args[1] = index value (SSA ref), aux = elem_size
        if (node.op == .slice_index) {
            const value_id = try func.newValue(.slice_index, node.type_idx, block);
            var value = func.getValue(value_id);
            // args[0] is raw slice local index
            if (node.args_len > 0) {
                value.args_storage[0] = node.args()[0];  // slice local index (raw)
            }
            // args[1] is IR node ID for index that needs SSA conversion
            if (node.args_len > 1) {
                if (ir_to_ssa.get(node.args()[1])) |ssa_val| {
                    value.args_storage[1] = ssa_val;  // index value (SSA ref)
                }
            }
            value.args_len = 2;
            value.aux_int = node.aux;  // element size
            return value_id;
        }

        // Handle store - args[0] = local index (raw), args[1] = value (SSA ref)
        if (node.op == .store) {
            const value_id = try func.newValue(.store, node.type_idx, block);
            var value = func.getValue(value_id);
            // args[0] is raw local index
            if (node.args_len > 0) {
                value.args_storage[0] = node.args()[0];  // local index (raw)
            }
            // args[1] is IR node ID that needs SSA conversion
            if (node.args_len > 1) {
                if (ir_to_ssa.get(node.args()[1])) |ssa_val| {
                    value.args_storage[1] = ssa_val;  // value to store (SSA ref)
                }
            }
            value.args_len = 2;
            value.aux_int = node.aux;  // field offset
            return value_id;
        }

        // Handle union_init - args[0] = payload value (SSA ref), aux = variant index
        if (node.op == .union_init) {
            const value_id = try func.newValue(.union_init, node.type_idx, block);
            var value = func.getValue(value_id);
            value.aux_int = node.aux;  // variant index (tag)
            // args[0] is IR node ID for payload that needs SSA conversion
            if (node.args_len > 0) {
                if (ir_to_ssa.get(node.args()[0])) |ssa_val| {
                    value.args_storage[0] = ssa_val;  // payload value (SSA ref)
                    value.args_len = 1;
                }
            }
            return value_id;
        }

        // Handle union_tag - args[0] = union value (SSA ref)
        if (node.op == .union_tag) {
            const value_id = try func.newValue(.union_tag, node.type_idx, block);
            var value = func.getValue(value_id);
            // args[0] is IR node ID for union that needs SSA conversion
            if (node.args_len > 0) {
                if (ir_to_ssa.get(node.args()[0])) |ssa_val| {
                    value.args_storage[0] = ssa_val;  // union value (SSA ref)
                    value.args_len = 1;
                }
            }
            return value_id;
        }

        // Handle union_payload - args[0] = union value (SSA ref), aux = variant index
        if (node.op == .union_payload) {
            const value_id = try func.newValue(.union_payload, node.type_idx, block);
            var value = func.getValue(value_id);
            value.aux_int = node.aux;  // variant index
            // args[0] is IR node ID for union that needs SSA conversion
            if (node.args_len > 0) {
                if (ir_to_ssa.get(node.args()[0])) |ssa_val| {
                    value.args_storage[0] = ssa_val;  // union value (SSA ref)
                    value.args_len = 1;
                }
            }
            return value_id;
        }

        // Handle map_new - no args, creates new map
        if (node.op == .map_new) {
            const value_id = try func.newValue(.map_new, node.type_idx, block);
            return value_id;
        }

        // Handle map_set - args[0]=handle, args[1]=key_ptr, args[2]=key_len, args[3]=value
        if (node.op == .map_set) {
            const value_id = try func.newValue(.map_set, node.type_idx, block);
            var value = func.getValue(value_id);
            var arg_count: u8 = 0;
            for (node.args()) |ir_arg_idx| {
                if (ir_to_ssa.get(ir_arg_idx)) |ssa_arg_id| {
                    if (arg_count < 3) {
                        value.args_storage[arg_count] = ssa_arg_id;
                        arg_count += 1;
                    }
                }
            }
            value.args_len = arg_count;
            return value_id;
        }

        // Handle map_get - args[0]=handle, args[1]=key_ptr, args[2]=key_len
        if (node.op == .map_get) {
            const value_id = try func.newValue(.map_get, node.type_idx, block);
            var value = func.getValue(value_id);
            var arg_count: u8 = 0;
            for (node.args()) |ir_arg_idx| {
                if (ir_to_ssa.get(ir_arg_idx)) |ssa_arg_id| {
                    if (arg_count < 3) {
                        value.args_storage[arg_count] = ssa_arg_id;
                        arg_count += 1;
                    }
                }
            }
            value.args_len = arg_count;
            return value_id;
        }

        // Handle map_has - args[0]=handle, args[1]=key_ptr, args[2]=key_len
        if (node.op == .map_has) {
            const value_id = try func.newValue(.map_has, node.type_idx, block);
            var value = func.getValue(value_id);
            var arg_count: u8 = 0;
            for (node.args()) |ir_arg_idx| {
                if (ir_to_ssa.get(ir_arg_idx)) |ssa_arg_id| {
                    if (arg_count < 3) {
                        value.args_storage[arg_count] = ssa_arg_id;
                        arg_count += 1;
                    }
                }
            }
            value.args_len = arg_count;
            return value_id;
        }

        // Handle map_size - args[0]=handle
        if (node.op == .map_size) {
            const value_id = try func.newValue(.map_size, node.type_idx, block);
            var value = func.getValue(value_id);
            if (node.args_len > 0) {
                if (ir_to_ssa.get(node.args()[0])) |ssa_val| {
                    value.args_storage[0] = ssa_val;
                    value.args_len = 1;
                }
            }
            return value_id;
        }

        // Handle map_free - args[0]=handle
        if (node.op == .map_free) {
            const value_id = try func.newValue(.map_free, node.type_idx, block);
            var value = func.getValue(value_id);
            if (node.args_len > 0) {
                if (ir_to_ssa.get(node.args()[0])) |ssa_val| {
                    value.args_storage[0] = ssa_val;
                    value.args_len = 1;
                }
            }
            return value_id;
        }

        // Handle list_new - no args, creates new list
        if (node.op == .list_new) {
            const value_id = try func.newValue(.list_new, node.type_idx, block);
            return value_id;
        }

        // Handle list_push - args[0]=handle, args[1]=value
        if (node.op == .list_push) {
            const value_id = try func.newValue(.list_push, node.type_idx, block);
            var value = func.getValue(value_id);
            var arg_count: u8 = 0;
            for (node.args()) |ir_arg_idx| {
                if (ir_to_ssa.get(ir_arg_idx)) |ssa_arg_id| {
                    if (arg_count < 2) {
                        value.args_storage[arg_count] = ssa_arg_id;
                        arg_count += 1;
                    }
                }
            }
            value.args_len = arg_count;
            return value_id;
        }

        // Handle list_get - args[0]=handle, args[1]=index
        if (node.op == .list_get) {
            const value_id = try func.newValue(.list_get, node.type_idx, block);
            var value = func.getValue(value_id);
            var arg_count: u8 = 0;
            for (node.args()) |ir_arg_idx| {
                if (ir_to_ssa.get(ir_arg_idx)) |ssa_arg_id| {
                    if (arg_count < 2) {
                        value.args_storage[arg_count] = ssa_arg_id;
                        arg_count += 1;
                    }
                }
            }
            value.args_len = arg_count;
            return value_id;
        }

        // Handle list_len - args[0]=handle
        if (node.op == .list_len) {
            const value_id = try func.newValue(.list_len, node.type_idx, block);
            var value = func.getValue(value_id);
            if (node.args_len > 0) {
                if (ir_to_ssa.get(node.args()[0])) |ssa_val| {
                    value.args_storage[0] = ssa_val;
                    value.args_len = 1;
                }
            }
            return value_id;
        }

        // Handle list_free - args[0]=handle
        if (node.op == .list_free) {
            const value_id = try func.newValue(.list_free, node.type_idx, block);
            var value = func.getValue(value_id);
            if (node.args_len > 0) {
                if (ir_to_ssa.get(node.args()[0])) |ssa_val| {
                    value.args_storage[0] = ssa_val;
                    value.args_len = 1;
                }
            }
            return value_id;
        }

        // Handle str_concat - args[0]=str1_ptr, args[1]=str1_len, args[2]=str2_ptr, args[3]=str2_len
        if (node.op == .str_concat) {
            const value_id = try func.newValue(.str_concat, node.type_idx, block);
            var value = func.getValue(value_id);
            var arg_count: u8 = 0;
            for (node.args()) |ir_arg_idx| {
                if (ir_to_ssa.get(ir_arg_idx)) |ssa_arg_id| {
                    if (arg_count < 4) {
                        value.args_storage[arg_count] = ssa_arg_id;
                        arg_count += 1;
                    }
                }
            }
            value.args_len = arg_count;
            return value_id;
        }

        // Handle unary operations - neg, not
        if (node.op == .neg or node.op == .not) {
            const ssa_op: ssa.Op = if (node.op == .neg) .neg else .not;
            const value_id = try func.newValue(ssa_op, node.type_idx, block);
            var value = func.getValue(value_id);
            // args[0] is the operand to negate/not
            if (node.args_len > 0) {
                if (ir_to_ssa.get(node.args()[0])) |ssa_val| {
                    value.args_storage[0] = ssa_val;
                    value.args_len = 1;
                }
            }
            return value_id;
        }

        // Convert IR op to SSA op
        const ssa_op: ssa.Op = switch (node.op) {
            .const_int => .const_int,
            .const_bool => .const_bool,
            .const_float => .const_float,
            .const_string => .const_string,
            .const_null => .const_nil,
            .ret => .ret,
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
            .neg => .neg,
            .not => .not,
            .load => .load,
            .local => .load, // Local variable load becomes SSA load
            .addr_local => .addr, // Address of local variable
            .store => .store,
            .jump => .jump,
            .branch => .branch,
            .addr_field => .field, // Field address becomes field op in SSA
            .field => .field,
            .union_init => .union_init,
            .union_tag => .union_tag,
            .union_payload => .union_payload,
            // Map operations (pass through to SSA)
            .map_new => .map_new,
            .map_set => .map_set,
            .map_get => .map_get,
            .map_has => .map_has,
            .map_size => .map_size,
            .map_free => .map_free,
            // List operations (pass through to SSA)
            .list_new => .list_new,
            .list_push => .list_push,
            .list_get => .list_get,
            .list_len => .list_len,
            .list_free => .list_free,
            // String operations
            .str_concat => .str_concat,
            else => .copy, // Default fallback
        };

        // Create SSA value
        const value_id = try func.newValue(ssa_op, node.type_idx, block);

        // Copy auxiliary data for constants
        var value = func.getValue(value_id);
        value.aux_int = node.aux;
        value.aux_str = node.aux_str;  // For const_string

        return value_id;
    }

    /// Get the stack offset for a local variable from SSA function locals
    fn getLocalOffset(self: *Driver, func: *const ssa.Func, local_idx: u32) i32 {
        _ = self;
        if (local_idx < func.locals.len) {
            return func.locals[local_idx].offset;
        }
        return 0;
    }

    // ========================================================================
    // Register Allocation: Backward Use Analysis
    // ========================================================================
    //
    // Scans SSA in reverse to build use lists with distances for each value.
    // This enables the Go-style "farthest next use" eviction policy.
    //
    // Distance is measured in instruction units from the end of the function.
    // Values used later (closer to end) have lower distances.
    //

    /// Perform backward scan to populate use lists in the register allocator
    fn analyzeUses(self: *Driver, func: *const ssa.Func) !void {
        var ra = &(self.reg_alloc orelse return);

        // Calculate total instructions for distance measurement
        var total_insts: i32 = 0;
        for (func.blocks.items) |block| {
            total_insts += @intCast(block.values.items.len);
        }

        // Scan blocks in reverse order
        var dist: i32 = 0;
        var block_idx: usize = func.blocks.items.len;
        while (block_idx > 0) {
            block_idx -= 1;
            const block = func.blocks.items[block_idx];

            // Scan values in reverse order within block
            var val_idx: usize = block.values.items.len;
            while (val_idx > 0) {
                val_idx -= 1;
                const value_id = block.values.items[val_idx];
                const value = &func.values.items[value_id];

                // Add uses for each argument of this instruction
                for (value.args()) |arg_id| {
                    try ra.addUse(arg_id, dist);
                }

                // Mark constants as rematerializeable
                if (value.op == .const_int) {
                    ra.markRematerializeable(value_id, .const_int, value.aux_int);
                }

                dist += regalloc.Distance.normal;
            }
        }

        if (self.options.debug_codegen) {
            std.debug.print("  Use analysis: {d} instructions scanned\n", .{total_insts});
        }
    }

    /// Initialize or reset register allocator for a function
    fn initRegAllocForFunc(self: *Driver, func: *const ssa.Func) !void {
        const call_conv = switch (self.options.target.arch) {
            .x86_64 => regalloc.x86_64_sysv,
            .aarch64 => regalloc.aarch64_aapcs,
        };

        const num_values = func.values.items.len;

        if (self.reg_alloc) |*ra| {
            // Reset existing allocator
            try ra.reset(num_values);
        } else {
            // Create new allocator with StorageManager integration
            self.reg_alloc = try regalloc.RegAllocator.initWithStorage(
                self.allocator,
                call_conv,
                num_values,
                &self.storage,
            );
        }
    }

    fn generateCode(self: *Driver, ssa_funcs: *std.ArrayList(ssa.Func)) ![]const u8 {
        // Debug: show what we're about to generate
        if (self.options.debug_codegen) {
            std.debug.print("\n=== CODEGEN START ===\n", .{});
            std.debug.print("Target: {s}-{s}\n", .{ @tagName(self.options.target.arch), @tagName(self.options.target.os) });
        }

        // Create object file
        const format = object.ObjectFormat.fromTarget(
            self.options.target.arch,
            self.options.target.os,
        );
        var obj = object.ObjectFile.init(self.allocator, format);
        defer obj.deinit();

        // Add text section
        const text_idx = try obj.addSection("__text", .text);

        // Add rodata section for string literals
        const rodata_idx = try obj.addSection("__cstring", .rodata);
        var rodata_section = obj.getSection(rodata_idx);

        // Map from symbol name to offset in rodata
        var string_offsets = std.StringHashMap(u32).init(self.allocator);
        defer string_offsets.deinit();

        // Track if we need a newline symbol for println
        var needs_newline = false;

        // Helper function to add a string to rodata
        const addStringToRodata = struct {
            fn add(
                allocator: std.mem.Allocator,
                rodata: *@TypeOf(rodata_section),
                offsets: *std.StringHashMap(u32),
                obj_ref: *object.ObjectFile,
                sect_idx: usize,
                str_val: *const ssa.Value,
            ) !void {
                if (str_val.op != .const_string) return;
                const str_content = str_val.aux_str;
                // Strip quotes
                const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                    str_content[1 .. str_content.len - 1]
                else
                    str_content;

                // Create symbol name
                const sym_name = try std.fmt.allocPrint(allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});

                // Add to rodata with symbol if not present
                if (!offsets.contains(sym_name)) {
                    const offset: u32 = @intCast(rodata.*.size());
                    try rodata.*.append(allocator, stripped);
                    try rodata.*.append(allocator, &[_]u8{0});
                    try offsets.put(sym_name, offset);

                    // Add symbol for the string
                    _ = try obj_ref.addSymbol(.{
                        .name = sym_name,
                        .kind = .data,
                        .section = @intCast(sect_idx),
                        .offset = offset,
                        .size = @intCast(stripped.len + 1),
                        .global = false,
                    });
                }
            }
        }.add;

        // Collect string literals from print/println and map operations
        for (ssa_funcs.items) |*func| {
            for (func.blocks.items) |block| {
                for (block.values.items) |value_id| {
                    const value = func.getValue(value_id);

                    // Check if we need a newline for println
                    if (value.op == .call and std.mem.eql(u8, value.aux_str, "println")) {
                        needs_newline = true;
                    }

                    // Add strings used by print/println calls
                    if (value.op == .call and (std.mem.eql(u8, value.aux_str, "print") or std.mem.eql(u8, value.aux_str, "println"))) {
                        const call_args = value.args();
                        if (call_args.len > 0) {
                            const arg_val = func.getValue(call_args[0]);
                            try addStringToRodata(self.allocator, &rodata_section, &string_offsets, &obj, rodata_idx, arg_val);
                        }
                    }

                    // Add strings used by map_set (args[1] is the key string)
                    if (value.op == .map_set) {
                        const map_args = value.args();
                        if (map_args.len > 1) {
                            const key_val = func.getValue(map_args[1]);
                            try addStringToRodata(self.allocator, &rodata_section, &string_offsets, &obj, rodata_idx, key_val);
                        }
                    }

                    // Add strings used by map_get (args[1] is the key string)
                    if (value.op == .map_get) {
                        const map_args = value.args();
                        if (map_args.len > 1) {
                            const key_val = func.getValue(map_args[1]);
                            try addStringToRodata(self.allocator, &rodata_section, &string_offsets, &obj, rodata_idx, key_val);
                        }
                    }

                    // Add strings used by map_has (args[1] is the key string)
                    if (value.op == .map_has) {
                        const map_args = value.args();
                        if (map_args.len > 1) {
                            const key_val = func.getValue(map_args[1]);
                            try addStringToRodata(self.allocator, &rodata_section, &string_offsets, &obj, rodata_idx, key_val);
                        }
                    }

                    // Add strings used by str_concat (both args can be const_string)
                    if (value.op == .str_concat) {
                        const concat_args = value.args();
                        if (concat_args.len > 0) {
                            const str1_val = func.getValue(concat_args[0]);
                            try addStringToRodata(self.allocator, &rodata_section, &string_offsets, &obj, rodata_idx, str1_val);
                        }
                        if (concat_args.len > 1) {
                            const str2_val = func.getValue(concat_args[1]);
                            try addStringToRodata(self.allocator, &rodata_section, &string_offsets, &obj, rodata_idx, str2_val);
                        }
                    }

                    // Add strings stored to variables (store of const_string)
                    if (value.op == .store) {
                        const store_args = value.args();
                        if (store_args.len > 1) {
                            const stored_val = func.getValue(store_args[1]);
                            try addStringToRodata(self.allocator, &rodata_section, &string_offsets, &obj, rodata_idx, stored_val);
                        }
                    }
                }
            }
        }

        // Add newline symbol if needed
        if (needs_newline) {
            const nl_offset: u32 = @intCast(rodata_section.size());
            try rodata_section.append(self.allocator, "\n");
            _ = try obj.addSymbol(.{
                .name = "__str_newline",
                .kind = .data,
                .section = rodata_idx,
                .offset = nl_offset,
                .size = 1,
                .global = false,
            });
        }

        // Create backend based on architecture
        var code_buf = be.CodeBuffer.init(self.allocator);
        defer code_buf.deinit();

        switch (self.options.target.arch) {
            .x86_64 => {
                var backend = x86_64.X86_64Backend.init(self.allocator);
                defer backend.deinit();

                for (ssa_funcs.items) |*func| {
                    // Reset storage manager for this function
                    self.storage.reset();

                    // Initialize register allocator and analyze uses
                    try self.initRegAllocForFunc(func);
                    try self.analyzeUses(func);

                    const sym_offset = code_buf.pos();

                    // macOS requires underscore prefix for C symbols
                    const sym_name = if (self.options.target.os == .macos)
                        try std.fmt.allocPrint(self.allocator, "_{s}", .{func.name})
                    else
                        func.name;

                    _ = try obj.addSymbol(.{
                        .name = sym_name,
                        .kind = .func,
                        .section = text_idx,
                        .offset = sym_offset,
                        .size = 0, // Will be updated
                        .global = true,
                    });

                    // Emit function prologue: push rbp; mov rbp, rsp; sub rsp, frame_size
                    try x86_64.pushReg(&code_buf, .rbp);
                    try x86_64.movRegReg(&code_buf, .rbp, .rsp);
                    // Reserve stack space using computed frame size (or minimum 512)
                    // Increased minimum to provide scratch space for intermediate results
                    const stack_size: i32 = @intCast(@max(512, func.frame_size));
                    try x86_64.subRegImm32(&code_buf, .rsp, stack_size);

                    // Spill function parameters from argument registers to local slots
                    // Parameters are the first param_count locals
                    // System V AMD64 ABI: arguments in rdi, rsi, rdx, rcx, r8, r9
                    const x86_arg_regs = [_]x86_64.Reg{ .rdi, .rsi, .rdx, .rcx, .r8, .r9 };
                    const num_params = @min(func.param_count, @as(u32, @intCast(x86_arg_regs.len)));
                    for (0..num_params) |param_idx| {
                        const local_offset: i32 = func.locals[param_idx].offset;
                        // mov [rbp + offset], reg
                        try x86_64.movMemReg(&code_buf, .rbp, local_offset, x86_arg_regs[param_idx]);
                    }

                    // Track branch positions for patching
                    var branch_patches: std.ArrayList(BranchPatch) = .{ .items = &.{}, .capacity = 0 };
                    defer branch_patches.deinit(self.allocator);

                    // Track block positions (byte offset where each block starts)
                    var block_positions: [256]u32 = undefined;
                    const num_blocks = func.blocks.items.len;

                    // Debug: show function being generated
                    if (self.options.debug_codegen) {
                        std.debug.print("\nGenerating x86_64 code for '{s}':\n", .{func.name});
                    }

                    // Generate code block by block (proper control flow order)
                    for (func.blocks.items, 0..) |block, block_idx| {
                        // Record block start position
                        block_positions[block_idx] = @intCast(code_buf.getBytes().len);

                        if (self.options.debug_codegen) {
                            std.debug.print("  block{d}:\n", .{block_idx});
                        }

                        // Generate code for each value in this block
                        for (block.values.items) |value_id| {
                            const value = func.getValue(value_id);
                            const pos_before = code_buf.pos();
                            try self.generateX86ValueWithPatching(&code_buf, func, value.*, value_id, &branch_patches);
                            const pos_after = code_buf.pos();

                            if (self.options.debug_codegen) {
                                std.debug.print("    v{d} {s}: {d} bytes\n", .{ value_id, @tagName(value.op), pos_after - pos_before });
                            }
                        }
                    }

                    // Record position after all blocks (for ret)
                    const end_pos: u32 = @intCast(code_buf.getBytes().len);
                    _ = end_pos;

                    // Emit function epilogue: mov rsp, rbp; pop rbp; ret
                    try x86_64.movRegReg(&code_buf, .rsp, .rbp);
                    try x86_64.popReg(&code_buf, .rbp);
                    try x86_64.ret(&code_buf);

                    // Patch branch offsets now that we know all block positions
                    // x86_64 jcc/jmp use PC-relative addressing from end of instruction
                    // jcc rel32 is 6 bytes: 0F 8x xx xx xx xx
                    // jmp rel32 is 5 bytes: E9 xx xx xx xx
                    for (branch_patches.items) |patch| {
                        // Get target block position
                        const target_pos: u32 = if (patch.target_block < num_blocks)
                            block_positions[patch.target_block]
                        else
                            @intCast(code_buf.getBytes().len); // fallback to end

                        // x86_64: offset is relative to the END of the jump instruction
                        // jcc rel32 is 6 bytes, jmp rel32 is 5 bytes
                        const inst_len: u32 = if (patch.is_conditional) 6 else 5;
                        const inst_end = patch.position + inst_len;
                        const offset: i32 = @intCast(@as(i64, target_pos) - @as(i64, inst_end));

                        // Patch the offset (last 4 bytes of the instruction)
                        const offset_pos = patch.position + inst_len - 4;
                        code_buf.bytes.items[offset_pos] = @truncate(@as(u32, @bitCast(offset)));
                        code_buf.bytes.items[offset_pos + 1] = @truncate(@as(u32, @bitCast(offset)) >> 8);
                        code_buf.bytes.items[offset_pos + 2] = @truncate(@as(u32, @bitCast(offset)) >> 16);
                        code_buf.bytes.items[offset_pos + 3] = @truncate(@as(u32, @bitCast(offset)) >> 24);
                    }
                }
            },
            .aarch64 => {
                var backend = aarch64.AArch64Backend.init(self.allocator);
                defer backend.deinit();

                for (ssa_funcs.items) |*func| {
                    // Reset storage manager for this function
                    self.storage.reset();

                    // Initialize register allocator and analyze uses
                    try self.initRegAllocForFunc(func);
                    try self.analyzeUses(func);

                    const sym_offset = code_buf.pos();

                    // macOS requires underscore prefix for C symbols
                    const sym_name = if (self.options.target.os == .macos)
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

                    // Check if function makes calls (needs to save link register)
                    var has_calls = false;
                    for (func.values.items) |value| {
                        if (value.op == .call or value.op == .map_new or value.op == .map_set or
                            value.op == .map_get or value.op == .map_has or value.op == .map_size or
                            value.op == .map_free or value.op == .list_new or value.op == .list_push or
                            value.op == .list_get or value.op == .list_free or value.op == .str_concat)
                        {
                            has_calls = true;
                            break;
                        }
                    }

                    // Calculate stack size using computed frame size (or minimum 128)
                    // Increased minimum to provide scratch space for intermediate results
                    const stack_size: u32 = @intCast(@max(128, func.frame_size));

                    // Prologue: allocate stack space for locals
                    // sub sp, sp, #stack_size
                    if (stack_size <= 4095) {
                        try aarch64.subRegImm12(&code_buf, .sp, .sp, @intCast(stack_size));
                    }
                    // Save frame pointer and link register if function makes calls
                    if (has_calls) {
                        // stp fp, lr, [sp, #-16]!
                        try aarch64.stpPreIndex(&code_buf, .fp, .lr, .sp, -2);
                    }

                    // Spill function parameters from argument registers to local slots
                    // Parameters are the first param_count locals
                    // AArch64 ABI: arguments in x0-x7
                    const arm_arg_regs = [_]aarch64.Reg{ .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7 };
                    const num_params = @min(func.param_count, @as(u32, @intCast(arm_arg_regs.len)));
                    for (0..num_params) |param_idx| {
                        const x86_offset: i32 = func.locals[param_idx].offset;
                        const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.strRegImm(&code_buf, arm_arg_regs[param_idx], .sp, offset_scaled);
                        }
                    }

                    // Track branch positions for patching
                    var branch_patches: std.ArrayList(BranchPatch) = .{ .items = &.{}, .capacity = 0 };
                    defer branch_patches.deinit(self.allocator);

                    // Track block positions (byte offset where each block starts)
                    var block_positions: [256]u32 = undefined;
                    const num_blocks = func.blocks.items.len;

                    // Debug: show function being generated
                    if (self.options.debug_codegen) {
                        std.debug.print("\nGenerating aarch64 code for '{s}':\n", .{func.name});
                    }

                    // Generate code block by block (proper control flow order)
                    for (func.blocks.items, 0..) |block, block_idx| {
                        // Record block start position
                        block_positions[block_idx] = @intCast(code_buf.getBytes().len);

                        if (self.options.debug_codegen) {
                            std.debug.print("  block{d}:\n", .{block_idx});
                        }

                        // Generate code for each value in this block
                        for (block.values.items) |value_id| {
                            const value = func.getValue(value_id);
                            const pos_before = code_buf.pos();
                            try self.generateAArch64ValueWithPatching(&code_buf, func, value.*, value_id, &branch_patches, stack_size, has_calls);
                            const pos_after = code_buf.pos();

                            if (self.options.debug_codegen) {
                                std.debug.print("    v{d} {s}: {d} bytes\n", .{ value_id, @tagName(value.op), pos_after - pos_before });
                            }
                        }
                    }

                    // Each .ret now emits its own epilogue and ret instruction
                    // (Functions with multiple return paths need each to properly exit)

                    // Patch branch offsets now that we know all block positions
                    for (branch_patches.items) |patch| {
                        // Get target block position
                        const target_pos: u32 = if (patch.target_block < num_blocks)
                            block_positions[patch.target_block]
                        else
                            @intCast(code_buf.getBytes().len); // fallback to end

                        const signed_offset: i32 = @intCast(@as(i64, target_pos) - @as(i64, patch.position));
                        const inst_offset: i32 = @divTrunc(signed_offset, 4);

                        // Patch the instruction at patch.position
                        if (patch.is_conditional) {
                            // Patch b.cond instruction (19-bit offset in bits 23:5)
                            const imm19: i19 = @intCast(inst_offset);
                            const extended: i32 = imm19;
                            var inst = std.mem.readInt(u32, code_buf.bytes.items[patch.position..][0..4], .little);
                            inst &= ~@as(u32, 0x7FFFF << 5); // Clear old offset
                            inst |= (@as(u32, @bitCast(extended)) & 0x7FFFF) << 5;
                            std.mem.writeInt(u32, code_buf.bytes.items[patch.position..][0..4], inst, .little);
                        } else {
                            // Patch unconditional b instruction (26-bit offset)
                            const imm26: i26 = @intCast(inst_offset);
                            const extended: i32 = imm26;
                            var inst = std.mem.readInt(u32, code_buf.bytes.items[patch.position..][0..4], .little);
                            inst &= ~@as(u32, 0x3FFFFFF); // Clear old offset
                            inst |= @as(u32, @bitCast(extended)) & 0x3FFFFFF;
                            std.mem.writeInt(u32, code_buf.bytes.items[patch.position..][0..4], inst, .little);
                        }
                    }
                }
            },
        }

        // Add code to object file
        try obj.addCode(text_idx, &code_buf);

        // Apply local relocations (resolve local function calls)
        obj.applyLocalRelocations();

        // Write object file
        const obj_path = try self.getObjectPath();
        try obj.writeToFile(obj_path);

        if (self.options.verbose) {
            std.debug.print("  Generated {s} ({d} bytes)\n", .{ obj_path, code_buf.pos() });
        }

        return obj_path;
    }

    fn getObjectPath(self: *Driver) ![]const u8 {
        const base = std.fs.path.stem(self.options.input_path);
        const ext = switch (self.options.target.os) {
            .windows => ".obj",
            else => ".o",
        };

        var path_buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{ base, ext }) catch {
            return error.OutOfMemory;
        };

        return try self.allocator.dupe(u8, path);
    }

    // ========================================================================
    // Register Allocator Helpers for x86_64
    // ========================================================================

    /// Load an SSA value into a register, using the register allocator
    /// Returns the x86_64 register containing the value
    fn loadX86ValueToReg(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, value_id: ssa.ValueID, hint_reg: ?x86_64.Reg) !x86_64.Reg {
        const value = &func.values.items[value_id];
        const arg_regs = [_]x86_64.Reg{ .rdi, .rsi, .rdx, .rcx, .r8, .r9 };
        const target_reg: x86_64.Reg = hint_reg orelse .rax;
        const target_reg_num: u5 = @truncate(@intFromEnum(target_reg));

        // Check if value is already in a register (from previous computation)
        if (self.reg_alloc) |*ra| {
            const current_regs = ra.getRegs(value_id);
            if (current_regs != 0) {
                // Value is already in some register
                const src_reg_num: u5 = @truncate(@ctz(current_regs));
                if (src_reg_num == target_reg_num) {
                    // Already in target register, nothing to do
                    ra.consumeUse(value_id);
                    return target_reg;
                } else {
                    // Move from current register to target
                    const src_reg: x86_64.Reg = @enumFromInt(src_reg_num);
                    try x86_64.movRegReg(buf, target_reg, src_reg);
                    try ra.allocSpecificReg(value_id, target_reg_num);
                    ra.consumeUse(value_id);
                    return target_reg;
                }
            }
        }

        // Value is not in a register, need to load it
        switch (value.op) {
            .const_int => {
                try x86_64.movRegImm64(buf, target_reg, value.aux_int);
            },
            .const_bool => {
                try x86_64.movRegImm64(buf, target_reg, value.aux_int);
            },
            .arg => {
                const param_idx: u32 = @intCast(value.aux_int);
                if (param_idx < arg_regs.len) {
                    if (arg_regs[param_idx] != target_reg) {
                        try x86_64.movRegReg(buf, target_reg, arg_regs[param_idx]);
                    }
                }
            },
            .load => {
                const local_idx: usize = @intCast(value.aux_int);
                const local_offset: i32 = func.locals[local_idx].offset;
                try x86_64.movRegMem(buf, target_reg, .rbp, local_offset);
            },
            else => {
                // Check storage manager for value location
                if (self.storage.get(value_id)) |slot| {
                    try x86_64.movRegMem(buf, target_reg, .rbp, slot);
                }
            },
        }

        // Mark value as now being in target_reg and consume the use
        if (self.reg_alloc) |*ra| {
            try ra.allocSpecificReg(value_id, target_reg_num);
            ra.consumeUse(value_id);
        }

        return target_reg;
    }

    /// Record that a value's result is in a register and save to storage
    fn saveX86Result(self: *Driver, buf: *be.CodeBuffer, value_idx: u32, result_reg: x86_64.Reg) !void {
        const result_reg_num: u5 = @truncate(@intFromEnum(result_reg));

        // Track in register allocator
        if (self.reg_alloc) |*ra| {
            try ra.allocSpecificReg(value_idx, result_reg_num);
        }

        // Save to storage slot for later use
        const result_slot = try self.storage.allocate(value_idx);
        try x86_64.movMemReg(buf, .rbp, result_slot, result_reg);
    }

    /// Invalidate all caller-saved registers after a function call
    /// This ensures we don't incorrectly think values are still in clobbered registers
    fn invalidateX86CallerSaved(self: *Driver) void {
        if (self.reg_alloc) |*ra| {
            // System V AMD64 caller-saved registers: rax, rcx, rdx, rsi, rdi, r8-r11
            const caller_saved = [_]u5{ 0, 1, 2, 6, 7, 8, 9, 10, 11 };
            for (caller_saved) |reg| {
                ra.freeReg(reg);
            }
        }
    }

    fn generateX86Value(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, value: ssa.Value, value_idx: u32) !void {
        // System V AMD64 ABI argument registers
        const arg_regs = [_]x86_64.Reg{ .rdi, .rsi, .rdx, .rcx, .r8, .r9 };

        switch (value.op) {
            .const_int, .const_bool, .const_string, .load => {
                // Constants and loads are used as operands by other instructions.
                // Don't generate standalone code - they're loaded inline when used.
            },
            .arg => {
                // Load parameter from argument register to rax
                const param_idx: u32 = @intCast(value.aux_int);
                if (param_idx < arg_regs.len) {
                    try x86_64.movRegReg(buf, .rax, arg_regs[param_idx]);
                }
            },
            .add => {
                // Binary add using register allocator
                const args = value.args();
                if (args.len >= 2) {
                    const left_idx = args[0];
                    const right_idx = args[1];
                    const right = func.getValue(right_idx);

                    // Load left operand to rax using allocator
                    _ = try self.loadX86ValueToReg(buf, func, left_idx, .rax);

                    // For right operand, check if it's a constant for optimization
                    if (right.op == .const_int and right.aux_int >= -2147483648 and right.aux_int <= 2147483647) {
                        // add rax, imm32 (more efficient for small constants)
                        try x86_64.addRegImm32(buf, .rax, @intCast(right.aux_int));
                        if (self.reg_alloc) |*ra| ra.consumeUse(right_idx);
                    } else {
                        // Load right to r9 and add
                        _ = try self.loadX86ValueToReg(buf, func, right_idx, .r9);
                        try x86_64.addRegReg(buf, .rax, .r9);
                    }
                }

                // Save result using allocator
                try self.saveX86Result(buf, value_idx, .rax);
            },
            .sub => {
                // Binary subtract using register allocator
                const args = value.args();
                if (args.len >= 2) {
                    const left_idx = args[0];
                    const right_idx = args[1];
                    const right = func.getValue(right_idx);

                    // Load left operand to rax
                    _ = try self.loadX86ValueToReg(buf, func, left_idx, .rax);

                    // For right operand, check if it's a constant for optimization
                    if (right.op == .const_int and right.aux_int >= -2147483648 and right.aux_int <= 2147483647) {
                        try x86_64.subRegImm32(buf, .rax, @intCast(right.aux_int));
                        if (self.reg_alloc) |*ra| ra.consumeUse(right_idx);
                    } else {
                        _ = try self.loadX86ValueToReg(buf, func, right_idx, .r9);
                        try x86_64.subRegReg(buf, .rax, .r9);
                    }
                }

                // Save result using allocator
                try self.saveX86Result(buf, value_idx, .rax);
            },
            .mul => {
                // Binary multiply using register allocator
                const args = value.args();
                if (args.len >= 2) {
                    const left_idx = args[0];
                    const right_idx = args[1];
                    const right = func.getValue(right_idx);

                    // Load left operand to rax
                    _ = try self.loadX86ValueToReg(buf, func, left_idx, .rax);

                    // For right operand, check if it's a constant for optimization
                    if (right.op == .const_int and right.aux_int >= -2147483648 and right.aux_int <= 2147483647) {
                        try x86_64.imulRegRegImm(buf, .rax, .rax, @intCast(right.aux_int));
                        if (self.reg_alloc) |*ra| ra.consumeUse(right_idx);
                    } else {
                        _ = try self.loadX86ValueToReg(buf, func, right_idx, .r9);
                        try x86_64.imulRegReg(buf, .rax, .r9);
                    }
                }

                // Save result using allocator
                try self.saveX86Result(buf, value_idx, .rax);
            },
            .div => {
                // Binary divide using register allocator
                // IDIV divides RDX:RAX by operand, quotient in RAX
                const args = value.args();
                if (args.len >= 2) {
                    const left_idx = args[0];
                    const right_idx = args[1];

                    // Load left operand (dividend) to rax
                    _ = try self.loadX86ValueToReg(buf, func, left_idx, .rax);

                    // Sign-extend RAX to RDX:RAX
                    try x86_64.cqo(buf);

                    // Load right operand (divisor) to r8, then divide
                    _ = try self.loadX86ValueToReg(buf, func, right_idx, .r8);
                    try x86_64.idivReg(buf, .r8);
                }

                // Save result using allocator
                try self.saveX86Result(buf, value_idx, .rax);
            },
            .neg => {
                // Unary negation
                const args = value.args();
                if (args.len >= 1) {
                    const operand_idx = args[0];
                    // Load operand to rax
                    _ = try self.loadX86ValueToReg(buf, func, operand_idx, .rax);
                    // NEG rax
                    try x86_64.negReg(buf, .rax);
                }
                // Save result
                try self.saveX86Result(buf, value_idx, .rax);
            },
            .call => {
                // Check for builtin print/println
                if (std.mem.eql(u8, value.aux_str, "print") or std.mem.eql(u8, value.aux_str, "println")) {
                    try self.emitX86PrintSyscall(buf, func, value);
                } else {
                    // Set up arguments in registers, then call
                    const args = value.args();
                    for (args, 0..) |arg_id, i| {
                        if (i >= arg_regs.len) break;
                        const arg_val = func.getValue(arg_id);

                        // Move argument value to appropriate register
                        if (arg_val.op == .const_int) {
                            try x86_64.movRegImm64(buf, arg_regs[i], arg_val.aux_int);
                        } else if (arg_val.op == .arg) {
                            // Already in an arg register, may need to shuffle
                            const param_idx: u32 = @intCast(arg_val.aux_int);
                            if (param_idx < arg_regs.len and param_idx != i) {
                                try x86_64.movRegReg(buf, arg_regs[i], arg_regs[param_idx]);
                            }
                        } else if (arg_val.op == .addr) {
                            // Address of local variable - compute stack address
                            const local_idx: usize = @intCast(arg_val.aux_int);
                            const local_offset: i32 = func.locals[local_idx].offset;
                            // lea reg, [rbp + offset]
                            try x86_64.leaRegMem(buf, arg_regs[i], .rbp, local_offset);
                        } else if (arg_val.op == .load) {
                            // Load from local variable
                            const local_idx: usize = @intCast(arg_val.aux_int);
                            const local_offset: i32 = func.locals[local_idx].offset;
                            try x86_64.movRegMem(buf, arg_regs[i], .rbp, local_offset);
                        }
                    }

                    // Emit call to function
                    const call_func_name = if (self.options.target.os == .macos)
                        try std.fmt.allocPrint(self.allocator, "_{s}", .{value.aux_str})
                    else
                        value.aux_str;
                    try x86_64.callSymbol(buf, call_func_name);
                    // Invalidate caller-saved registers since call may have clobbered them
                    self.invalidateX86CallerSaved();
                    // Return value is in rax - save to storage slot for later use
                    const slot = try self.storage.allocate(value_idx);
                    try x86_64.movMemReg(buf, .rbp, slot, .rax);
                }
            },
            .ret => {
                // Return value should be in rax
                // Check if there's an argument to return
                const args = value.args();
                if (args.len > 0) {
                    const ret_val = func.getValue(args[0]);
                    const ret_idx = args[0];
                    // If the return value isn't already in rax, move it there
                    // Use storage manager to check if value has a saved location
                    if (self.storage.get(ret_idx)) |slot| {
                        // Value was saved to storage slot - load from there
                        try x86_64.movRegMem(buf, .rax, .rbp, slot);
                    } else if (ret_val.op == .arg) {
                        const param_idx: u32 = @intCast(ret_val.aux_int);
                        if (param_idx < arg_regs.len) {
                            try x86_64.movRegReg(buf, .rax, arg_regs[param_idx]);
                        }
                    } else if (ret_val.op == .const_int or ret_val.op == .const_bool) {
                        try x86_64.movRegImm64(buf, .rax, ret_val.aux_int);
                    } else if (ret_val.op == .load) {
                        // Load from local variable into rax
                        const local_idx: usize = @intCast(ret_val.aux_int);
                        const local_offset: i32 = func.locals[local_idx].offset;
                        try x86_64.movRegMem(buf, .rax, .rbp, local_offset);
                    }
                    // Note: sub, mul, div, field results are already in rax
                }
                // Emit function epilogue: mov rsp, rbp; pop rbp; ret
                try x86_64.movRegReg(buf, .rsp, .rbp);
                try x86_64.popReg(buf, .rbp);
                try x86_64.ret(buf);
            },
            .eq, .ne, .lt, .le, .gt, .ge => {
                // Comparison: emit cmp instruction, result in flags
                const args = value.args();
                if (args.len >= 2) {
                    const left = func.getValue(args[0]);
                    const right = func.getValue(args[1]);

                    // Load left operand into r8 (temp register)
                    if (left.op == .const_int) {
                        try x86_64.movRegImm64(buf, .r8, left.aux_int);
                    } else if (left.op == .arg) {
                        const idx: u32 = @intCast(left.aux_int);
                        if (idx < arg_regs.len) {
                            try x86_64.movRegReg(buf, .r8, arg_regs[idx]);
                        }
                    } else if (left.op == .load) {
                        // Load from local variable into r8
                        const local_idx: usize = @intCast(left.aux_int);
                        const local_offset: i32 = func.locals[local_idx].offset;
                        try x86_64.movRegMem(buf, .r8, .rbp, local_offset);
                    } else if (left.op == .field) {
                        // Field access: load from struct at local + field offset
                        const field_args = left.args();
                        if (field_args.len > 0) {
                            const local_idx: usize = @intCast(field_args[0]);
                            const field_offset: i32 = @intCast(left.aux_int);
                            const local_offset: i32 = func.locals[local_idx].offset;
                            try x86_64.movRegMem(buf, .r8, .rbp, local_offset + field_offset);
                        }
                    } else {
                        // Computed value (neg, add, etc) - load from storage
                        if (self.storage.get(args[0])) |slot| {
                            try x86_64.movRegMem(buf, .r8, .rbp, slot);
                        }
                    }

                    // Compare with right operand
                    if (right.op == .const_int) {
                        try x86_64.cmpRegImm32(buf, .r8, @intCast(right.aux_int));
                    } else if (right.op == .arg) {
                        const idx: u32 = @intCast(right.aux_int);
                        if (idx < arg_regs.len) {
                            try x86_64.cmpRegReg(buf, .r8, arg_regs[idx]);
                        }
                    } else if (right.op == .load) {
                        // Load from local variable into r9 and compare
                        const local_idx: usize = @intCast(right.aux_int);
                        const local_offset: i32 = func.locals[local_idx].offset;
                        try x86_64.movRegMem(buf, .r9, .rbp, local_offset);
                        try x86_64.cmpRegReg(buf, .r8, .r9);
                    } else if (right.op == .field) {
                        // Field access: load from struct at local + field offset
                        const field_args = right.args();
                        if (field_args.len > 0) {
                            const local_idx: usize = @intCast(field_args[0]);
                            const field_offset: i32 = @intCast(right.aux_int);
                            const local_offset: i32 = func.locals[local_idx].offset;
                            try x86_64.movRegMem(buf, .r9, .rbp, local_offset + field_offset);
                            try x86_64.cmpRegReg(buf, .r8, .r9);
                        }
                    } else {
                        // Computed value (neg, add, etc) - load from storage
                        if (self.storage.get(args[1])) |slot| {
                            try x86_64.movRegMem(buf, .r9, .rbp, slot);
                            try x86_64.cmpRegReg(buf, .r8, .r9);
                        }
                    }
                }
            },
            .select => {
                // Conditional select: args[0] = cond, args[1] = then, args[2] = else
                // The condition (eq/ne/lt/etc or or) has already set flags
                // Load else value into rax, then value into r8, cmov to select
                const args = value.args();
                if (args.len >= 3) {
                    const cond_val = func.getValue(args[0]);
                    const else_val = func.getValue(args[2]);
                    const then_val = func.getValue(args[1]);

                    // Load else value into rax (unless it's already there from previous select)
                    if (else_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rax, else_val.aux_int);
                    } else if (else_val.op == .load) {
                        const local_idx: usize = @intCast(else_val.aux_int);
                        const local_offset: i32 = func.locals[local_idx].offset;
                        try x86_64.movRegMem(buf, .rax, .rbp, local_offset);
                    }
                    // else if else_val.op == .select, result is already in rax

                    // Load then value into r8
                    if (then_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .r8, then_val.aux_int);
                    } else if (then_val.op == .load) {
                        const local_idx: usize = @intCast(then_val.aux_int);
                        const local_offset: i32 = func.locals[local_idx].offset;
                        try x86_64.movRegMem(buf, .r8, .rbp, local_offset);
                    }

                    // Use appropriate cmov based on condition type
                    // For 'or': result in r10, cmp r10, 0 sets ZF=0 if any true
                    //   So we use cmovne to select "then" when at least one was true
                    // For 'eq' and other comparisons: cmove (if ZF=1)
                    if (cond_val.op == .@"or") {
                        try x86_64.cmovneRegReg(buf, .rax, .r8);
                    } else {
                        try x86_64.cmoveRegReg(buf, .rax, .r8);
                    }
                }
            },
            .branch, .jump => {
                // These are handled by generateX86ValueWithPatching
            },
            .addr => {
                // Compute address of local field: lea rax, [rbp + local_offset + field_offset]
                // args[0] = local index (raw), aux_int = field offset
                const args = value.args();
                if (args.len > 0) {
                    const local_idx = args[0];
                    const field_offset: i32 = @intCast(value.aux_int);
                    const local_offset: i32 = func.locals[@intCast(local_idx)].offset;
                    const total_offset: i32 = local_offset + field_offset;
                    try x86_64.leaRegMem(buf, .rax, .rbp, total_offset);
                }
            },
            .field => {
                // Field access: load from address
                // Two cases:
                // 1. args[0] is a local index (for direct slice.len) - check if < locals.len
                // 2. args[0] is an SSA value ID (for nested access) - address in register
                const args = value.args();
                if (args.len > 0) {
                    const maybe_local_or_ssa = args[0];
                    const field_offset: i32 = @intCast(value.aux_int);

                    // Check if this is a direct local access or SSA value reference
                    // If the value is a valid local index, treat as direct local access
                    if (maybe_local_or_ssa < func.locals.len) {
                        // Direct local field access
                        const local_offset: i32 = func.locals[@intCast(maybe_local_or_ssa)].offset;
                        const total_offset: i32 = local_offset + field_offset;
                        try x86_64.movRegMem(buf, .rax, .rbp, total_offset);
                    } else {
                        // SSA value reference - the address was computed by a prior .addr op
                        // The address should already be in rax from the prior value
                        // Load from [rax + field_offset]
                        if (field_offset != 0) {
                            try x86_64.movRegMem(buf, .rax, .rax, field_offset);
                        } else {
                            try x86_64.movRegMem(buf, .rax, .rax, 0);
                        }
                    }
                }
            },
            .ptr_field => {
                // Load field through pointer: local holds pointer, load from ptr + offset
                // args[0] = local index holding pointer, aux_int = field offset
                const args = value.args();
                if (args.len > 0) {
                    const local_idx = args[0];
                    const field_offset: i32 = @intCast(value.aux_int);

                    // Get stack offset of local holding the pointer
                    const local_offset: i32 = func.locals[@intCast(local_idx)].offset;

                    // Load the pointer into rax: mov rax, [rbp + local_offset]
                    try x86_64.movRegMem(buf, .rax, .rbp, local_offset);

                    // Load field from pointer: mov rax, [rax + field_offset]
                    try x86_64.movRegMem(buf, .rax, .rax, field_offset);
                }
            },
            .index => {
                // Dynamic array indexing: load from stack[local_offset + index * elem_size]
                // args[0] = local index, args[1] = index value (SSA ref), aux_int = elem_size
                const args = value.args();
                if (args.len >= 2) {
                    const local_idx = args[0];
                    const idx_val_id = args[1];
                    const idx_val = func.getValue(idx_val_id);
                    const elem_size: i64 = value.aux_int;

                    // Use computed stack offset from frame layout
                    const local_offset: i32 = func.locals[@intCast(local_idx)].offset;

                    // Get index value into r9
                    if (idx_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .r9, idx_val.aux_int);
                    } else if (idx_val.op == .arg) {
                        const idx: u32 = @intCast(idx_val.aux_int);
                        if (idx < arg_regs.len) {
                            try x86_64.movRegReg(buf, .r9, arg_regs[idx]);
                        }
                    } else if (idx_val.op == .load) {
                        // Load from a local variable
                        const idx_local: usize = @intCast(idx_val.aux_int);
                        const idx_offset: i32 = func.locals[idx_local].offset;
                        try x86_64.movRegMem(buf, .r9, .rbp, idx_offset);
                    } else {
                        // Assume result is in rax from previous computation
                        try x86_64.movRegReg(buf, .r9, .rax);
                    }

                    // Multiply index by element size: imul r9, r9, elem_size
                    try x86_64.imulRegRegImm(buf, .r9, .r9, @intCast(elem_size));

                    // Compute address: lea rax, [rbp + local_offset]
                    try x86_64.leaRegMem(buf, .rax, .rbp, local_offset);

                    // Add index offset: add rax, r9
                    try x86_64.addRegReg(buf, .rax, .r9);

                    // Load value from computed address: mov rax, [rax]
                    try x86_64.movRegMem(buf, .rax, .rax, 0);
                }
            },
            .slice_make => {
                // Slice construction from array
                // args[0] = array local index (raw), args[1] = start (SSA), args[2] = end (SSA)
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

                    // Get array base address into rax
                    const local_offset: i32 = func.locals[@intCast(local_idx)].offset;
                    try x86_64.leaRegMem(buf, .rax, .rbp, local_offset);

                    // Get start value into r9
                    if (start_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .r9, start_val.aux_int);
                    }

                    // Calculate ptr = base + start * elem_size
                    // r10 = start * elem_size
                    try x86_64.imulRegRegImm(buf, .r10, .r9, @intCast(elem_size));
                    // rax = rax + r10
                    try x86_64.addRegReg(buf, .rax, .r10);

                    // Get end value and calculate len = end - start into rdx
                    if (end_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rdx, end_val.aux_int);
                    }
                    // rdx = end - start
                    try x86_64.subRegReg(buf, .rdx, .r9);
                }
            },
            .slice_index => {
                // Slice indexing: load ptr from slice, compute ptr + index*elem_size, load value
                // args[0] = slice local index (raw), args[1] = index value (SSA ref)
                // aux_int = element size
                // Result: rax = value at slice[index]
                const args = value.args();
                if (args.len >= 2) {
                    const local_idx = args[0];
                    const idx_val_id = args[1];
                    const idx_val = func.getValue(idx_val_id);
                    const elem_size: i64 = value.aux_int;

                    // Get slice's stack offset (slice is ptr+len, 16 bytes)
                    const local_offset: i32 = func.locals[@intCast(local_idx)].offset;

                    // Load slice ptr (first 8 bytes) into rax
                    try x86_64.movRegMem(buf, .rax, .rbp, local_offset);

                    // Get index value into r9
                    if (idx_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .r9, idx_val.aux_int);
                    } else if (idx_val.op == .arg) {
                        const idx: u32 = @intCast(idx_val.aux_int);
                        if (idx < arg_regs.len) {
                            try x86_64.movRegReg(buf, .r9, arg_regs[idx]);
                        }
                    } else if (idx_val.op == .load) {
                        const idx_local: usize = @intCast(idx_val.aux_int);
                        const idx_offset: i32 = func.locals[idx_local].offset;
                        try x86_64.movRegMem(buf, .r9, .rbp, idx_offset);
                    } else {
                        // Assume index is in rax, save ptr first
                        try x86_64.movRegReg(buf, .r10, .rax);
                        try x86_64.movRegMem(buf, .rax, .rbp, local_offset);
                        try x86_64.movRegReg(buf, .r9, .r10);
                    }

                    // Multiply index by element size: imul r9, r9, elem_size
                    try x86_64.imulRegRegImm(buf, .r9, .r9, @intCast(elem_size));

                    // Add to ptr: add rax, r9
                    try x86_64.addRegReg(buf, .rax, .r9);

                    // Load value from computed address: mov rax, [rax]
                    try x86_64.movRegMem(buf, .rax, .rax, 0);
                }
            },
            .store => {
                // Store value to local at optional field offset
                // args[0] = local index, args[1] = value, aux_int = field offset
                const args = value.args();
                if (args.len >= 2) {
                    const local_idx = args[0];
                    const val_id = args[1];
                    const val = func.getValue(val_id);
                    const field_offset: i32 = @intCast(value.aux_int);

                    // Use computed stack offset from frame layout
                    const local_offset: i32 = func.locals[@intCast(local_idx)].offset;
                    const total_offset: i32 = local_offset + field_offset;

                    // Check if storing a slice (slice_make leaves ptr in rax, len in rdx)
                    if (val.op == .slice_make) {
                        // Store 16-byte slice: ptr at offset 0, len at offset 8
                        try x86_64.movMemReg(buf, .rbp, total_offset, .rax);
                        try x86_64.movMemReg(buf, .rbp, total_offset + 8, .rdx);
                    } else if (val.op == .union_init) {
                        // Store 16-byte union: tag at offset 0, payload at offset 8
                        try x86_64.movMemReg(buf, .rbp, total_offset, .rax);
                        try x86_64.movMemReg(buf, .rbp, total_offset + 8, .rdx);
                    } else if (val.op == .str_concat) {
                        // Store 16-byte string: ptr at offset 0, len at offset 8
                        // str_concat leaves ptr in rax, len in rdx
                        try x86_64.movMemReg(buf, .rbp, total_offset, .rax);
                        try x86_64.movMemReg(buf, .rbp, total_offset + 8, .rdx);
                    } else if (val.op == .const_string) {
                        // Store 16-byte string literal: load ptr (from rodata) and len (immediate)
                        const str_content = val.aux_str;
                        const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                            str_content[1 .. str_content.len - 1]
                        else
                            str_content;
                        const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
                        try x86_64.leaRipSymbol(buf, .rax, sym_name);
                        try x86_64.movMemReg(buf, .rbp, total_offset, .rax);
                        try x86_64.movRegImm64(buf, .rax, @intCast(stripped.len));
                        try x86_64.movMemReg(buf, .rbp, total_offset + 8, .rax);
                    } else {
                        // Get value to store into r8, or use rax directly for ops
                        var use_rax_directly = false;
                        if (val.op == .const_int) {
                            try x86_64.movRegImm64(buf, .r8, val.aux_int);
                        } else if (val.op == .arg) {
                            const idx: u32 = @intCast(val.aux_int);
                            if (idx < arg_regs.len) {
                                try x86_64.movRegReg(buf, .r8, arg_regs[idx]);
                            }
                        } else if (val.op == .load) {
                            // Load from local's stack slot - load ops don't emit code themselves
                            const src_local_idx: usize = @intCast(val.aux_int);
                            const src_offset: i32 = func.locals[src_local_idx].offset;
                            try x86_64.movRegMem(buf, .r8, .rbp, src_offset);
                        } else if (val.op == .add or val.op == .sub or val.op == .mul or val.op == .div or
                            val.op == .call or val.op == .field or val.op == .index or
                            val.op == .slice_index or val.op == .union_payload or
                            val.op == .map_new or val.op == .map_get or val.op == .map_has or val.op == .map_size or
                            val.op == .list_new or val.op == .list_get or val.op == .list_len)
                        {
                            // Operations that leave result in rax - store directly
                            use_rax_directly = true;
                        }

                        // Store to [rbp + total_offset]
                        if (use_rax_directly) {
                            try x86_64.movMemReg(buf, .rbp, total_offset, .rax);
                        } else {
                            try x86_64.movMemReg(buf, .rbp, total_offset, .r8);
                        }
                    }
                }
            },
            .union_init => {
                // Initialize a tagged union value
                // aux_int = variant index (tag), args[0] = payload value (if any)
                // Union layout: tag (8 bytes) at offset 0, payload at offset 8
                const variant_idx: i64 = value.aux_int;

                // Store tag in rax (for later store)
                try x86_64.movRegImm64(buf, .rax, variant_idx);

                // If there's a payload, get it into rdx
                const args = value.args();
                if (args.len > 0) {
                    const payload_id = args[0];
                    const payload_val = func.getValue(payload_id);
                    if (payload_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rdx, payload_val.aux_int);
                    } else {
                        // Payload should be in rax from previous computation, save tag first
                        try x86_64.movRegReg(buf, .r8, .rax); // save tag
                        // The payload computation left result in rax, move to rdx
                        try x86_64.movRegReg(buf, .rdx, .rax);
                        try x86_64.movRegReg(buf, .rax, .r8); // restore tag
                    }
                }
                // Result: rax = tag, rdx = payload (if any)
            },
            .union_tag => {
                // Extract tag from union value
                // Union layout: tag (8 bytes) at offset 0
                // Use r8 for tag to avoid conflicts with operations that use rax
                const args = value.args();
                if (args.len > 0) {
                    const union_id = args[0];
                    const union_val = func.getValue(union_id);
                    // If the union value is a load, get its address
                    if (union_val.op == .load) {
                        const local_idx: usize = @intCast(union_val.aux_int);
                        const local_offset: i32 = func.locals[local_idx].offset;
                        // Load tag (8 bytes at offset 0 from local) into r8
                        try x86_64.movRegMem(buf, .r8, .rbp, local_offset);
                    }
                }
            },
            .union_payload => {
                // Extract payload from union value
                // Union layout: tag (8 bytes) at offset 0, payload at offset 8
                const args = value.args();
                if (args.len > 0) {
                    const union_id = args[0];
                    const union_val = func.getValue(union_id);
                    // If the union value is a load, get its address
                    if (union_val.op == .load) {
                        const local_idx: usize = @intCast(union_val.aux_int);
                        const local_offset: i32 = func.locals[local_idx].offset;
                        // Load payload (at offset 8 from local)
                        try x86_64.movRegMem(buf, .rax, .rbp, local_offset + 8);
                    }
                }
            },
            .@"or" => {
                // Logical OR: combine two comparison results
                // Strategy: capture each comparison result as 0/1, then OR them
                const args = value.args();
                if (args.len >= 2) {
                    const left = func.getValue(args[0]);
                    const right = func.getValue(args[1]);

                    // Get left comparison result into r10
                    if (left.op == .eq or left.op == .ne or left.op == .lt or
                        left.op == .le or left.op == .gt or left.op == .ge)
                    {
                        // Re-generate the comparison
                        try self.generateX86Comparison(buf, func, left.*);
                        // r10 = 0, r11 = 1, then cmove/cmovne based on condition
                        try x86_64.xorRegReg(buf, .r10, .r10); // r10 = 0
                        try x86_64.movRegImm64(buf, .r11, 1); // r11 = 1
                        // Use appropriate cmov for the comparison type
                        // For eq: cmove (if ZF=1)
                        // For now, all our comparisons use eq for the condition
                        try x86_64.cmoveRegReg(buf, .r10, .r11);
                    } else if (left.op == .@"or") {
                        // Left is already an OR - its result should be in r10
                        // Just keep it
                    }

                    // Get right comparison result into r11
                    if (right.op == .eq or right.op == .ne or right.op == .lt or
                        right.op == .le or right.op == .gt or right.op == .ge)
                    {
                        // Re-generate the comparison
                        try self.generateX86Comparison(buf, func, right.*);
                        // r11 = 0, r12 = 1, then cmove
                        try x86_64.xorRegReg(buf, .r11, .r11); // r11 = 0
                        try x86_64.movRegImm64(buf, .r12, 1); // r12 = 1
                        try x86_64.cmoveRegReg(buf, .r11, .r12);
                    } else if (right.op == .@"or") {
                        // Right is already an OR - recurse handled its result in r10
                        // Move to r11
                        try x86_64.movRegReg(buf, .r11, .r10);
                    }

                    // Combine: or r10, r11
                    try x86_64.orRegReg(buf, .r10, .r11);

                    // Set flags for subsequent select: cmp r10, 0
                    // If r10 > 0, at least one was true (ZF = 0)
                    // If r10 == 0, both false (ZF = 1)
                    try x86_64.cmpRegImm32(buf, .r10, 0);
                }
            },
            // Map operations - native codegen implementation
            // Map layout:
            //   Header (32 bytes): capacity (8), size (8), seed (8), unused (8)
            //   Slots (64 x 32 bytes = 2048 bytes): meta (1), pad (7), key_ptr (8), key_len (8), value (8)
            //   Total: 2080 bytes
            // Slot meta: 0 = empty, 1 = occupied, 2 = deleted
            .map_new => {
                // Call calloc(1, 2080) to allocate zeroed map
                // System V AMD64 ABI: rdi=nmemb, rsi=size
                try x86_64.movRegImm64(buf, .rdi, 1);
                try x86_64.movRegImm64(buf, .rsi, 2080); // 32 header + 64*32 slots
                const calloc_name = if (self.options.target.os == .macos) "_calloc" else "calloc";
                try x86_64.callSymbol(buf, calloc_name);
                self.invalidateX86CallerSaved();
                // rax now has pointer to zeroed map

                // Initialize capacity field at offset 0 to 64
                try x86_64.movRegImm64(buf, .rcx, 64);
                try x86_64.movMemReg(buf, .rax, 0, .rcx); // [rax+0] = 64

                // size at offset 8 is already 0 from calloc
                // seed at offset 16 - initialize to FNV offset basis for consistent hashing
                try x86_64.movRegImm64(buf, .rcx, @as(i64, @bitCast(@as(u64, 0xcbf29ce484222325))));
                try x86_64.movMemReg(buf, .rax, 16, .rcx); // [rax+16] = FNV offset

                // Result (map pointer) is in rax
            },
            .map_set => {
                // Call cot_native_map_set(map, key_ptr, key_len, value) - 4 args
                // System V AMD64 ABI: rdi=map, rsi=key_ptr, rdx=key_len, rcx=value
                // Lowerer emits: args[0]=handle, args[1]=key, args[2]=value
                const args = value.args();

                // Load map pointer from local into rdi
                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const offset = self.getLocalOffset(func, local_idx);
                        try x86_64.movRegMem(buf, .rdi, .rbp, offset);
                    } else if (handle_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rdi, handle_val.aux_int);
                    }
                }

                // Load key_ptr and key_len from key string
                if (args.len > 1) {
                    const key_val = func.getValue(args[1]);
                    if (key_val.op == .const_string) {
                        const str_content = key_val.aux_str;
                        const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                            str_content[1 .. str_content.len - 1]
                        else
                            str_content;
                        const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
                        // rsi = key_ptr
                        try x86_64.leaRipSymbol(buf, .rsi, sym_name);
                        // rdx = key_len
                        try x86_64.movRegImm64(buf, .rdx, @intCast(stripped.len));
                    }
                }

                // Load value into rcx
                if (args.len > 2) {
                    const val_val = func.getValue(args[2]);
                    if (val_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rcx, val_val.aux_int);
                    } else if (val_val.op == .load or val_val.op == .copy) {
                        const local_idx: u32 = @intCast(val_val.aux_int);
                        const offset = self.getLocalOffset(func, local_idx);
                        try x86_64.movRegMem(buf, .rcx, .rbp, offset);
                    }
                }

                const map_set_name = if (self.options.target.os == .macos) "_cot_native_map_set" else "cot_native_map_set";
                try x86_64.callSymbol(buf, map_set_name);
                self.invalidateX86CallerSaved();
                // Result is in rax
            },
            .map_get => {
                // Call cot_native_map_get(map, key_ptr, key_len) - 3 args
                // System V AMD64 ABI: rdi=map, rsi=key_ptr, rdx=key_len
                // Lowerer emits: args[0]=handle, args[1]=key
                const args = value.args();

                // Load map pointer from local into rdi
                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const offset = self.getLocalOffset(func, local_idx);
                        try x86_64.movRegMem(buf, .rdi, .rbp, offset);
                    } else if (handle_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rdi, handle_val.aux_int);
                    }
                }

                // Load key_ptr and key_len from key string
                if (args.len > 1) {
                    const key_val = func.getValue(args[1]);
                    if (key_val.op == .const_string) {
                        const str_content = key_val.aux_str;
                        const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                            str_content[1 .. str_content.len - 1]
                        else
                            str_content;
                        const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
                        // rsi = key_ptr
                        try x86_64.leaRipSymbol(buf, .rsi, sym_name);
                        // rdx = key_len
                        try x86_64.movRegImm64(buf, .rdx, @intCast(stripped.len));
                    }
                }

                const map_get_name = if (self.options.target.os == .macos) "_cot_native_map_get" else "cot_native_map_get";
                try x86_64.callSymbol(buf, map_get_name);
                self.invalidateX86CallerSaved();
                // Result is in rax
            },
            .map_has => {
                // Call cot_native_map_has(map, key_ptr, key_len) - 3 args
                // System V AMD64 ABI: rdi=map, rsi=key_ptr, rdx=key_len
                // Lowerer emits: args[0]=handle, args[1]=key
                const args = value.args();

                // Load map pointer from local into rdi
                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const offset = self.getLocalOffset(func, local_idx);
                        try x86_64.movRegMem(buf, .rdi, .rbp, offset);
                    } else if (handle_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rdi, handle_val.aux_int);
                    }
                }

                // Load key_ptr and key_len from key string
                if (args.len > 1) {
                    const key_val = func.getValue(args[1]);
                    if (key_val.op == .const_string) {
                        const str_content = key_val.aux_str;
                        const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                            str_content[1 .. str_content.len - 1]
                        else
                            str_content;
                        const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
                        // rsi = key_ptr
                        try x86_64.leaRipSymbol(buf, .rsi, sym_name);
                        // rdx = key_len
                        try x86_64.movRegImm64(buf, .rdx, @intCast(stripped.len));
                    }
                }

                const map_has_name = if (self.options.target.os == .macos) "_cot_native_map_has" else "cot_native_map_has";
                try x86_64.callSymbol(buf, map_has_name);
                self.invalidateX86CallerSaved();
                // Result is in rax
            },
            .map_size => {
                // Call cot_native_map_size(map) - 1 arg
                // Lowerer emits: args[0]=handle
                const args = value.args();
                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const offset = self.getLocalOffset(func, local_idx);
                        try x86_64.movRegMem(buf, .rdi, .rbp, offset);
                    } else if (handle_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rdi, handle_val.aux_int);
                    }
                }
                const map_size_name = if (self.options.target.os == .macos) "_cot_native_map_size" else "cot_native_map_size";
                try x86_64.callSymbol(buf, map_size_name);
                self.invalidateX86CallerSaved();
                // Result is in rax
            },
            .map_free => {
                // Call cot_native_map_free(map) - 1 arg, no return
                // Lowerer emits: args[0]=handle
                const args = value.args();
                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const offset = self.getLocalOffset(func, local_idx);
                        try x86_64.movRegMem(buf, .rdi, .rbp, offset);
                    } else if (handle_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rdi, handle_val.aux_int);
                    }
                }
                const map_free_name = if (self.options.target.os == .macos) "_cot_native_map_free" else "cot_native_map_free";
                try x86_64.callSymbol(buf, map_free_name);
                self.invalidateX86CallerSaved();
            },
            // ========== List Operations (native layout + FFI) ==========
            // List layout (24 bytes):
            //   elements_ptr (8): pointer to heap-allocated element array
            //   length (8): current number of elements
            //   capacity (8): allocated capacity
            .list_new => {
                // Call calloc(1, 24) to allocate zeroed list header
                // System V AMD64 ABI: rdi=nmemb, rsi=size
                try x86_64.movRegImm64(buf, .rdi, 1);
                try x86_64.movRegImm64(buf, .rsi, 24); // 24-byte header
                const calloc_name = if (self.options.target.os == .macos) "_calloc" else "calloc";
                try x86_64.callSymbol(buf, calloc_name);
                self.invalidateX86CallerSaved();
                // rax now has pointer to zeroed list header
                // All fields (elements_ptr=0, length=0, capacity=0) already correct from calloc
            },
            .list_push => {
                // Call cot_native_list_push(list, value) - grows if needed
                // System V AMD64 ABI: rdi=list, rsi=value
                const args = value.args();
                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const offset = self.getLocalOffset(func, local_idx);
                        try x86_64.movRegMem(buf, .rdi, .rbp, offset);
                    } else if (handle_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rdi, handle_val.aux_int);
                    }
                }
                if (args.len > 1) {
                    const val_val = func.getValue(args[1]);
                    if (val_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rsi, val_val.aux_int);
                    } else if (val_val.op == .load or val_val.op == .copy) {
                        const local_idx: u32 = @intCast(val_val.aux_int);
                        const offset = self.getLocalOffset(func, local_idx);
                        try x86_64.movRegMem(buf, .rsi, .rbp, offset);
                    }
                }
                const list_push_name = if (self.options.target.os == .macos) "_cot_native_list_push" else "cot_native_list_push";
                try x86_64.callSymbol(buf, list_push_name);
                self.invalidateX86CallerSaved();
            },
            .list_get => {
                // Call cot_native_list_get(list, index) - returns element value
                // System V AMD64 ABI: rdi=list, rsi=index
                const args = value.args();
                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const offset = self.getLocalOffset(func, local_idx);
                        try x86_64.movRegMem(buf, .rdi, .rbp, offset);
                    } else if (handle_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rdi, handle_val.aux_int);
                    }
                }
                if (args.len > 1) {
                    const idx_val = func.getValue(args[1]);
                    if (idx_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rsi, idx_val.aux_int);
                    } else if (idx_val.op == .load or idx_val.op == .copy) {
                        const local_idx: u32 = @intCast(idx_val.aux_int);
                        const offset = self.getLocalOffset(func, local_idx);
                        try x86_64.movRegMem(buf, .rsi, .rbp, offset);
                    }
                }
                const list_get_name = if (self.options.target.os == .macos) "_cot_native_list_get" else "cot_native_list_get";
                try x86_64.callSymbol(buf, list_get_name);
                self.invalidateX86CallerSaved();
                // Result is in rax - save to storage for later use
                const slot = try self.storage.allocate(value_idx);
                try x86_64.movMemReg(buf, .rbp, slot, .rax);
            },
            .list_len => {
                // Read length field from list header (offset 8)
                // Inline implementation - no FFI needed
                const args = value.args();
                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const offset = self.getLocalOffset(func, local_idx);
                        try x86_64.movRegMem(buf, .rdi, .rbp, offset); // rdi = list ptr
                    } else if (handle_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rdi, handle_val.aux_int);
                    }
                }
                // Load length from [rdi + 8] into rax
                // mov rax, [rdi+8] = REX.W + MOV r64,r/m64 + ModRM(disp8) + disp
                try buf.emit8(0x48); // REX.W
                try buf.emit8(0x8B); // MOV r64, r/m64
                try buf.emit8(0x47); // ModRM: [rdi + disp8], dst=rax
                try buf.emit8(0x08); // disp8 = 8
            },
            .list_free => {
                // Call cot_native_list_free(list) - frees elements array and header
                const args = value.args();
                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const offset = self.getLocalOffset(func, local_idx);
                        try x86_64.movRegMem(buf, .rdi, .rbp, offset);
                    } else if (handle_val.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rdi, handle_val.aux_int);
                    }
                }
                const list_free_name = if (self.options.target.os == .macos) "_cot_native_list_free" else "cot_native_list_free";
                try x86_64.callSymbol(buf, list_free_name);
                self.invalidateX86CallerSaved();
            },
            .str_concat => {
                // Call cot_str_concat(ptr1, len1, ptr2, len2)
                // System V AMD64 ABI: rdi=ptr1, rsi=len1, rdx=ptr2, rcx=len2
                // Returns: rax=new_ptr, rdx=new_len (struct return)
                const args = value.args();

                // For now, we expect const_string args with symbol references
                // Load first string (ptr1 -> rdi, len1 -> rsi)
                if (args.len > 0) {
                    const str1_val = func.getValue(args[0]);
                    if (str1_val.op == .const_string) {
                        const str_content = str1_val.aux_str;
                        const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                            str_content[1 .. str_content.len - 1]
                        else
                            str_content;
                        const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
                        try x86_64.leaRipSymbol(buf, .rdi, sym_name);
                        try x86_64.movRegImm64(buf, .rsi, @intCast(stripped.len));
                    } else if (str1_val.op == .load or str1_val.op == .copy) {
                        // Load string from local (ptr at offset, len at offset+8)
                        const local_idx: u32 = @intCast(str1_val.aux_int);
                        const offset = self.getLocalOffset(func, local_idx);
                        try x86_64.movRegMem(buf, .rdi, .rbp, offset); // ptr
                        try x86_64.movRegMem(buf, .rsi, .rbp, offset + 8); // len
                    } else if (str1_val.op == .str_concat) {
                        // Result from previous str_concat is in rax/rdx, move to rdi/rsi
                        try x86_64.movRegReg(buf, .rdi, .rax); // ptr
                        try x86_64.movRegReg(buf, .rsi, .rdx); // len
                    }
                }

                // Load second string (ptr2 -> rdx, len2 -> rcx)
                if (args.len > 1) {
                    const str2_val = func.getValue(args[1]);
                    if (str2_val.op == .const_string) {
                        const str_content = str2_val.aux_str;
                        const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                            str_content[1 .. str_content.len - 1]
                        else
                            str_content;
                        const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
                        try x86_64.leaRipSymbol(buf, .rdx, sym_name);
                        try x86_64.movRegImm64(buf, .rcx, @intCast(stripped.len));
                    } else if (str2_val.op == .load or str2_val.op == .copy) {
                        // Load string from local (ptr at offset, len at offset+8)
                        const local_idx: u32 = @intCast(str2_val.aux_int);
                        const offset = self.getLocalOffset(func, local_idx);
                        try x86_64.movRegMem(buf, .rdx, .rbp, offset); // ptr
                        try x86_64.movRegMem(buf, .rcx, .rbp, offset + 8); // len
                    }
                }

                const str_concat_name = if (self.options.target.os == .macos) "_cot_str_concat" else "cot_str_concat";
                try x86_64.callSymbol(buf, str_concat_name);
                self.invalidateX86CallerSaved();
                // Result: rax = new ptr, rdx = new len
            },
            else => {
                // Warn about unhandled ops in debug mode
                if (self.options.debug_codegen) {
                    std.debug.print("  [WARN] Unhandled x86_64 SSA op: {s}\n", .{@tagName(value.op)});
                }
            },
        }
    }

    /// Generate x86_64 code for a comparison operation (helper for or/and)
    fn generateX86Comparison(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, cmp_value: ssa.Value) !void {
        _ = self;
        const arg_regs = [_]x86_64.Reg{ .rdi, .rsi, .rdx, .rcx, .r8, .r9 };
        const cmp_args = cmp_value.args();
        if (cmp_args.len >= 2) {
            const left = func.getValue(cmp_args[0]);
            const right = func.getValue(cmp_args[1]);

            // Load left operand into r8
            if (left.op == .const_int) {
                try x86_64.movRegImm64(buf, .r8, left.aux_int);
            } else if (left.op == .arg) {
                const idx: u32 = @intCast(left.aux_int);
                if (idx < arg_regs.len) {
                    try x86_64.movRegReg(buf, .r8, arg_regs[idx]);
                }
            } else if (left.op == .load) {
                const local_idx: usize = @intCast(left.aux_int);
                const local_offset: i32 = func.locals[local_idx].offset;
                try x86_64.movRegMem(buf, .r8, .rbp, local_offset);
            }

            // Compare with right operand
            if (right.op == .const_int) {
                try x86_64.cmpRegImm32(buf, .r8, @intCast(right.aux_int));
            } else if (right.op == .arg) {
                const idx: u32 = @intCast(right.aux_int);
                if (idx < arg_regs.len) {
                    try x86_64.cmpRegReg(buf, .r8, arg_regs[idx]);
                }
            } else if (right.op == .load) {
                const local_idx: usize = @intCast(right.aux_int);
                const local_offset: i32 = func.locals[local_idx].offset;
                try x86_64.movRegMem(buf, .r9, .rbp, local_offset);
                try x86_64.cmpRegReg(buf, .r8, .r9);
            }
        }
    }

    /// Generate x86_64 code for a value and record branch positions for patching
    fn generateX86ValueWithPatching(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, value: ssa.Value, value_idx: u32, patches: *std.ArrayList(BranchPatch)) !void {
        const arg_regs = [_]x86_64.Reg{ .rdi, .rsi, .rdx, .rcx, .r8, .r9 };
        _ = arg_regs;

        switch (value.op) {
            .branch => {
                // Branch: conditional jump based on comparison result
                // aux_int packs both blocks: lower 32 = true, upper 32 = false
                // We emit: conditional jump to false block, then unconditional jump to true block
                const args = value.args();
                const cond_pos: u32 = @intCast(buf.getBytes().len);

                // Extract block IDs from aux_int
                const true_block: u32 = @truncate(@as(u64, @bitCast(value.aux_int)));
                const false_block: u32 = @truncate(@as(u64, @bitCast(value.aux_int)) >> 32);

                if (args.len > 0) {
                    const cond_id = args[0];
                    const cond_val = func.getValue(cond_id);

                    if (cond_val.op == .const_bool) {
                        // Constant-folded condition: emit unconditional jump to appropriate block
                        const target = if (cond_val.aux_int != 0) true_block else false_block;
                        try x86_64.jmpRel32(buf, 0);
                        try patches.append(self.allocator, .{
                            .position = cond_pos,
                            .is_conditional = false,
                            .target_block = target,
                        });
                        // No need to emit second jump - we only go one way
                        return;
                    } else if (cond_val.op == .eq) {
                        // For "if equal", jump to false block if NOT equal
                        try x86_64.jccRel32(buf, .ne, 0);
                    } else if (cond_val.op == .ne) {
                        // For "if not equal", jump to false block if equal
                        try x86_64.jccRel32(buf, .e, 0);
                    } else if (cond_val.op == .lt) {
                        // For "if less than", jump to false block if >=
                        try x86_64.jccRel32(buf, .ge, 0);
                    } else if (cond_val.op == .le) {
                        // For "if less or equal", jump to false block if >
                        try x86_64.jccRel32(buf, .g, 0);
                    } else if (cond_val.op == .gt) {
                        // For "if greater than", jump to false block if <=
                        try x86_64.jccRel32(buf, .le, 0);
                    } else if (cond_val.op == .ge) {
                        // For "if greater or equal", jump to false block if <
                        try x86_64.jccRel32(buf, .l, 0);
                    } else {
                        // Default: unconditional jump to false block
                        try x86_64.jmpRel32(buf, 0);
                    }
                } else {
                    try x86_64.jmpRel32(buf, 0);
                }

                // Record patch targeting FALSE block for conditional branch
                try patches.append(self.allocator, .{
                    .position = cond_pos,
                    .is_conditional = true,
                    .target_block = false_block,
                });

                // Emit unconditional jump to TRUE block (can't rely on fall-through)
                const true_pos: u32 = @intCast(buf.getBytes().len);
                try x86_64.jmpRel32(buf, 0);
                try patches.append(self.allocator, .{
                    .position = true_pos,
                    .is_conditional = false,
                    .target_block = true_block,
                });
            },
            .jump => {
                // Unconditional jump to target block
                const target_block: u32 = @intCast(value.aux_int);
                const pos: u32 = @intCast(buf.getBytes().len);
                try x86_64.jmpRel32(buf, 0);

                try patches.append(self.allocator, .{
                    .position = pos,
                    .is_conditional = false,
                    .target_block = target_block,
                });
            },
            else => {
                // Use the regular code generator for non-branch ops
                try self.generateX86Value(buf, func, value, value_idx);
            },
        }
    }

    /// Emit x86_64 write call for print/println builtin
    /// Uses libc write function instead of raw syscall to avoid relocation issues
    fn emitX86PrintSyscall(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, value: ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const arg_val = func.getValue(args[0]);
        const is_println = std.mem.eql(u8, value.aux_str, "println");

        // Get string data
        if (arg_val.op == .const_string) {
            const str_content = arg_val.aux_str;
            // Strip quotes from string literal
            const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                str_content[1 .. str_content.len - 1]
            else
                str_content;

            // Create unique symbol name for this string
            const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});

            // Call write(fd=1, buf, len) via libc
            // System V AMD64 ABI: rdi, rsi, rdx for first 3 args
            try x86_64.movRegImm64(buf, .rdi, 1); // fd = stdout
            try x86_64.leaRipSymbol(buf, .rsi, sym_name); // buf = string address
            try x86_64.movRegImm64(buf, .rdx, @intCast(stripped.len)); // len
            // Call write function (libc)
            const write_name = if (self.options.target.os == .macos) "_write" else "write";
            try x86_64.callSymbol(buf, write_name);

            // For println, also write a newline
            if (is_println) {
                const nl_sym = "__str_newline";
                try x86_64.movRegImm64(buf, .rdi, 1);
                try x86_64.leaRipSymbol(buf, .rsi, nl_sym);
                try x86_64.movRegImm64(buf, .rdx, 1);
                try x86_64.callSymbol(buf, write_name);
            }
        }
    }

    /// Emit AArch64 write call for print/println builtin
    /// Uses libc write function instead of raw syscall to avoid relocation issues
    fn emitAArch64PrintSyscall(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, value: ssa.Value) !void {
        const args = value.args();
        if (args.len == 0) return;

        const arg_val = func.getValue(args[0]);
        const is_println = std.mem.eql(u8, value.aux_str, "println");

        // Get string data
        if (arg_val.op == .const_string) {
            const str_content = arg_val.aux_str;
            // Strip quotes from string literal
            const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                str_content[1 .. str_content.len - 1]
            else
                str_content;

            // Create unique symbol name for this string
            const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});

            // Call write(fd=1, buf, len) via libc
            // AAPCS64: x0, x1, x2 for first 3 args
            try aarch64.movRegImm64(buf, .x0, 1); // fd = stdout
            try aarch64.loadSymbolAddr(buf, .x1, sym_name); // buf = string address
            try aarch64.movRegImm64(buf, .x2, @intCast(stripped.len)); // len
            // Call write function (libc)
            const write_name = if (self.options.target.os == .macos) "_write" else "write";
            try aarch64.callSymbol(buf, write_name);

            // For println, also write a newline
            if (is_println) {
                const nl_sym = "__str_newline";
                try aarch64.movRegImm64(buf, .x0, 1);
                try aarch64.loadSymbolAddr(buf, .x1, nl_sym);
                try aarch64.movRegImm64(buf, .x2, 1);
                try aarch64.callSymbol(buf, write_name);
            }
        }
    }

    // ========================================================================
    // Register Allocator Helpers for AArch64
    // ========================================================================

    /// Load an SSA value into a register for AArch64
    /// Returns the aarch64 register containing the value
    fn loadAArch64ValueToReg(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, value_id: ssa.ValueID, hint_reg: ?aarch64.Reg) !aarch64.Reg {
        const value = &func.values.items[value_id];
        const arg_regs = [_]aarch64.Reg{ .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7 };
        const target_reg: aarch64.Reg = hint_reg orelse .x0;
        const target_reg_num: u5 = @truncate(@intFromEnum(target_reg));

        // Check if value is already in a register (from previous computation)
        if (self.reg_alloc) |*ra| {
            const current_regs = ra.getRegs(value_id);
            if (current_regs != 0) {
                // Value is already in some register
                const src_reg_num: u5 = @truncate(@ctz(current_regs));
                if (src_reg_num == target_reg_num) {
                    // Already in target register, nothing to do
                    ra.consumeUse(value_id);
                    return target_reg;
                } else {
                    // Move from current register to target
                    const src_reg: aarch64.Reg = @enumFromInt(src_reg_num);
                    try aarch64.movRegReg(buf, target_reg, src_reg);
                    try ra.allocSpecificReg(value_id, target_reg_num);
                    ra.consumeUse(value_id);
                    return target_reg;
                }
            }
        }

        // Value is not in a register, need to load it
        switch (value.op) {
            .const_int => {
                try aarch64.movRegImm64(buf, target_reg, value.aux_int);
            },
            .const_bool => {
                try aarch64.movRegImm64(buf, target_reg, value.aux_int);
            },
            .arg => {
                const param_idx: u32 = @intCast(value.aux_int);
                if (param_idx < arg_regs.len) {
                    if (arg_regs[param_idx] != target_reg) {
                        try aarch64.movRegReg(buf, target_reg, arg_regs[param_idx]);
                    }
                }
            },
            .load => {
                const local_idx: usize = @intCast(value.aux_int);
                const x86_offset: i32 = func.locals[local_idx].offset;
                const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                    const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                    try aarch64.ldrRegImm(buf, target_reg, .sp, offset_scaled);
                }
            },
            else => {
                // Check storage manager for value location
                if (self.storage.get(value_id)) |slot| {
                    const aarch64_offset = self.storage.aarch64Offset(slot, func.frame_size);
                    try aarch64.ldrRegImm(buf, target_reg, .sp, aarch64_offset);
                }
            },
        }

        // Mark value as now being in target_reg and consume the use
        if (self.reg_alloc) |*ra| {
            try ra.allocSpecificReg(value_id, target_reg_num);
            ra.consumeUse(value_id);
        }

        return target_reg;
    }

    /// Record that a value's result is in a register and save to storage for AArch64
    fn saveAArch64Result(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, value_idx: u32, result_reg: aarch64.Reg) !void {
        const result_reg_num: u5 = @truncate(@intFromEnum(result_reg));

        // Track in register allocator
        if (self.reg_alloc) |*ra| {
            try ra.allocSpecificReg(value_idx, result_reg_num);
        }

        // Save to storage slot for later use
        const result_slot = try self.storage.allocate(value_idx);
        const result_aarch64 = self.storage.aarch64Offset(result_slot, func.frame_size);
        try aarch64.strRegImm(buf, result_reg, .sp, result_aarch64);
    }

    /// Invalidate all caller-saved registers after a function call for AArch64
    fn invalidateAArch64CallerSaved(self: *Driver) void {
        if (self.reg_alloc) |*ra| {
            // AAPCS64 caller-saved registers: x0-x18 (x18 is platform register, often callee-saved on Apple)
            // We invalidate x0-x17 to be safe
            var i: u5 = 0;
            while (i <= 17) : (i += 1) {
                ra.freeReg(i);
            }
        }
    }

    fn generateAArch64Value(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, value: ssa.Value, value_idx: u32, stack_size: u32, has_calls: bool) !void {
        // AAPCS64 argument registers: x0-x7
        const arg_regs = [_]aarch64.Reg{ .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7 };

        switch (value.op) {
            .const_int, .const_bool, .const_string, .arg, .load => {
                // These are handled as operands when used by other ops.
                // Don't generate standalone code for them.
                // .load values are consumed inline when referenced by add, ret, map_*, etc.
            },
            .add => {
                // Binary add: look up both operands
                const args = value.args();
                if (args.len >= 2) {
                    const left_idx = args[0];
                    const right_idx = args[1];
                    const right = func.getValue(right_idx);

                    // Load left operand into x0
                    _ = try self.loadAArch64ValueToReg(buf, func, left_idx, .x0);

                    // Generate code for right operand, then add
                    if (right.op == .const_int and right.aux_int >= 0 and right.aux_int <= 4095) {
                        // add x0, x0, #imm12 (optimization for small constants)
                        const imm: u12 = @intCast(right.aux_int);
                        try aarch64.addRegImm12(buf, .x0, .x0, imm);
                        if (self.reg_alloc) |*ra| ra.consumeUse(right_idx);
                    } else {
                        // Load right operand into x9 and add
                        _ = try self.loadAArch64ValueToReg(buf, func, right_idx, .x9);
                        try aarch64.addRegReg(buf, .x0, .x0, .x9);
                    }
                }

                // Save result to storage for use by later operations
                try self.saveAArch64Result(buf, func, value_idx, .x0);
            },
            .sub => {
                // Binary sub: look up both operands
                const args = value.args();
                if (args.len >= 2) {
                    const left_idx = args[0];
                    const right_idx = args[1];

                    // Load left operand into x0
                    _ = try self.loadAArch64ValueToReg(buf, func, left_idx, .x0);
                    // Load right operand into x9, then sub
                    _ = try self.loadAArch64ValueToReg(buf, func, right_idx, .x9);
                    try aarch64.subRegReg(buf, .x0, .x0, .x9);
                }

                // Save result to storage
                try self.saveAArch64Result(buf, func, value_idx, .x0);
            },
            .mul => {
                // Binary mul: look up both operands
                const args = value.args();
                if (args.len >= 2) {
                    const left_idx = args[0];
                    const right_idx = args[1];

                    // Load left operand into x0
                    _ = try self.loadAArch64ValueToReg(buf, func, left_idx, .x0);
                    // Load right operand into x9, then mul
                    _ = try self.loadAArch64ValueToReg(buf, func, right_idx, .x9);
                    try aarch64.mulRegReg(buf, .x0, .x0, .x9);
                }

                // Save result to storage
                try self.saveAArch64Result(buf, func, value_idx, .x0);
            },
            .div => {
                // Binary div: look up both operands
                // AArch64 uses SDIV for signed division
                const args = value.args();
                if (args.len >= 2) {
                    const left_idx = args[0];
                    const right_idx = args[1];

                    // Load left operand into x0
                    _ = try self.loadAArch64ValueToReg(buf, func, left_idx, .x0);
                    // Load right operand into x9, then div
                    _ = try self.loadAArch64ValueToReg(buf, func, right_idx, .x9);
                    try aarch64.sdivRegReg(buf, .x0, .x0, .x9);
                }

                // Save result to storage
                try self.saveAArch64Result(buf, func, value_idx, .x0);
            },
            .neg => {
                // Unary negation
                const args = value.args();
                if (args.len >= 1) {
                    const operand_idx = args[0];
                    // Load operand to x0
                    _ = try self.loadAArch64ValueToReg(buf, func, operand_idx, .x0);
                    // NEG x0, x0 (sub x0, xzr, x0)
                    try aarch64.negReg(buf, .x0, .x0);
                }
                // Save result
                try self.saveAArch64Result(buf, func, value_idx, .x0);
            },
            .call => {
                // Check for builtin print/println
                if (std.mem.eql(u8, value.aux_str, "print") or std.mem.eql(u8, value.aux_str, "println")) {
                    try self.emitAArch64PrintSyscall(buf, func, value);
                } else {
                    // Set up arguments in registers, then call
                    const args = value.args();
                    for (args, 0..) |arg_id, i| {
                        if (i >= arg_regs.len) break;
                        const arg_val = func.getValue(arg_id);

                        // Move argument value to appropriate register
                        if (arg_val.op == .const_int) {
                            try aarch64.movRegImm64(buf, arg_regs[i], arg_val.aux_int);
                        } else if (arg_val.op == .arg) {
                            const param_idx: u32 = @intCast(arg_val.aux_int);
                            if (param_idx < arg_regs.len and param_idx != i) {
                                try aarch64.movRegReg(buf, arg_regs[i], arg_regs[param_idx]);
                            }
                        } else if (arg_val.op == .addr) {
                            // Address of local variable - compute stack address
                            const local_idx: usize = @intCast(arg_val.aux_int);
                            const x86_offset: i32 = func.locals[local_idx].offset;
                            const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                            // add reg, sp, #offset
                            if (local_offset >= 0 and local_offset <= 4095) {
                                try aarch64.addRegImm12(buf, arg_regs[i], .sp, @intCast(local_offset));
                            }
                        } else if (arg_val.op == .load) {
                            // Load from local variable
                            const local_idx: usize = @intCast(arg_val.aux_int);
                            const x86_offset: i32 = func.locals[local_idx].offset;
                            const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                            if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                                const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                                try aarch64.ldrRegImm(buf, arg_regs[i], .sp, offset_scaled);
                            }
                        }
                    }

                    // Emit call to function
                    const call_func_name = if (self.options.target.os == .macos)
                        try std.fmt.allocPrint(self.allocator, "_{s}", .{value.aux_str})
                    else
                        value.aux_str;
                    try aarch64.callSymbol(buf, call_func_name);
                    // Invalidate caller-saved registers since call may have clobbered them
                    self.invalidateAArch64CallerSaved();
                    // Return value is in x0 - save to storage for later use
                    const slot = try self.storage.allocate(value_idx);
                    const aarch64_offset = self.storage.aarch64Offset(slot, func.frame_size);
                    try aarch64.strRegImm(buf, .x0, .sp, aarch64_offset);
                }
            },
            .ret => {
                // Return value should be in x0
                const args = value.args();
                if (args.len > 0) {
                    const ret_val = func.getValue(args[0]);
                    const ret_idx = args[0];
                    // Use storage manager to check if value has a saved location
                    if (self.storage.get(ret_idx)) |slot| {
                        // Value was saved to storage slot - load from there
                        const aarch64_offset = self.storage.aarch64Offset(slot, func.frame_size);
                        try aarch64.ldrRegImm(buf, .x0, .sp, aarch64_offset);
                    } else if (ret_val.op == .arg) {
                        const param_idx: u32 = @intCast(ret_val.aux_int);
                        if (param_idx < arg_regs.len and param_idx != 0) {
                            try aarch64.movRegReg(buf, .x0, arg_regs[param_idx]);
                        }
                    } else if (ret_val.op == .const_int or ret_val.op == .const_bool) {
                        // Load constant into x0 for return
                        try aarch64.movRegImm64(buf, .x0, ret_val.aux_int);
                    } else if (ret_val.op == .load) {
                        // Load from local variable into x0
                        const local_idx: usize = @intCast(ret_val.aux_int);
                        const x86_offset: i32 = func.locals[local_idx].offset;
                        const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x0, .sp, offset_scaled);
                        }
                    }
                    // Note: sub, mul, div, field, index, slice_make leave result in x0
                    // and are consumed immediately - no storage needed
                }
                // Emit epilogue and ret for each return point
                // (Functions with multiple returns need each to properly exit)
                if (has_calls) {
                    try aarch64.ldpPostIndex(buf, .fp, .lr, .sp, 2);
                }
                if (stack_size <= 4095) {
                    try aarch64.addRegImm12(buf, .sp, .sp, @intCast(stack_size));
                }
                try aarch64.ret(buf);
            },
            .eq, .ne, .lt, .le, .gt, .ge => {
                // Comparison: load operands, compare, set result
                const args = value.args();
                if (args.len >= 2) {
                    const left = func.getValue(args[0]);
                    const right = func.getValue(args[1]);

                    // Load left operand into x8 (temp register)
                    if (left.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x8, left.aux_int);
                    } else if (left.op == .arg) {
                        const idx: u32 = @intCast(left.aux_int);
                        if (idx < arg_regs.len) {
                            try aarch64.movRegReg(buf, .x8, arg_regs[idx]);
                        }
                    } else if (left.op == .load) {
                        // Load from local variable into x8
                        const local_idx: usize = @intCast(left.aux_int);
                        const x86_offset: i32 = func.locals[local_idx].offset;
                        const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x8, .sp, offset_scaled);
                        }
                    } else if (left.op == .field) {
                        // Field result is in x0, move to x8
                        try aarch64.movRegReg(buf, .x8, .x0);
                    }

                    // Compare with right operand
                    if (right.op == .const_int) {
                        // cmp x8, #imm
                        const imm: u12 = @intCast(right.aux_int & 0xFFF);
                        try aarch64.cmpRegImm12(buf, .x8, imm);
                    } else if (right.op == .arg) {
                        const idx: u32 = @intCast(right.aux_int);
                        if (idx < arg_regs.len) {
                            try aarch64.cmpRegReg(buf, .x8, arg_regs[idx]);
                        }
                    } else if (right.op == .load) {
                        // Load from local variable into x9 and compare
                        const local_idx: usize = @intCast(right.aux_int);
                        const x86_offset: i32 = func.locals[local_idx].offset;
                        const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x9, .sp, offset_scaled);
                            try aarch64.cmpRegReg(buf, .x8, .x9);
                        }
                    } else if (right.op == .field) {
                        // Field result is in x0, move to x9 and compare
                        try aarch64.movRegReg(buf, .x9, .x0);
                        try aarch64.cmpRegReg(buf, .x8, .x9);
                    }
                    // Comparison result is in flags, will be used by branch
                }
            },
            .select => {
                // Conditional select: args[0] = cond, args[1] = then, args[2] = else
                // The condition (eq/ne/lt/etc or or) has already set flags
                // Use CSEL: csel x0, x8 (then), x9 (else), cond
                const args = value.args();
                if (args.len >= 3) {
                    const cond_val = func.getValue(args[0]);
                    const else_val = func.getValue(args[2]);
                    const then_val = func.getValue(args[1]);

                    // Load else value into x9
                    if (else_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x9, else_val.aux_int);
                    } else if (else_val.op == .load) {
                        const local_idx: usize = @intCast(else_val.aux_int);
                        const x86_offset: i32 = func.locals[local_idx].offset;
                        const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x9, .sp, offset_scaled);
                        }
                    } else if (else_val.op == .select) {
                        // Result of previous select is in x0, move to x9
                        try aarch64.movRegReg(buf, .x9, .x0);
                    }

                    // Load then value into x8
                    if (then_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x8, then_val.aux_int);
                    } else if (then_val.op == .load) {
                        const local_idx: usize = @intCast(then_val.aux_int);
                        const x86_offset: i32 = func.locals[local_idx].offset;
                        const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x8, .sp, offset_scaled);
                        }
                    }

                    // Determine condition for csel based on the condition operation
                    // For 'or': result is in x10, cmp x10, #0 sets ZF=0 if any true
                    //   So we use .ne to select "then" when at least one was true
                    // For 'eq' and other comparisons: use the corresponding condition
                    const cond: aarch64.Cond = switch (cond_val.op) {
                        .@"or" => .ne, // x10 != 0 means at least one was true
                        .eq => .eq,
                        .ne => .ne,
                        .lt => .lt,
                        .le => .le,
                        .gt => .gt,
                        .ge => .ge,
                        else => .eq,
                    };
                    try aarch64.csel(buf, .x0, .x8, .x9, cond);
                }
            },
            .branch => {
                // Conditional branch based on previous comparison
                // For now, emit cbz/cbnz or b.cond based on condition
                // The condition is in args[0], but we use the flags set by cmp
                const args = value.args();
                if (args.len > 0) {
                    const cond_val = func.getValue(args[0]);
                    // Emit conditional branch based on the comparison type
                    // true_block is in aux_int, false_block in aux_str
                    const true_block: u32 = @intCast(value.aux_int);
                    _ = true_block;

                    // For equality comparison, use b.eq/b.ne
                    // We'll emit a forward branch that skips the else block
                    // This is simplified - proper implementation needs block layout
                    if (cond_val.op == .eq) {
                        // b.ne to false path (skip then block if not equal)
                        // Placeholder: branch offset will be fixed later
                        try aarch64.bCond(buf, .ne, 0); // Will be patched
                    } else if (cond_val.op == .ne) {
                        try aarch64.bCond(buf, .eq, 0);
                    } else {
                        // Default: unconditional branch placeholder
                        try aarch64.b(buf, 0);
                    }
                }
            },
            .jump => {
                // Unconditional jump - emit branch instruction
                // Offset will need to be patched based on block layout
                try aarch64.b(buf, 0); // Placeholder
            },
            .store => {
                // Store value to local at optional field offset
                // args[0] = local index, args[1] = value, aux_int = field offset
                const args = value.args();
                if (args.len >= 2) {
                    const local_idx = args[0];
                    const val_id = args[1];
                    const val = func.getValue(val_id);
                    const field_offset: i32 = @intCast(value.aux_int);

                    // Convert x86-style offset to ARM64 sp-relative offset using centralized function
                    const x86_offset: i32 = func.locals[@intCast(local_idx)].offset;
                    const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                    const total_offset: i32 = local_offset + field_offset;

                    // Check if storing a slice (slice_make leaves ptr in x0, len in x1)
                    if (val.op == .slice_make) {
                        // Store 16-byte slice: ptr at offset 0, len at offset 8
                        if (total_offset >= 0 and @mod(total_offset, 8) == 0) {
                            const ptr_offset: u12 = @intCast(@divExact(total_offset, 8));
                            const len_offset: u12 = ptr_offset + 1; // +8 bytes
                            try aarch64.strRegImm(buf, .x0, .sp, ptr_offset); // store ptr
                            try aarch64.strRegImm(buf, .x1, .sp, len_offset); // store len
                        }
                    } else if (val.op == .union_init) {
                        // Store 16-byte union: tag at offset 0, payload at offset 8
                        if (total_offset >= 0 and @mod(total_offset, 8) == 0) {
                            const tag_offset: u12 = @intCast(@divExact(total_offset, 8));
                            const payload_offset: u12 = tag_offset + 1; // +8 bytes
                            try aarch64.strRegImm(buf, .x0, .sp, tag_offset); // store tag
                            try aarch64.strRegImm(buf, .x1, .sp, payload_offset); // store payload
                        }
                    } else if (val.op == .str_concat) {
                        // Store 16-byte string: ptr at offset 0, len at offset 8
                        // str_concat leaves ptr in x0, len in x1
                        if (total_offset >= 0 and @mod(total_offset, 8) == 0) {
                            const ptr_offset: u12 = @intCast(@divExact(total_offset, 8));
                            const len_offset: u12 = ptr_offset + 1; // +8 bytes
                            try aarch64.strRegImm(buf, .x0, .sp, ptr_offset); // store ptr
                            try aarch64.strRegImm(buf, .x1, .sp, len_offset); // store len
                        }
                    } else if (val.op == .const_string) {
                        // Store 16-byte string literal: load ptr (from rodata) and len (immediate)
                        const str_content = val.aux_str;
                        const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                            str_content[1 .. str_content.len - 1]
                        else
                            str_content;
                        const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
                        try aarch64.loadSymbolAddr(buf, .x0, sym_name);
                        if (total_offset >= 0 and @mod(total_offset, 8) == 0) {
                            const ptr_offset: u12 = @intCast(@divExact(total_offset, 8));
                            try aarch64.strRegImm(buf, .x0, .sp, ptr_offset); // store ptr
                        }
                        try aarch64.movRegImm64(buf, .x0, @intCast(stripped.len));
                        if (total_offset >= 0 and @mod(total_offset, 8) == 0) {
                            const len_offset: u12 = @as(u12, @intCast(@divExact(total_offset, 8))) + 1;
                            try aarch64.strRegImm(buf, .x0, .sp, len_offset); // store len
                        }
                    } else {
                        // Regular 8-byte store
                        // Get value to store into x8 (temp register), or use x0 directly for ops
                        var use_x0_directly = false;
                        if (val.op == .const_int) {
                            try aarch64.movRegImm64(buf, .x8, val.aux_int);
                        } else if (val.op == .arg) {
                            const idx: u32 = @intCast(val.aux_int);
                            if (idx < arg_regs.len) {
                                try aarch64.movRegReg(buf, .x8, arg_regs[idx]);
                            }
                        } else if (val.op == .load) {
                            // Load from local's stack slot - load ops don't emit code themselves
                            const src_local_idx: usize = @intCast(val.aux_int);
                            const src_x86_offset: i32 = func.locals[src_local_idx].offset;
                            const src_offset: i32 = FrameLayout.aarch64LocalOffset(src_x86_offset, func.frame_size);
                            if (src_offset >= 0 and @mod(src_offset, 8) == 0) {
                                const src_scaled: u12 = @intCast(@divExact(src_offset, 8));
                                try aarch64.ldrRegImm(buf, .x8, .sp, src_scaled);
                            }
                        } else if (val.op == .add or val.op == .sub or val.op == .mul or val.op == .div or
                            val.op == .call or val.op == .field or val.op == .index or
                            val.op == .slice_index or val.op == .union_payload or
                            val.op == .map_new or val.op == .map_get or val.op == .map_has or val.op == .map_size or
                            val.op == .list_new or val.op == .list_get or val.op == .list_len)
                        {
                            // Operations that leave result in x0 - store directly
                            use_x0_directly = true;
                        }

                        // Store to [sp + total_offset]
                        // strRegImm uses scaled offset (divided by 8)
                        if (total_offset >= 0 and @mod(total_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(total_offset, 8));
                            if (use_x0_directly) {
                                try aarch64.strRegImm(buf, .x0, .sp, offset_scaled);
                            } else {
                                try aarch64.strRegImm(buf, .x8, .sp, offset_scaled);
                            }
                        }
                    }
                }
            },
            .addr => {
                // Compute address of local field: add x0, sp, #(local_offset + field_offset)
                // args[0] = local index (raw), aux_int = field offset
                const args = value.args();
                if (args.len > 0) {
                    const local_idx = args[0];
                    const field_offset: i32 = @intCast(value.aux_int);
                    const x86_offset: i32 = func.locals[@intCast(local_idx)].offset;
                    const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                    const total_offset: i32 = local_offset + field_offset;
                    // add x0, sp, #offset
                    if (total_offset >= 0) {
                        try aarch64.addRegImm12(buf, .x0, .sp, @intCast(total_offset));
                    }
                }
            },
            .field => {
                // Field access: load from address
                // Two cases:
                // 1. args[0] is a local index (for direct slice.len) - check if < locals.len
                // 2. args[0] is an SSA value ID (for nested access) - address in x0
                const args = value.args();
                if (args.len > 0) {
                    const maybe_local_or_ssa = args[0];
                    const field_offset: i32 = @intCast(value.aux_int);

                    if (maybe_local_or_ssa < func.locals.len) {
                        // Direct local field access
                        const x86_offset: i32 = func.locals[@intCast(maybe_local_or_ssa)].offset;
                        const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        const total_offset: i32 = local_offset + field_offset;
                        if (total_offset >= 0 and @mod(total_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(total_offset, 8));
                            try aarch64.ldrRegImm(buf, .x0, .sp, offset_scaled);
                        }
                    } else {
                        // SSA value reference - address was computed by prior .addr op and is in x0
                        // Load from [x0 + field_offset]
                        if (field_offset >= 0 and @mod(field_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(field_offset, 8));
                            try aarch64.ldrRegImm(buf, .x0, .x0, offset_scaled);
                        } else if (field_offset == 0) {
                            try aarch64.ldrRegImm(buf, .x0, .x0, 0);
                        }
                    }
                }
            },
            .ptr_field => {
                // Load field through pointer: local holds pointer, load from ptr + offset
                // args[0] = local index holding pointer, aux_int = field offset
                const args = value.args();
                if (args.len > 0) {
                    const local_idx = args[0];
                    const field_offset: i32 = @intCast(value.aux_int);

                    // Convert x86-style negative offset to ARM64 positive sp-relative offset
                    const x86_offset: i32 = func.locals[@intCast(local_idx)].offset;
                    const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);

                    // Load the pointer into x8: ldr x8, [sp, #local_offset]
                    if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                        const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                        try aarch64.ldrRegImm(buf, .x8, .sp, offset_scaled);
                    }

                    // Load field from pointer: ldr x0, [x8, #field_offset]
                    if (field_offset >= 0 and @mod(field_offset, 8) == 0) {
                        const field_offset_scaled: u12 = @intCast(@divExact(field_offset, 8));
                        try aarch64.ldrRegImm(buf, .x0, .x8, field_offset_scaled);
                    } else {
                        // Unaligned field offset: add offset to pointer and load
                        try aarch64.addRegImm12(buf, .x8, .x8, @intCast(field_offset));
                        try aarch64.ldrRegImm(buf, .x0, .x8, 0);
                    }
                }
            },
            .index => {
                // Dynamic array indexing: load from stack[local_offset + index * elem_size]
                // args[0] = local index, args[1] = index value (SSA ref), aux_int = elem_size
                const args = value.args();
                if (args.len >= 2) {
                    const local_idx = args[0];
                    const idx_val_id = args[1];
                    const idx_val = func.getValue(idx_val_id);
                    const elem_size: i64 = value.aux_int;

                    // Get base stack offset for local (convert x86 negative to ARM64 positive)
                    const x86_offset: i32 = func.locals[@intCast(local_idx)].offset;
                    const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);

                    // Get index value into x9
                    if (idx_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x9, idx_val.aux_int);
                    } else if (idx_val.op == .arg) {
                        const idx: u32 = @intCast(idx_val.aux_int);
                        if (idx < arg_regs.len) {
                            try aarch64.movRegReg(buf, .x9, arg_regs[idx]);
                        }
                    } else if (idx_val.op == .load) {
                        // Load from a local variable using computed offset
                        const idx_local: usize = @intCast(idx_val.aux_int);
                        const idx_x86_offset: i32 = func.locals[idx_local].offset;
                        const idx_sp_offset: i32 = FrameLayout.aarch64LocalOffset(idx_x86_offset, func.frame_size);
                        if (idx_sp_offset >= 0 and @mod(idx_sp_offset, 8) == 0) {
                            const idx_scaled: u12 = @intCast(@divExact(idx_sp_offset, 8));
                            try aarch64.ldrRegImm(buf, .x9, .sp, idx_scaled);
                        }
                    } else {
                        // Assume result is in x0 from previous computation
                        try aarch64.movRegReg(buf, .x9, .x0);
                    }

                    // Load element size into x10 and multiply: x9 = x9 * elem_size
                    try aarch64.movRegImm64(buf, .x10, elem_size);
                    try aarch64.mulRegReg(buf, .x9, .x9, .x10);

                    // Compute base address: x8 = sp + local_offset
                    if (local_offset >= 0 and local_offset <= 4095) {
                        try aarch64.addRegImm12(buf, .x8, .sp, @intCast(local_offset));
                    }

                    // Add index offset: x8 = x8 + x9
                    try aarch64.addRegReg(buf, .x8, .x8, .x9);

                    // Load value from [x8]: ldr x0, [x8, #0]
                    try aarch64.ldrRegImm(buf, .x0, .x8, 0);
                }
            },
            .slice_make => {
                // Slice construction from array
                // args[0] = array local index (raw), args[1] = start (SSA), args[2] = end (SSA)
                // aux_int = element size
                // Result: x0 = ptr (base + start*elem_size), x1 = len (end - start)
                const args = value.args();
                if (args.len >= 3) {
                    const local_idx = args[0];
                    const start_id = args[1];
                    const end_id = args[2];
                    const elem_size: i64 = value.aux_int;

                    const start_val = func.getValue(start_id);
                    const end_val = func.getValue(end_id);

                    // Get array base address into x8
                    const x86_offset: i32 = func.locals[@intCast(local_idx)].offset;
                    const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);

                    if (local_offset >= 0 and local_offset <= 4095) {
                        try aarch64.addRegImm12(buf, .x8, .sp, @intCast(local_offset));
                    }

                    // Get start value into x9
                    if (start_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x9, start_val.aux_int);
                    }

                    // Get end value into x10
                    if (end_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x10, end_val.aux_int);
                    }

                    // Compute len = end - start -> x1
                    try aarch64.subRegReg(buf, .x1, .x10, .x9);

                    // Compute ptr = base + start * elem_size -> x0
                    // First: x11 = start * elem_size
                    try aarch64.movRegImm64(buf, .x11, elem_size);
                    try aarch64.mulRegReg(buf, .x11, .x9, .x11);
                    // Then: x0 = base + x11
                    try aarch64.addRegReg(buf, .x0, .x8, .x11);
                }
            },
            .slice_index => {
                // Slice indexing: load ptr from slice, compute ptr + index*elem_size, load value
                // args[0] = slice local index (raw), args[1] = index value (SSA ref)
                // aux_int = element size
                // Result: x0 = value at slice[index]
                const args = value.args();
                if (args.len >= 2) {
                    const local_idx = args[0];
                    const idx_val_id = args[1];
                    const idx_val = func.getValue(idx_val_id);
                    const elem_size: i64 = value.aux_int;

                    // Get slice's stack offset (convert x86 negative to ARM64 positive)
                    const x86_offset: i32 = func.locals[@intCast(local_idx)].offset;
                    const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);

                    // Load slice ptr (first 8 bytes) into x8
                    if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                        const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                        try aarch64.ldrRegImm(buf, .x8, .sp, offset_scaled);
                    }

                    // Get index value into x9
                    if (idx_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x9, idx_val.aux_int);
                    } else if (idx_val.op == .arg) {
                        const idx: u32 = @intCast(idx_val.aux_int);
                        if (idx < arg_regs.len) {
                            try aarch64.movRegReg(buf, .x9, arg_regs[idx]);
                        }
                    } else if (idx_val.op == .load) {
                        const idx_local: usize = @intCast(idx_val.aux_int);
                        const idx_x86_offset: i32 = func.locals[idx_local].offset;
                        const idx_sp_offset: i32 = FrameLayout.aarch64LocalOffset(idx_x86_offset, func.frame_size);
                        if (idx_sp_offset >= 0 and @mod(idx_sp_offset, 8) == 0) {
                            const idx_scaled: u12 = @intCast(@divExact(idx_sp_offset, 8));
                            try aarch64.ldrRegImm(buf, .x9, .sp, idx_scaled);
                        }
                    } else {
                        // Assume result is in x0 from previous computation
                        try aarch64.movRegReg(buf, .x9, .x0);
                    }

                    // Multiply index by element size: x9 = x9 * elem_size
                    try aarch64.movRegImm64(buf, .x10, elem_size);
                    try aarch64.mulRegReg(buf, .x9, .x9, .x10);

                    // Add to ptr: x8 = x8 + x9
                    try aarch64.addRegReg(buf, .x8, .x8, .x9);

                    // Load value from [x8]: ldr x0, [x8, #0]
                    try aarch64.ldrRegImm(buf, .x0, .x8, 0);
                }
            },
            .union_init => {
                // Initialize a tagged union value
                // aux_int = variant index (tag), args[0] = payload value (if any)
                // Union layout: tag (8 bytes) at offset 0, payload at offset 8
                const variant_idx: i64 = value.aux_int;

                // Store tag in x0 (for later store)
                try aarch64.movRegImm64(buf, .x0, variant_idx);

                // If there's a payload, get it into x1
                const args = value.args();
                if (args.len > 0) {
                    const payload_id = args[0];
                    const payload_val = func.getValue(payload_id);
                    if (payload_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x1, payload_val.aux_int);
                    } else {
                        // Payload should be in x0 from previous computation, save tag first
                        try aarch64.movRegReg(buf, .x8, .x0); // save tag
                        // The payload computation left result in x0, move to x1
                        try aarch64.movRegReg(buf, .x1, .x0);
                        try aarch64.movRegReg(buf, .x0, .x8); // restore tag
                    }
                }
                // Result: x0 = tag, x1 = payload (if any)
            },
            .union_tag => {
                // Extract tag from union value
                // Union layout: tag (8 bytes) at offset 0
                const args = value.args();
                if (args.len > 0) {
                    const union_id = args[0];
                    const union_val = func.getValue(union_id);
                    // If the union value is a load, get its address
                    if (union_val.op == .load) {
                        const local_idx: usize = @intCast(union_val.aux_int);
                        const x86_offset: i32 = func.locals[local_idx].offset;
                        // Convert x86 (rbp-relative negative) to ARM (sp-relative positive)
                        const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x0, .sp, offset_scaled);
                        }
                    }
                }
            },
            .union_payload => {
                // Extract payload from union value
                // Union layout: tag (8 bytes) at offset 0, payload at offset 8
                const args = value.args();
                if (args.len > 0) {
                    const union_id = args[0];
                    const union_val = func.getValue(union_id);
                    // If the union value is a load, get its address
                    if (union_val.op == .load) {
                        const local_idx: usize = @intCast(union_val.aux_int);
                        const x86_offset: i32 = func.locals[local_idx].offset;
                        // Convert x86 (rbp-relative negative) to ARM (sp-relative positive)
                        // Add 8 for payload offset within union
                        const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size) + 8;
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x0, .sp, offset_scaled);
                        }
                    }
                }
            },
            .@"or" => {
                // Logical OR: combine two comparison results
                // Strategy: capture each comparison result as 0/1, then OR them
                const args = value.args();
                if (args.len >= 2) {
                    const left = func.getValue(args[0]);
                    const right = func.getValue(args[1]);

                    // Helper to get comparison result into x10 or x11
                    // After comparison, use csel to convert flags to 0/1

                    // Load 1 and 0 for csel
                    try aarch64.movRegImm64(buf, .x12, 1);

                    // Get left comparison result
                    if (left.op == .eq or left.op == .ne or left.op == .lt or
                        left.op == .le or left.op == .gt or left.op == .ge)
                    {
                        // Re-generate the comparison
                        try self.generateAArch64Comparison(buf, func, left.*);
                        // csel x10, x12, xzr, eq - x10 = 1 if equal, else 0
                        const cond: aarch64.Cond = switch (left.op) {
                            .eq => .eq,
                            .ne => .ne,
                            .lt => .lt,
                            .le => .le,
                            .gt => .gt,
                            .ge => .ge,
                            else => .eq,
                        };
                        try aarch64.csel(buf, .x10, .x12, aarch64.zr, cond);
                    } else if (left.op == .@"or") {
                        // Left is already an OR - its result should be in x10
                        // Just keep it
                    }

                    // Get right comparison result
                    if (right.op == .eq or right.op == .ne or right.op == .lt or
                        right.op == .le or right.op == .gt or right.op == .ge)
                    {
                        // Re-generate the comparison
                        try self.generateAArch64Comparison(buf, func, right.*);
                        // csel x11, x12, xzr, eq - x11 = 1 if equal, else 0
                        const cond: aarch64.Cond = switch (right.op) {
                            .eq => .eq,
                            .ne => .ne,
                            .lt => .lt,
                            .le => .le,
                            .gt => .gt,
                            .ge => .ge,
                            else => .eq,
                        };
                        try aarch64.csel(buf, .x11, .x12, aarch64.zr, cond);
                    } else if (right.op == .@"or") {
                        // Right is already an OR - recurse handled its result
                        // Move it to x11 if needed
                        try aarch64.movRegReg(buf, .x11, .x10);
                    }

                    // Combine: orr x10, x10, x11
                    try aarch64.orrRegReg(buf, .x10, .x10, .x11);

                    // Set flags for subsequent select: cmp x10, #0
                    // If x10 > 0, at least one was true (ZF = 0)
                    // If x10 == 0, both false (ZF = 1)
                    try aarch64.cmpRegImm12(buf, .x10, 0);
                }
            },
            // Map operations - native codegen implementation
            // Map layout:
            //   Header (32 bytes): capacity (8), size (8), seed (8), unused (8)
            //   Slots (64 x 32 bytes = 2048 bytes): meta (1), pad (7), key_ptr (8), key_len (8), value (8)
            //   Total: 2080 bytes
            // Slot meta: 0 = empty, 1 = occupied, 2 = deleted
            .map_new => {
                // Call calloc(1, 2080) to allocate zeroed map
                // AArch64 ABI: x0=nmemb, x1=size
                try aarch64.movRegImm64(buf, .x0, 1);
                try aarch64.movRegImm64(buf, .x1, 2080); // 32 header + 64*32 slots
                const calloc_name = if (self.options.target.os == .macos) "_calloc" else "calloc";
                try aarch64.callSymbol(buf, calloc_name);
                self.invalidateAArch64CallerSaved();
                // x0 now has pointer to zeroed map

                // Initialize capacity field at offset 0 to 64
                try aarch64.movRegImm64(buf, .x1, 64);
                try aarch64.strRegImm(buf, .x1, .x0, 0); // [x0+0] = 64

                // size at offset 8 is already 0 from calloc
                // seed at offset 16 - initialize to FNV offset basis
                try aarch64.movRegImm64(buf, .x1, @as(i64, @bitCast(@as(u64, 0xcbf29ce484222325))));
                try aarch64.strRegImm(buf, .x1, .x0, 2); // [x0+16] = FNV offset (offset is scaled by 8)

                // Result (map pointer) is in x0
            },
            .map_set => {
                // Call cot_native_map_set(map, key_ptr, key_len, value) - 4 args
                // AArch64 ABI: x0=map, x1=key_ptr, x2=key_len, x3=value
                // Lowerer emits: args[0]=handle, args[1]=key, args[2]=value
                const args = value.args();

                // Load map pointer from local into x0
                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const x86_offset = self.getLocalOffset(func, local_idx);
                        const local_offset = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x0, .sp, offset_scaled);
                        }
                    } else if (handle_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x0, handle_val.aux_int);
                    }
                }

                // Load key_ptr and key_len from key string
                if (args.len > 1) {
                    const key_val = func.getValue(args[1]);
                    if (key_val.op == .const_string) {
                        const str_content = key_val.aux_str;
                        const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                            str_content[1 .. str_content.len - 1]
                        else
                            str_content;
                        const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
                        // x1 = key_ptr
                        try aarch64.loadSymbolAddr(buf, .x1, sym_name);
                        // x2 = key_len
                        try aarch64.movRegImm64(buf, .x2, @intCast(stripped.len));
                    }
                }

                // Load value into x3
                if (args.len > 2) {
                    const val_val = func.getValue(args[2]);
                    if (val_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x3, val_val.aux_int);
                    } else if (val_val.op == .load or val_val.op == .copy) {
                        const local_idx: u32 = @intCast(val_val.aux_int);
                        const x86_offset = self.getLocalOffset(func, local_idx);
                        const local_offset = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x3, .sp, offset_scaled);
                        }
                    }
                }

                const map_set_name = if (self.options.target.os == .macos) "_cot_native_map_set" else "cot_native_map_set";
                try aarch64.callSymbol(buf, map_set_name);
                self.invalidateAArch64CallerSaved();
                // Result is in x0
            },
            .map_get => {
                // Call cot_native_map_get(map, key_ptr, key_len) - 3 args
                // AArch64 ABI: x0=map, x1=key_ptr, x2=key_len
                // Lowerer emits: args[0]=handle, args[1]=key
                const args = value.args();

                // Load map pointer from local into x0
                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const x86_offset = self.getLocalOffset(func, local_idx);
                        const local_offset = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x0, .sp, offset_scaled);
                        }
                    } else if (handle_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x0, handle_val.aux_int);
                    }
                }

                // Load key_ptr and key_len from key string
                if (args.len > 1) {
                    const key_val = func.getValue(args[1]);
                    if (key_val.op == .const_string) {
                        const str_content = key_val.aux_str;
                        const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                            str_content[1 .. str_content.len - 1]
                        else
                            str_content;
                        const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
                        // x1 = key_ptr
                        try aarch64.loadSymbolAddr(buf, .x1, sym_name);
                        // x2 = key_len
                        try aarch64.movRegImm64(buf, .x2, @intCast(stripped.len));
                    }
                }

                const map_get_name = if (self.options.target.os == .macos) "_cot_native_map_get" else "cot_native_map_get";
                try aarch64.callSymbol(buf, map_get_name);
                self.invalidateAArch64CallerSaved();
                // Result is in x0
            },
            .map_has => {
                // Call cot_native_map_has(map, key_ptr, key_len) - 3 args
                // AArch64 ABI: x0=map, x1=key_ptr, x2=key_len
                // Lowerer emits: args[0]=handle, args[1]=key
                const args = value.args();

                // Load map pointer from local into x0
                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const x86_offset = self.getLocalOffset(func, local_idx);
                        const local_offset = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x0, .sp, offset_scaled);
                        }
                    } else if (handle_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x0, handle_val.aux_int);
                    }
                }

                // Load key_ptr and key_len from key string
                if (args.len > 1) {
                    const key_val = func.getValue(args[1]);
                    if (key_val.op == .const_string) {
                        const str_content = key_val.aux_str;
                        const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                            str_content[1 .. str_content.len - 1]
                        else
                            str_content;
                        const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
                        // x1 = key_ptr
                        try aarch64.loadSymbolAddr(buf, .x1, sym_name);
                        // x2 = key_len
                        try aarch64.movRegImm64(buf, .x2, @intCast(stripped.len));
                    }
                }

                const map_has_name = if (self.options.target.os == .macos) "_cot_native_map_has" else "cot_native_map_has";
                try aarch64.callSymbol(buf, map_has_name);
                self.invalidateAArch64CallerSaved();
                // Result is in x0
            },
            .map_size => {
                // Call cot_native_map_size(map) - 1 arg
                // Lowerer emits: args[0]=handle
                const args = value.args();

                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const x86_offset = self.getLocalOffset(func, local_idx);
                        const local_offset = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x0, .sp, offset_scaled);
                        }
                    } else if (handle_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x0, handle_val.aux_int);
                    }
                }
                const map_size_name = if (self.options.target.os == .macos) "_cot_native_map_size" else "cot_native_map_size";
                try aarch64.callSymbol(buf, map_size_name);
                self.invalidateAArch64CallerSaved();
                // Result is in x0
            },
            .map_free => {
                // Call cot_native_map_free(map) - 1 arg, no return
                // Lowerer emits: args[0]=handle
                const args = value.args();

                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const x86_offset = self.getLocalOffset(func, local_idx);
                        const local_offset = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x0, .sp, offset_scaled);
                        }
                    } else if (handle_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x0, handle_val.aux_int);
                    }
                }
                const map_free_name = if (self.options.target.os == .macos) "_cot_native_map_free" else "cot_native_map_free";
                try aarch64.callSymbol(buf, map_free_name);
                self.invalidateAArch64CallerSaved();
            },
            // ========== List Operations (native layout + FFI) ==========
            // List layout (24 bytes):
            //   elements_ptr (8): pointer to heap-allocated element array
            //   length (8): current number of elements
            //   capacity (8): allocated capacity
            .list_new => {
                // Call calloc(1, 24) to allocate zeroed list header
                // AArch64 ABI: x0=nmemb, x1=size
                try aarch64.movRegImm64(buf, .x0, 1);
                try aarch64.movRegImm64(buf, .x1, 24); // 24-byte header
                const calloc_name = if (self.options.target.os == .macos) "_calloc" else "calloc";
                try aarch64.callSymbol(buf, calloc_name);
                self.invalidateAArch64CallerSaved();
                // x0 now has pointer to zeroed list header
                // All fields (elements_ptr=0, length=0, capacity=0) already correct from calloc
            },
            .list_push => {
                // Call cot_native_list_push(list, value) - grows if needed
                // AArch64 ABI: x0=list, x1=value
                const args = value.args();
                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const x86_offset = self.getLocalOffset(func, local_idx);
                        const local_offset = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x0, .sp, offset_scaled);
                        }
                    } else if (handle_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x0, handle_val.aux_int);
                    }
                }
                if (args.len > 1) {
                    const val_val = func.getValue(args[1]);
                    if (val_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x1, val_val.aux_int);
                    } else if (val_val.op == .load or val_val.op == .copy) {
                        const local_idx: u32 = @intCast(val_val.aux_int);
                        const x86_offset = self.getLocalOffset(func, local_idx);
                        const local_offset = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x1, .sp, offset_scaled);
                        }
                    }
                }
                const list_push_name = if (self.options.target.os == .macos) "_cot_native_list_push" else "cot_native_list_push";
                try aarch64.callSymbol(buf, list_push_name);
                self.invalidateAArch64CallerSaved();
            },
            .list_get => {
                // Call cot_native_list_get(list, index) - returns element value
                // AArch64 ABI: x0=list, x1=index
                const args = value.args();
                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const x86_offset = self.getLocalOffset(func, local_idx);
                        const local_offset = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x0, .sp, offset_scaled);
                        }
                    } else if (handle_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x0, handle_val.aux_int);
                    }
                }
                if (args.len > 1) {
                    const idx_val = func.getValue(args[1]);
                    if (idx_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x1, idx_val.aux_int);
                    } else if (idx_val.op == .load or idx_val.op == .copy) {
                        const local_idx: u32 = @intCast(idx_val.aux_int);
                        const x86_offset = self.getLocalOffset(func, local_idx);
                        const local_offset = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x1, .sp, offset_scaled);
                        }
                    }
                }
                const list_get_name = if (self.options.target.os == .macos) "_cot_native_list_get" else "cot_native_list_get";
                try aarch64.callSymbol(buf, list_get_name);
                self.invalidateAArch64CallerSaved();
                // Result is in x0 - save to storage for later use
                const slot = try self.storage.allocate(value_idx);
                const aarch64_offset = self.storage.aarch64Offset(slot, func.frame_size);
                try aarch64.strRegImm(buf, .x0, .sp, aarch64_offset);
            },
            .list_len => {
                // Read length field from list header (offset 8)
                // Inline implementation - no FFI needed
                const args = value.args();
                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const x86_offset = self.getLocalOffset(func, local_idx);
                        const local_offset = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x1, .sp, offset_scaled); // x1 = list ptr
                        }
                    } else if (handle_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x1, handle_val.aux_int);
                    }
                }
                // Load length from [x1 + 8] into x0
                // LDR x0, [x1, #8] - offset is byte offset for LDR with imm
                try aarch64.ldrRegImm(buf, .x0, .x1, 1); // offset_scaled=1 means 8 bytes
            },
            .list_free => {
                // Call cot_native_list_free(list) - frees elements array and header
                const args = value.args();
                if (args.len > 0) {
                    const handle_val = func.getValue(args[0]);
                    if (handle_val.op == .load or handle_val.op == .copy) {
                        const local_idx: u32 = @intCast(handle_val.aux_int);
                        const x86_offset = self.getLocalOffset(func, local_idx);
                        const local_offset = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x0, .sp, offset_scaled);
                        }
                    } else if (handle_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x0, handle_val.aux_int);
                    }
                }
                const list_free_name = if (self.options.target.os == .macos) "_cot_native_list_free" else "cot_native_list_free";
                try aarch64.callSymbol(buf, list_free_name);
                self.invalidateAArch64CallerSaved();
            },
            .str_concat => {
                // Call cot_str_concat(ptr1, len1, ptr2, len2)
                // AAPCS64: x0=ptr1, x1=len1, x2=ptr2, x3=len2
                // Returns: x0=new_ptr, x1=new_len (struct return)
                const args = value.args();

                // Load first string (ptr1 -> x0, len1 -> x1)
                if (args.len > 0) {
                    const str1_val = func.getValue(args[0]);
                    if (str1_val.op == .const_string) {
                        const str_content = str1_val.aux_str;
                        const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                            str_content[1 .. str_content.len - 1]
                        else
                            str_content;
                        const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
                        try aarch64.loadSymbolAddr(buf, .x0, sym_name);
                        try aarch64.movRegImm64(buf, .x1, @intCast(stripped.len));
                    } else if (str1_val.op == .load or str1_val.op == .copy) {
                        // Load string from local (ptr at offset, len at offset+8)
                        const local_idx: u32 = @intCast(str1_val.aux_int);
                        const x86_offset = self.getLocalOffset(func, local_idx);
                        const local_offset = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x0, .sp, offset_scaled); // ptr
                            try aarch64.ldrRegImm(buf, .x1, .sp, offset_scaled + 1); // len (next 8 bytes)
                        }
                    }
                }

                // Load second string (ptr2 -> x2, len2 -> x3)
                if (args.len > 1) {
                    const str2_val = func.getValue(args[1]);
                    if (str2_val.op == .const_string) {
                        const str_content = str2_val.aux_str;
                        const stripped = if (str_content.len >= 2 and str_content[0] == '"' and str_content[str_content.len - 1] == '"')
                            str_content[1 .. str_content.len - 1]
                        else
                            str_content;
                        const sym_name = try std.fmt.allocPrint(self.allocator, "__str_{d}", .{@as(u32, @truncate(std.hash.Wyhash.hash(0, stripped)))});
                        try aarch64.loadSymbolAddr(buf, .x2, sym_name);
                        try aarch64.movRegImm64(buf, .x3, @intCast(stripped.len));
                    } else if (str2_val.op == .load or str2_val.op == .copy) {
                        // Load string from local (ptr at offset, len at offset+8)
                        const local_idx: u32 = @intCast(str2_val.aux_int);
                        const x86_offset = self.getLocalOffset(func, local_idx);
                        const local_offset = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x2, .sp, offset_scaled); // ptr
                            try aarch64.ldrRegImm(buf, .x3, .sp, offset_scaled + 1); // len
                        }
                    }
                }

                const str_concat_name = if (self.options.target.os == .macos) "_cot_str_concat" else "cot_str_concat";
                try aarch64.callSymbol(buf, str_concat_name);
                self.invalidateAArch64CallerSaved();
                // Result: x0 = new ptr, x1 = new len
            },
            else => {
                // Warn about unhandled ops in debug mode
                if (self.options.debug_codegen) {
                    std.debug.print("  [WARN] Unhandled AArch64 SSA op: {s}\n", .{@tagName(value.op)});
                }
            },
        }
    }

    /// Generate ARM64 code for a comparison operation (helper for or/and)
    fn generateAArch64Comparison(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, cmp_value: ssa.Value) !void {
        _ = self;
        const arg_regs = [_]aarch64.Reg{ .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7 };
        const cmp_args = cmp_value.args();
        if (cmp_args.len >= 2) {
            const left = func.getValue(cmp_args[0]);
            const right = func.getValue(cmp_args[1]);

            // Load left operand into x8
            if (left.op == .const_int) {
                try aarch64.movRegImm64(buf, .x8, left.aux_int);
            } else if (left.op == .arg) {
                const idx: u32 = @intCast(left.aux_int);
                if (idx < arg_regs.len) {
                    try aarch64.movRegReg(buf, .x8, arg_regs[idx]);
                }
            } else if (left.op == .load) {
                const local_idx: usize = @intCast(left.aux_int);
                const x86_offset: i32 = func.locals[local_idx].offset;
                const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                    const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                    try aarch64.ldrRegImm(buf, .x8, .sp, offset_scaled);
                }
            }

            // Compare with right operand
            if (right.op == .const_int) {
                const imm: u12 = @intCast(right.aux_int & 0xFFF);
                try aarch64.cmpRegImm12(buf, .x8, imm);
            } else if (right.op == .arg) {
                const idx: u32 = @intCast(right.aux_int);
                if (idx < arg_regs.len) {
                    try aarch64.cmpRegReg(buf, .x8, arg_regs[idx]);
                }
            } else if (right.op == .load) {
                const local_idx: usize = @intCast(right.aux_int);
                const x86_offset: i32 = func.locals[local_idx].offset;
                const local_offset: i32 = FrameLayout.aarch64LocalOffset(x86_offset, func.frame_size);
                if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                    const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                    try aarch64.ldrRegImm(buf, .x9, .sp, offset_scaled);
                    try aarch64.cmpRegReg(buf, .x8, .x9);
                }
            }
        }
    }

    /// Generate code for a single SSA value and record branch positions for patching
    fn generateAArch64ValueWithPatching(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, value: ssa.Value, value_idx: u32, patches: *std.ArrayList(BranchPatch), stack_size: u32, has_calls: bool) !void {

        // For branch and jump, record position for patching
        switch (value.op) {
            .branch => {
                // Branch: conditional jump based on comparison result
                // aux_int packs both blocks: lower 32 = true, upper 32 = false
                // We emit: conditional jump to false block, then unconditional jump to true block
                const cond_pos = buf.pos();

                // Extract block IDs from aux_int
                const true_block: u32 = @truncate(@as(u64, @bitCast(value.aux_int)));
                const false_block: u32 = @truncate(@as(u64, @bitCast(value.aux_int)) >> 32);

                // Emit the conditional branch to FALSE block (will be patched later)
                const args = value.args();
                if (args.len > 0) {
                    const cond_val = func.getValue(args[0]);
                    if (cond_val.op == .const_bool) {
                        // Constant-folded condition: emit unconditional jump to appropriate block
                        const target = if (cond_val.aux_int != 0) true_block else false_block;
                        try aarch64.b(buf, 0);
                        try patches.append(self.allocator, .{
                            .position = cond_pos,
                            .is_conditional = false,
                            .target_block = target,
                        });
                        // No need to emit second jump - we only go one way
                        return;
                    } else if (cond_val.op == .eq) {
                        // For "if equal", branch to false block if NOT equal
                        try aarch64.bCond(buf, .ne, 0);
                    } else if (cond_val.op == .ne) {
                        // For "if not equal", branch to false block if equal
                        try aarch64.bCond(buf, .eq, 0);
                    } else if (cond_val.op == .lt) {
                        // For "if less than", branch to false block if >=
                        try aarch64.bCond(buf, .ge, 0);
                    } else if (cond_val.op == .le) {
                        // For "if less or equal", branch to false block if >
                        try aarch64.bCond(buf, .gt, 0);
                    } else if (cond_val.op == .gt) {
                        // For "if greater than", branch to false block if <=
                        try aarch64.bCond(buf, .le, 0);
                    } else if (cond_val.op == .ge) {
                        // For "if greater or equal", branch to false block if <
                        try aarch64.bCond(buf, .lt, 0);
                    } else {
                        try aarch64.b(buf, 0);
                    }
                } else {
                    try aarch64.b(buf, 0);
                }

                // Record patch targeting FALSE block for conditional branch
                try patches.append(self.allocator, .{
                    .position = cond_pos,
                    .is_conditional = true,
                    .target_block = false_block,
                });

                // Emit unconditional jump to TRUE block (can't rely on fall-through)
                const true_pos = buf.pos();
                try aarch64.b(buf, 0);
                try patches.append(self.allocator, .{
                    .position = true_pos,
                    .is_conditional = false,
                    .target_block = true_block,
                });
            },
            .jump => {
                // Unconditional jump to target block
                const target_block: u32 = @intCast(value.aux_int);
                const pos = buf.pos();
                try aarch64.b(buf, 0);

                try patches.append(self.allocator, .{
                    .position = pos,
                    .is_conditional = false,
                    .target_block = target_block,
                });
            },
            else => {
                // Use the regular code generator for non-branch ops
                try self.generateAArch64Value(buf, func, value, value_idx, stack_size, has_calls);
            },
        }
    }

    fn link(self: *Driver, obj_path: []const u8) ![]const u8 {
        const exe_path = self.options.getOutputPath();

        // Build linker command based on target
        var argv: std.ArrayList([]const u8) = .{ .items = &.{}, .capacity = 0 };
        defer argv.deinit(self.allocator);

        switch (self.options.target.os) {
            .macos => {
                // macOS: use zig cc for consistent cross-platform linking
                try argv.append(self.allocator, "zig");
                try argv.append(self.allocator, "cc");
                try argv.append(self.allocator, "-o");
                try argv.append(self.allocator, exe_path);
                try argv.append(self.allocator, obj_path);
                try argv.append(self.allocator, "-lSystem");
                // Link with runtime library for map operations (use static lib directly)
                try argv.append(self.allocator, "./zig-out/lib/libcot_runtime.a");
            },
            .linux => {
                // Linux: use zig cc for consistent cross-platform linking
                try argv.append(self.allocator, "zig");
                try argv.append(self.allocator, "cc");
                try argv.append(self.allocator, "-o");
                try argv.append(self.allocator, exe_path);
                try argv.append(self.allocator, obj_path);
                // Link with runtime library for map operations (use static lib directly)
                try argv.append(self.allocator, "./zig-out/lib/libcot_runtime.a");
            },
            .windows => {
                // Windows: use link.exe
                try argv.append(self.allocator, "link.exe");
                try argv.append(self.allocator, "/OUT:");
                try argv.append(self.allocator, exe_path);
                try argv.append(self.allocator, obj_path);
            },
        }

        if (self.options.verbose) {
            std.debug.print("  Linking: ", .{});
            for (argv.items) |arg| {
                std.debug.print("{s} ", .{arg});
            }
            std.debug.print("\n", .{});
        }

        // Run linker
        var child = std.process.Child.init(argv.items, self.allocator);
        child.spawn() catch {
            return error.LinkError;
        };

        const term = child.wait() catch {
            return error.LinkError;
        };

        if (term.Exited != 0) {
            std.debug.print("Linker failed with code {d}\n", .{term.Exited});
            return error.LinkError;
        }

        if (self.options.verbose) {
            std.debug.print("  Created {s}\n", .{exe_path});
        }

        return exe_path;
    }
};

// ============================================================================
// Convenience Functions
// ============================================================================

/// Compile a single file with default options
pub fn compileFile(allocator: Allocator, path: []const u8) CompileResult {
    var driver = Driver.init(allocator, .{ .input_path = path });
    defer driver.deinit();
    return driver.compile();
}

/// Compile with full options
pub fn compileWithOptions(allocator: Allocator, options: CompileOptions) CompileResult {
    var driver = Driver.init(allocator, options);
    defer driver.deinit();
    return driver.compile();
}

// ============================================================================
// Tests
// ============================================================================

test "driver init" {
    const allocator = std.testing.allocator;
    var driver = Driver.init(allocator, .{ .input_path = "test.cot" });
    defer driver.deinit();

    try std.testing.expectEqualStrings("test.cot", driver.options.input_path);
}

test "target detection" {
    const target = Target.native();
    // Should detect current platform
    try std.testing.expect(target.arch == .x86_64 or target.arch == .aarch64);
}

test "output path derivation" {
    const opts = CompileOptions{
        .input_path = "foo/bar/test.cot",
        .output_kind = .executable,
    };
    const out = opts.getOutputPath();
    try std.testing.expectEqualStrings("test", out);
}

// Exhaustive switch test - ensures all IR ops are accounted for.
// If a new IR op is added, this test will fail to compile.
test "IR op coverage - exhaustive" {
    const ir_ops = [_]ir.Op{
        // Constants
        .const_int, .const_float, .const_string, .const_bool, .const_null,
        // Variables
        .local, .global, .param,
        // Arithmetic
        .add, .sub, .mul, .div, .mod, .neg,
        // Comparison
        .eq, .ne, .lt, .le, .gt, .ge,
        // Logical
        .@"and", .@"or", .not,
        // Bitwise
        .bit_and, .bit_or, .bit_xor, .bit_not, .shl, .shr,
        // Memory
        .load, .store, .addr_local, .addr_field, .addr_index,
        // Struct/Array/Union
        .field, .ptr_field, .index, .slice, .slice_index,
        .union_init, .union_tag, .union_payload,
        // Map operations
        .map_new, .map_set, .map_get, .map_has, .map_size, .map_free,
        // List operations
        .list_new, .list_push, .list_get, .list_len, .list_free,
        // String operations
        .str_concat,
        // Control Flow
        .call, .ret, .jump, .branch, .phi, .select,
        // Conversions
        .convert, .ptr_cast,
        // Misc
        .nop,
    };
    // This switch must be exhaustive - will fail to compile if IR.Op has new values
    for (ir_ops) |op| {
        const is_valid = switch (op) {
            .const_int, .const_float, .const_string, .const_bool, .const_null,
            .local, .global, .param,
            .add, .sub, .mul, .div, .mod, .neg,
            .eq, .ne, .lt, .le, .gt, .ge,
            .@"and", .@"or", .not,
            .bit_and, .bit_or, .bit_xor, .bit_not, .shl, .shr,
            .load, .store, .addr_local, .addr_field, .addr_index,
            .field, .ptr_field, .index, .slice, .slice_index,
            .union_init, .union_tag, .union_payload,
            .map_new, .map_set, .map_get, .map_has, .map_size, .map_free,
            .list_new, .list_push, .list_get, .list_len, .list_free,
            .str_concat,
            .call, .ret, .jump, .branch, .phi, .select,
            .convert, .ptr_cast,
            .nop,
            => true,
        };
        try std.testing.expect(is_valid);
    }
}

// Exhaustive switch test - ensures all SSA ops are accounted for.
// If a new SSA op is added, this test will fail to compile.
test "SSA op coverage - exhaustive" {
    const ssa_ops = [_]ssa.Op{
        // Constants
        .const_int, .const_float, .const_string, .const_bool, .const_nil,
        // SSA specific
        .phi, .copy,
        // Arithmetic
        .add, .sub, .mul, .div, .mod, .neg,
        // Comparison
        .eq, .ne, .lt, .le, .gt, .ge,
        // Logical
        .@"and", .@"or", .not,
        // Select
        .select,
        // Memory
        .load, .store, .addr, .alloc,
        // Struct/array
        .field, .ptr_field, .index,
        // Slice
        .slice_make, .slice_index,
        // Union
        .union_init, .union_tag, .union_payload,
        // Map operations
        .map_new, .map_set, .map_get, .map_has, .map_size, .map_free,
        // List operations
        .list_new, .list_push, .list_get, .list_len, .list_free,
        // String operations
        .str_concat,
        // Function
        .call, .arg,
        // ARC
        .retain, .release,
        // Control
        .ret, .jump, .branch, .@"unreachable",
    };
    // This switch must be exhaustive - will fail to compile if SSA.Op has new values
    for (ssa_ops) |op| {
        const is_valid = switch (op) {
            .const_int, .const_float, .const_string, .const_bool, .const_nil,
            .phi, .copy,
            .add, .sub, .mul, .div, .mod, .neg,
            .eq, .ne, .lt, .le, .gt, .ge,
            .@"and", .@"or", .not,
            .select,
            .load, .store, .addr, .alloc,
            .field, .ptr_field, .index,
            .slice_make, .slice_index,
            .union_init, .union_tag, .union_payload,
            .map_new, .map_set, .map_get, .map_has, .map_size, .map_free,
            .list_new, .list_push, .list_get, .list_len, .list_free,
            .str_concat,
            .call, .arg,
            .retain, .release,
            .ret, .jump, .branch, .@"unreachable",
            => true,
        };
        try std.testing.expect(is_valid);
    }
}

// ============================================================================
// Frame Layout Safety Tests - CRITICAL FOR PREVENTING MEMORY CORRUPTION
// ============================================================================
//
// These tests verify that stack offset calculations are correct.
// If these tests fail, local variables will overlap with saved registers
// and corrupt the return address, causing crashes.

test "FrameLayout AArch64 - local at offset -8 with frame_size 16" {
    // Most common case: first local variable
    // x86 layout: [rbp-8] = first local
    // ARM64 layout: [sp+0] = fp, [sp+8] = lr, [sp+16+] = locals
    // Expected: 16 + (-8) + 16 = 24
    const result = FrameLayout.aarch64LocalOffset(-8, 16);
    try std.testing.expectEqual(@as(i32, 24), result);
}

test "FrameLayout AArch64 - local at offset -16 with frame_size 16" {
    // Second local at rbp-16
    // Expected: 16 + (-16) + 16 = 16
    const result = FrameLayout.aarch64LocalOffset(-16, 16);
    try std.testing.expectEqual(@as(i32, 16), result);
}

test "FrameLayout AArch64 - offset must not overlap saved registers" {
    // Any computed offset must be >= 16 (past saved fp/lr)
    // This test verifies the safety assertion in aarch64LocalOffset
    const offsets = [_]struct { x86: i32, frame: u32 }{
        .{ .x86 = -8, .frame = 16 },   // Normal case
        .{ .x86 = -16, .frame = 32 },  // Larger frame
        .{ .x86 = -8, .frame = 32 },   // Different alignment
        .{ .x86 = -24, .frame = 32 },  // Third local
    };

    for (offsets) |o| {
        const result = FrameLayout.aarch64LocalOffset(o.x86, o.frame);
        // Result must be >= AARCH64_SAVED_REGS to avoid corrupting fp/lr
        try std.testing.expect(result >= FrameLayout.AARCH64_SAVED_REGS);
    }
}

test "FrameLayout AArch64 - constant value is 16" {
    // Verify the saved registers size constant is correct
    // fp (8 bytes) + lr (8 bytes) = 16 bytes
    try std.testing.expectEqual(@as(i32, 16), FrameLayout.AARCH64_SAVED_REGS);
}

test "FrameLayout x86_64 - offset unchanged" {
    // x86_64 uses rbp-relative addressing, no conversion needed
    try std.testing.expectEqual(@as(i32, -8), FrameLayout.x86_64LocalOffset(-8));
    try std.testing.expectEqual(@as(i32, -16), FrameLayout.x86_64LocalOffset(-16));
}
