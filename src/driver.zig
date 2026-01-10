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

    // Diagnostics
    err_reporter: ?*errors.ErrorReporter = null,
    current_phase: Phase = .read,

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
        if (self.ir_data) |i| {
            // TODO: IR.deinit() when implemented
            self.allocator.destroy(i);
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

        // Create global scope for type checking
        var global_scope = check.Scope.init(self.allocator, null);
        defer global_scope.deinit();

        var checker = check.Checker.init(
            self.allocator,
            self.tree.?,
            reg,
            self.err_reporter.?,
            &global_scope,
        );
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
            node.op == .gt or node.op == .ge)
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

        // Handle addr_field - struct field access
        // args[0] = local index (as NodeIndex), aux = field offset
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

        // Handle field - direct field access (used by len() on slices)
        // args[0] = local index (as NodeIndex), aux = field offset
        if (node.op == .field) {
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
            .store => .store,
            .jump => .jump,
            .branch => .branch,
            .addr_field => .field,  // Field address becomes field op in SSA
            .field => .field,
            else => .copy,  // Default fallback
        };

        // Create SSA value
        const value_id = try func.newValue(ssa_op, node.type_idx, block);

        // Copy auxiliary data for constants
        var value = func.getValue(value_id);
        value.aux_int = node.aux;
        value.aux_str = node.aux_str;  // For const_string

        return value_id;
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

        // Collect and store string literals
        // Map from string content to offset in rodata
        var string_offsets = std.StringHashMap(u32).init(self.allocator);
        defer string_offsets.deinit();

        for (ssa_funcs.items) |*func| {
            for (func.blocks.items) |block| {
                for (block.values.items) |value_id| {
                    const value = func.getValue(value_id);
                    if (value.op == .const_string and value.aux_str.len > 0) {
                        // Add string to rodata if not already there
                        if (!string_offsets.contains(value.aux_str)) {
                            const offset: u32 = @intCast(rodata_section.size());
                            try rodata_section.append(self.allocator, value.aux_str);
                            try rodata_section.append(self.allocator, &[_]u8{0}); // null terminator
                            try string_offsets.put(value.aux_str, offset);
                        }
                    }
                }
            }
        }

        // Create backend based on architecture
        var code_buf = be.CodeBuffer.init(self.allocator);
        defer code_buf.deinit();

        switch (self.options.target.arch) {
            .x86_64 => {
                var backend = x86_64.X86_64Backend.init(self.allocator);
                defer backend.deinit();

                for (ssa_funcs.items) |*func| {
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
                    // Reserve stack space using computed frame size (or minimum 16)
                    const stack_size: i32 = @intCast(@max(16, func.frame_size));
                    try x86_64.subRegImm32(&code_buf, .rsp, stack_size);

                    // Track branch positions for patching
                    var branch_patches: std.ArrayList(BranchPatch) = .{ .items = &.{}, .capacity = 0 };
                    defer branch_patches.deinit(self.allocator);

                    // Track block positions (byte offset where each block starts)
                    var block_positions: [64]u32 = undefined;
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
                        if (value.op == .call) {
                            has_calls = true;
                            break;
                        }
                    }

                    // Calculate stack size using computed frame size (or minimum 32)
                    const stack_size: u32 = @intCast(@max(32, func.frame_size));

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

                    // Track branch positions for patching
                    var branch_patches: std.ArrayList(BranchPatch) = .{ .items = &.{}, .capacity = 0 };
                    defer branch_patches.deinit(self.allocator);

                    // Track block positions (byte offset where each block starts)
                    var block_positions: [64]u32 = undefined;
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

    fn generateX86Value(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, value: ssa.Value) !void {
        // System V AMD64 ABI argument registers
        const arg_regs = [_]x86_64.Reg{ .rdi, .rsi, .rdx, .rcx, .r8, .r9 };

        switch (value.op) {
            .const_int, .const_bool => {
                // Constants are used as operands by other instructions.
                // Don't generate standalone code - it would clobber rax.
            },
            .const_string => {
                // String literals are stored in rodata.
                // For now, don't generate standalone code - they're used as operands.
            },
            .arg => {
                // Load parameter from argument register to rax
                const param_idx: u32 = @intCast(value.aux_int);
                if (param_idx < arg_regs.len) {
                    try x86_64.movRegReg(buf, .rax, arg_regs[param_idx]);
                }
            },
            .add => {
                // Binary add: look up both operands
                const args = value.args();
                if (args.len >= 2) {
                    const left = func.getValue(args[0]);
                    const right = func.getValue(args[1]);

                    // Generate code for left operand -> rax
                    if (left.op == .arg) {
                        const param_idx: u32 = @intCast(left.aux_int);
                        if (param_idx < arg_regs.len) {
                            try x86_64.movRegReg(buf, .rax, arg_regs[param_idx]);
                        }
                    } else if (left.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rax, left.aux_int);
                    } else if (left.op == .load) {
                        // Load from local variable into rax
                        const local_idx: usize = @intCast(left.aux_int);
                        const local_offset: i32 = func.locals[local_idx].offset;
                        try x86_64.movRegMem(buf, .rax, .rbp, local_offset);
                    }

                    // Generate code for right operand, then add
                    if (right.op == .const_int) {
                        // add rax, imm32
                        try x86_64.addRegImm32(buf, .rax, @intCast(right.aux_int));
                    } else if (right.op == .arg) {
                        const param_idx: u32 = @intCast(right.aux_int);
                        if (param_idx < arg_regs.len) {
                            try x86_64.addRegReg(buf, .rax, arg_regs[param_idx]);
                        }
                    } else if (right.op == .load) {
                        // Load from local variable into r9 and add
                        const local_idx: usize = @intCast(right.aux_int);
                        const local_offset: i32 = func.locals[local_idx].offset;
                        try x86_64.movRegMem(buf, .r9, .rbp, local_offset);
                        try x86_64.addRegReg(buf, .rax, .r9);
                    }
                }
            },
            .sub => {
                // Binary subtract: look up both operands
                const args = value.args();
                if (args.len >= 2) {
                    const left = func.getValue(args[0]);
                    const right = func.getValue(args[1]);

                    // Generate code for left operand -> rax
                    if (left.op == .arg) {
                        const param_idx: u32 = @intCast(left.aux_int);
                        if (param_idx < arg_regs.len) {
                            try x86_64.movRegReg(buf, .rax, arg_regs[param_idx]);
                        }
                    } else if (left.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rax, left.aux_int);
                    }

                    // Generate code for right operand, then subtract
                    if (right.op == .const_int) {
                        // sub rax, imm32
                        try x86_64.subRegImm32(buf, .rax, @intCast(right.aux_int));
                    } else if (right.op == .arg) {
                        const param_idx: u32 = @intCast(right.aux_int);
                        if (param_idx < arg_regs.len) {
                            try x86_64.subRegReg(buf, .rax, arg_regs[param_idx]);
                        }
                    }
                }
            },
            .mul => {
                // Binary multiply: look up both operands
                const args = value.args();
                if (args.len >= 2) {
                    const left = func.getValue(args[0]);
                    const right = func.getValue(args[1]);

                    // Generate code for left operand -> rax
                    if (left.op == .arg) {
                        const param_idx: u32 = @intCast(left.aux_int);
                        if (param_idx < arg_regs.len) {
                            try x86_64.movRegReg(buf, .rax, arg_regs[param_idx]);
                        }
                    } else if (left.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rax, left.aux_int);
                    }

                    // Generate code for right operand, then multiply
                    if (right.op == .const_int) {
                        // imul rax, rax, imm32
                        try x86_64.imulRegRegImm(buf, .rax, .rax, @intCast(right.aux_int));
                    } else if (right.op == .arg) {
                        const param_idx: u32 = @intCast(right.aux_int);
                        if (param_idx < arg_regs.len) {
                            try x86_64.imulRegReg(buf, .rax, arg_regs[param_idx]);
                        }
                    }
                }
            },
            .div => {
                // Binary divide: look up both operands
                // IDIV divides RDX:RAX by operand, quotient in RAX
                const args = value.args();
                if (args.len >= 2) {
                    const left = func.getValue(args[0]);
                    const right = func.getValue(args[1]);

                    // Generate code for left operand (dividend) -> rax
                    if (left.op == .arg) {
                        const param_idx: u32 = @intCast(left.aux_int);
                        if (param_idx < arg_regs.len) {
                            try x86_64.movRegReg(buf, .rax, arg_regs[param_idx]);
                        }
                    } else if (left.op == .const_int) {
                        try x86_64.movRegImm64(buf, .rax, left.aux_int);
                    }

                    // Sign-extend RAX to RDX:RAX
                    try x86_64.cqo(buf);

                    // Generate code for right operand (divisor), then divide
                    if (right.op == .const_int) {
                        // Load divisor to r8, then idiv r8
                        try x86_64.movRegImm64(buf, .r8, right.aux_int);
                        try x86_64.idivReg(buf, .r8);
                    } else if (right.op == .arg) {
                        const param_idx: u32 = @intCast(right.aux_int);
                        if (param_idx < arg_regs.len) {
                            try x86_64.idivReg(buf, arg_regs[param_idx]);
                        }
                    }
                }
            },
            .call => {
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
                    }
                }

                // Emit call to function
                const func_name = if (self.options.target.os == .macos)
                    try std.fmt.allocPrint(self.allocator, "_{s}", .{value.aux_str})
                else
                    value.aux_str;
                try x86_64.callSymbol(buf, func_name);
                // Return value is in rax
            },
            .ret => {
                // Return value should be in rax
                // Check if there's an argument to return
                const args = value.args();
                if (args.len > 0) {
                    const ret_val = func.getValue(args[0]);
                    // If the return value isn't already in rax, move it there
                    if (ret_val.op == .arg) {
                        const param_idx: u32 = @intCast(ret_val.aux_int);
                        if (param_idx < arg_regs.len) {
                            try x86_64.movRegReg(buf, .rax, arg_regs[param_idx]);
                        }
                    } else if (ret_val.op == .const_int or ret_val.op == .const_bool) {
                        try x86_64.movRegImm64(buf, .rax, ret_val.aux_int);
                    }
                    // .field and call results are already in rax
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
                    }
                }
            },
            .select => {
                // Conditional select: args[0] = cond, args[1] = then, args[2] = else
                // The condition (eq/ne/lt/etc) has already set flags
                // Load else value into rax, then value into r8, cmove to select
                const args = value.args();
                if (args.len >= 3) {
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

                    // cmove: if equal (ZF=1), move r8 to rax
                    try x86_64.cmoveRegReg(buf, .rax, .r8);
                }
            },
            .branch, .jump => {
                // These are handled by generateX86ValueWithPatching
            },
            .field => {
                // Field access: load from stack offset
                // args[0] = local index, aux_int = field offset
                const args = value.args();
                if (args.len > 0) {
                    const local_idx = args[0];
                    const field_offset: i32 = @intCast(value.aux_int);

                    // Use computed stack offset from frame layout
                    const local_offset: i32 = func.locals[@intCast(local_idx)].offset;

                    // Load from [rbp + local_offset + field_offset]
                    const total_offset: i32 = local_offset + field_offset;
                    try x86_64.movRegMem(buf, .rax, .rbp, total_offset);
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
                        } else if (val.op == .add or val.op == .sub or val.op == .mul or val.op == .div or
                            val.op == .load or val.op == .call or val.op == .field or val.op == .index or
                            val.op == .slice_index)
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
            else => {
                // Warn about unhandled ops in debug mode
                if (self.options.debug_codegen) {
                    std.debug.print("  [WARN] Unhandled x86_64 SSA op: {s}\n", .{@tagName(value.op)});
                }
            },
        }
    }

    /// Generate x86_64 code for a value and record branch positions for patching
    fn generateX86ValueWithPatching(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, value: ssa.Value, value_idx: u32, patches: *std.ArrayList(BranchPatch)) !void {
        const arg_regs = [_]x86_64.Reg{ .rdi, .rsi, .rdx, .rcx, .r8, .r9 };
        _ = arg_regs;
        _ = value_idx;

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
                try self.generateX86Value(buf, func, value);
            },
        }
    }

    fn generateAArch64Value(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, value: ssa.Value, stack_size: u32, has_calls: bool) !void {
        // AAPCS64 argument registers: x0-x7
        const arg_regs = [_]aarch64.Reg{ .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7 };

        switch (value.op) {
            .const_int, .const_bool, .const_string, .arg => {
                // These are handled as operands when used by other ops.
                // Don't generate standalone code for them.
            },
            .add => {
                // Binary add: look up both operands
                const args = value.args();
                if (args.len >= 2) {
                    const left = func.getValue(args[0]);
                    const right = func.getValue(args[1]);

                    // Generate code for left operand -> x0
                    if (left.op == .arg) {
                        const param_idx: u32 = @intCast(left.aux_int);
                        if (param_idx < arg_regs.len and param_idx != 0) {
                            try aarch64.movRegReg(buf, .x0, arg_regs[param_idx]);
                        }
                    } else if (left.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x0, left.aux_int);
                    } else if (left.op == .load) {
                        // Load from local variable into x0
                        const local_idx: usize = @intCast(left.aux_int);
                        const x86_offset: i32 = func.locals[local_idx].offset;
                        const local_offset: i32 = @as(i32, @intCast(func.frame_size)) + x86_offset;
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x0, .sp, offset_scaled);
                        }
                    }

                    // Generate code for right operand, then add
                    if (right.op == .const_int) {
                        // add x0, x0, #imm12
                        const imm: u12 = @intCast(right.aux_int & 0xFFF);
                        try aarch64.addRegImm12(buf, .x0, .x0, imm);
                    } else if (right.op == .arg) {
                        const param_idx: u32 = @intCast(right.aux_int);
                        if (param_idx < arg_regs.len) {
                            try aarch64.addRegReg(buf, .x0, .x0, arg_regs[param_idx]);
                        }
                    } else if (right.op == .load) {
                        // Load from local variable into x9 and add
                        const local_idx: usize = @intCast(right.aux_int);
                        const x86_offset: i32 = func.locals[local_idx].offset;
                        const local_offset: i32 = @as(i32, @intCast(func.frame_size)) + x86_offset;
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x9, .sp, offset_scaled);
                            try aarch64.addRegReg(buf, .x0, .x0, .x9);
                        }
                    }
                }
            },
            .sub => {
                // Binary sub: look up both operands
                const args = value.args();
                if (args.len >= 2) {
                    const left = func.getValue(args[0]);
                    const right = func.getValue(args[1]);

                    // Generate code for left operand -> x0
                    if (left.op == .arg) {
                        const param_idx: u32 = @intCast(left.aux_int);
                        if (param_idx < arg_regs.len and param_idx != 0) {
                            try aarch64.movRegReg(buf, .x0, arg_regs[param_idx]);
                        }
                    } else if (left.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x0, left.aux_int);
                    }

                    // Generate code for right operand, then sub
                    if (right.op == .const_int) {
                        // Load right into x8, then sub x0, x0, x8
                        try aarch64.movRegImm64(buf, .x8, right.aux_int);
                        try aarch64.subRegReg(buf, .x0, .x0, .x8);
                    } else if (right.op == .arg) {
                        const param_idx: u32 = @intCast(right.aux_int);
                        if (param_idx < arg_regs.len) {
                            try aarch64.subRegReg(buf, .x0, .x0, arg_regs[param_idx]);
                        }
                    }
                }
            },
            .mul => {
                // Binary mul: look up both operands
                const args = value.args();
                if (args.len >= 2) {
                    const left = func.getValue(args[0]);
                    const right = func.getValue(args[1]);

                    // Generate code for left operand -> x0
                    if (left.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x0, left.aux_int);
                    } else if (left.op == .arg) {
                        const param_idx: u32 = @intCast(left.aux_int);
                        if (param_idx < arg_regs.len and param_idx != 0) {
                            try aarch64.movRegReg(buf, .x0, arg_regs[param_idx]);
                        }
                    }

                    // Generate code for right operand -> x8, then mul
                    if (right.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x8, right.aux_int);
                        try aarch64.mulRegReg(buf, .x0, .x0, .x8);
                    } else if (right.op == .arg) {
                        const param_idx: u32 = @intCast(right.aux_int);
                        if (param_idx < arg_regs.len) {
                            try aarch64.mulRegReg(buf, .x0, .x0, arg_regs[param_idx]);
                        }
                    }
                }
            },
            .div => {
                // Binary div: look up both operands
                // AArch64 uses SDIV for signed division
                const args = value.args();
                if (args.len >= 2) {
                    const left = func.getValue(args[0]);
                    const right = func.getValue(args[1]);

                    // Generate code for left operand -> x0
                    if (left.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x0, left.aux_int);
                    } else if (left.op == .arg) {
                        const param_idx: u32 = @intCast(left.aux_int);
                        if (param_idx < arg_regs.len and param_idx != 0) {
                            try aarch64.movRegReg(buf, .x0, arg_regs[param_idx]);
                        }
                    }

                    // Generate code for right operand -> x8, then div
                    if (right.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x8, right.aux_int);
                        try aarch64.sdivRegReg(buf, .x0, .x0, .x8);
                    } else if (right.op == .arg) {
                        const param_idx: u32 = @intCast(right.aux_int);
                        if (param_idx < arg_regs.len) {
                            try aarch64.sdivRegReg(buf, .x0, .x0, arg_regs[param_idx]);
                        }
                    }
                }
            },
            .call => {
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
                    }
                }

                // Emit call to function
                const func_name = if (self.options.target.os == .macos)
                    try std.fmt.allocPrint(self.allocator, "_{s}", .{value.aux_str})
                else
                    value.aux_str;
                try aarch64.callSymbol(buf, func_name);
                // Return value is in x0
            },
            .ret => {
                // Return value should be in x0
                const args = value.args();
                if (args.len > 0) {
                    const ret_val = func.getValue(args[0]);
                    if (ret_val.op == .arg) {
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
                        const local_offset: i32 = @as(i32, @intCast(func.frame_size)) + x86_offset;
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x0, .sp, offset_scaled);
                        }
                    }
                    // Operations that already leave result in x0: add, sub, mul, div,
                    // field, index, call, slice_make - no extra code needed
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
                        const local_offset: i32 = @as(i32, @intCast(func.frame_size)) + x86_offset;
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x8, .sp, offset_scaled);
                        }
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
                        const local_offset: i32 = @as(i32, @intCast(func.frame_size)) + x86_offset;
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x9, .sp, offset_scaled);
                            try aarch64.cmpRegReg(buf, .x8, .x9);
                        }
                    }
                    // Comparison result is in flags, will be used by branch
                }
            },
            .select => {
                // Conditional select: args[0] = cond, args[1] = then, args[2] = else
                // The condition (eq/ne/lt/etc) has already set flags
                // Use CSEL: csel x0, x8 (then), x9 (else), eq
                const args = value.args();
                if (args.len >= 3) {
                    const else_val = func.getValue(args[2]);
                    const then_val = func.getValue(args[1]);

                    // Load else value into x9
                    if (else_val.op == .const_int) {
                        try aarch64.movRegImm64(buf, .x9, else_val.aux_int);
                    } else if (else_val.op == .load) {
                        const local_idx: usize = @intCast(else_val.aux_int);
                        const x86_offset: i32 = func.locals[local_idx].offset;
                        const local_offset: i32 = @as(i32, @intCast(func.frame_size)) + x86_offset;
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
                        const local_offset: i32 = @as(i32, @intCast(func.frame_size)) + x86_offset;
                        if (local_offset >= 0 and @mod(local_offset, 8) == 0) {
                            const offset_scaled: u12 = @intCast(@divExact(local_offset, 8));
                            try aarch64.ldrRegImm(buf, .x8, .sp, offset_scaled);
                        }
                    }

                    // CSEL x0, x8, x9, eq: if equal, x0 = x8 (then), else x0 = x9 (else)
                    try aarch64.csel(buf, .x0, .x8, .x9, .eq);
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

                    // Convert x86-style negative offset to ARM64 positive sp-relative offset
                    // arm64_offset = frame_size + x86_offset
                    const x86_offset: i32 = func.locals[@intCast(local_idx)].offset;
                    const local_offset: i32 = @as(i32, @intCast(func.frame_size)) + x86_offset;
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
                        } else if (val.op == .add or val.op == .sub or val.op == .mul or val.op == .div or
                            val.op == .load or val.op == .call or val.op == .field or val.op == .index or
                            val.op == .slice_index)
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
            .field => {
                // Field access: load from stack offset
                // args[0] = local index, aux_int = field offset
                const args = value.args();
                if (args.len > 0) {
                    const local_idx = args[0];
                    const field_offset: i32 = @intCast(value.aux_int);

                    // Convert x86-style negative offset to ARM64 positive sp-relative offset
                    const x86_offset: i32 = func.locals[@intCast(local_idx)].offset;
                    const local_offset: i32 = @as(i32, @intCast(func.frame_size)) + x86_offset;

                    // Load from [sp + local_offset + field_offset]
                    const total_offset: i32 = local_offset + field_offset;

                    // LDR x0, [sp, #offset] - load into x0 for return
                    // offset must be 8-byte aligned and fit in 12-bit scaled immediate
                    if (total_offset >= 0 and @mod(total_offset, 8) == 0) {
                        const offset_scaled: u12 = @intCast(@divExact(total_offset, 8));
                        try aarch64.ldrRegImm(buf, .x0, .sp, offset_scaled);
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
                    const local_offset: i32 = @as(i32, @intCast(func.frame_size)) + x86_offset;

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
                        const idx_sp_offset: i32 = @as(i32, @intCast(func.frame_size)) + idx_x86_offset;
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
                    const local_offset: i32 = @as(i32, @intCast(func.frame_size)) + x86_offset;

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
                    const local_offset: i32 = @as(i32, @intCast(func.frame_size)) + x86_offset;

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
                        const idx_sp_offset: i32 = @as(i32, @intCast(func.frame_size)) + idx_x86_offset;
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
            else => {
                // Warn about unhandled ops in debug mode
                if (self.options.debug_codegen) {
                    std.debug.print("  [WARN] Unhandled AArch64 SSA op: {s}\n", .{@tagName(value.op)});
                }
            },
        }
    }

    /// Generate code for a single SSA value and record branch positions for patching
    fn generateAArch64ValueWithPatching(self: *Driver, buf: *be.CodeBuffer, func: *ssa.Func, value: ssa.Value, value_idx: u32, patches: *std.ArrayList(BranchPatch), stack_size: u32, has_calls: bool) !void {
        _ = value_idx;

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
                try self.generateAArch64Value(buf, func, value, stack_size, has_calls);
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
                // macOS: use ld64 via cc
                try argv.append(self.allocator, "cc");
                try argv.append(self.allocator, "-o");
                try argv.append(self.allocator, exe_path);
                try argv.append(self.allocator, obj_path);
                try argv.append(self.allocator, "-lSystem");
            },
            .linux => {
                // Linux: use ld directly or via cc
                try argv.append(self.allocator, "cc");
                try argv.append(self.allocator, "-o");
                try argv.append(self.allocator, exe_path);
                try argv.append(self.allocator, obj_path);
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
