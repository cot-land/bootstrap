const std = @import("std");
const token = @import("token.zig");
const source = @import("source.zig");
const scanner = @import("scanner.zig");
const errors = @import("errors.zig");
const ast = @import("ast.zig");
const parser = @import("parser.zig");
const types = @import("types.zig");
const check = @import("check.zig");
const ir = @import("ir.zig");
const lower = @import("lower.zig");
const ssa = @import("ssa.zig");
const backend = @import("codegen/backend.zig");
const x86_64 = @import("codegen/x86_64.zig");
const aarch64 = @import("codegen/aarch64.zig");
const object = @import("codegen/object.zig");
const driver = @import("driver.zig");
const debug = @import("debug.zig");

const version_string = "cot 0.2.0";

pub fn main() !void {
    // Initialize debug configuration from environment
    debug.initConfig();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    const cmd = args[1];

    if (std.mem.eql(u8, cmd, "build")) {
        try cmdBuild(allocator, args[2..]);
    } else if (std.mem.eql(u8, cmd, "version")) {
        std.debug.print("{s}\n", .{version_string});
    } else if (std.mem.eql(u8, cmd, "help")) {
        printUsage();
    } else {
        // Assume it's a file path (shorthand for build)
        try cmdBuild(allocator, args[1..]);
    }
}

fn printUsage() void {
    std.debug.print(
        \\{s}
        \\
        \\Usage: cot <command> [options] [file]
        \\
        \\Commands:
        \\  build <file.cot>   Compile source file to executable
        \\  version            Show version information
        \\  help               Show this help message
        \\
        \\Build Options:
        \\  -c                 Compile only (produce .o file, don't link)
        \\  -o <file>          Output file name
        \\  -v, --verbose      Verbose output
        \\
        \\Debug Flags (for troubleshooting compiler issues):
        \\  --debug-ir         Dump IR after lowering (shows ops, locals, control flow)
        \\  --debug-ssa        Dump SSA after conversion (shows values, blocks, args)
        \\  --debug-codegen    Dump codegen operations (shows what instructions are emitted)
        \\  --disasm           Run objdump on output (shows final machine code)
        \\
        \\Environment Variables:
        \\  COT_DEBUG=<cats>   Enable debug categories (ssa,regalloc,codegen,all)
        \\  COT_DUMP_IR=1      Dump IR after each phase
        \\  COT_TRACE_REGALLOC=1  Trace register allocation
        \\
        \\Examples:
        \\  cot build hello.cot           Compile hello.cot to ./hello
        \\  cot build -o myapp main.cot   Compile to ./myapp
        \\  cot build -c lib.cot          Compile to lib.o only
        \\
    , .{version_string});
}

fn cmdBuild(allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    var options = driver.CompileOptions{
        .input_path = "",
    };

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (arg[0] == '-') {
            // Option
            if (std.mem.eql(u8, arg, "-c")) {
                options.output_kind = .object;
            } else if (std.mem.eql(u8, arg, "-o")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("Error: -o requires an argument\n", .{});
                    return;
                }
                options.output_path = args[i];
            } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
                options.verbose = true;
            } else if (std.mem.eql(u8, arg, "--debug-ir")) {
                options.debug_ir = true;
            } else if (std.mem.eql(u8, arg, "--debug-ssa")) {
                options.debug_ssa = true;
            } else if (std.mem.eql(u8, arg, "--debug-codegen")) {
                options.debug_codegen = true;
            } else if (std.mem.eql(u8, arg, "--disasm")) {
                options.disasm = true;
            } else {
                std.debug.print("Unknown option: {s}\n", .{arg});
                return;
            }
        } else {
            // Input file
            options.input_path = arg;
        }
    }

    if (options.input_path.len == 0) {
        std.debug.print("Error: no input file specified\n", .{});
        return;
    }

    // Run compilation
    var drv = driver.Driver.init(allocator, options);
    defer drv.deinit();

    const result = drv.compile();

    if (result.success) {
        if (result.output_path) |path| {
            std.debug.print("Compiled: {s}\n", .{path});
        }
    } else {
        std.debug.print("Compilation failed with {d} error(s)\n", .{result.error_count});
        std.process.exit(1);
    }
}

test "compiler starts" {
    // Verify token module is working
    try std.testing.expectEqual(token.Token.kw_fn, token.keywords.get("fn").?);
}

test {
    // Run tests from imported modules
    std.testing.refAllDecls(@This());
    _ = token;
    _ = source;
    _ = scanner;
    _ = errors;
    _ = ast;
    _ = parser;
    _ = types;
    _ = check;
    _ = ir;
    _ = lower;
    _ = ssa;
    _ = backend;
    _ = x86_64;
    _ = aarch64;
    _ = object;
    _ = driver;
    _ = debug;
}
