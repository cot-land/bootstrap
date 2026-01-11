///! Debugging and tracing infrastructure for the cot compiler.
///!
///! Inspired by:
///! - Go: GOSSAFUNC environment variable, phase-based dumps
///! - Zig: Scoped loggers with multiple verbosity levels
///! - Roc: Environment variable flags, IR dumps after each pass
///! - Kotlin: PhaseConfig with before/after dumps, validation hooks
///!
///! Usage:
///!   COT_DEBUG=ssa,regalloc      Enable specific debug categories
///!   COT_DUMP_IR=1               Dump IR after each phase
///!   COT_DUMP_FUNC=main          Only dump specific function
///!   COT_TRACE_REGALLOC=1        Trace register allocation decisions
///!   COT_VALIDATE_IR=1           Validate IR after each pass

const std = @import("std");
const builtin = @import("builtin");

// ============================================================================
// Debug Categories (Scoped Logging)
// ============================================================================

/// Debug categories that can be enabled independently.
pub const Category = enum {
    scanner, // Lexer debugging
    parser, // Parser debugging
    types, // Type system debugging
    checker, // Type checker debugging
    ir, // IR generation debugging
    ssa, // SSA construction debugging
    regalloc, // Register allocation debugging
    codegen, // Code generation debugging
    object, // Object file debugging
    pe_coff, // PE/COFF (Windows) object file debugging

    pub fn enabled(self: Category) bool {
        return isEnabled(self);
    }
};

/// Cross-platform getenv helper (returns null on Windows for now)
fn getEnvCrossPlat(comptime name: []const u8) ?[]const u8 {
    // Windows uses WTF-16 for environment strings, std.posix.getenv is not available
    // For now, return null on Windows (debug features disabled)
    // TODO: Use std.process.getEnvVarOwned with an allocator for Windows
    if (comptime builtin.os.tag == .windows) {
        return null;
    } else {
        return std.posix.getenv(name);
    }
}

/// Check if a debug category is enabled.
/// In release builds, this always returns false (zero overhead).
pub fn isEnabled(category: Category) bool {
    if (builtin.mode != .Debug) return false;

    // Cache the parsed environment variable
    const state = struct {
        var initialized: bool = false;
        var enabled_mask: u32 = 0;

        fn init() void {
            if (initialized) return;
            initialized = true;

            const env = getEnvCrossPlat("COT_DEBUG") orelse return;

            // Parse comma-separated categories: "ssa,regalloc,codegen"
            var iter = std.mem.splitScalar(u8, env, ',');
            while (iter.next()) |name| {
                const trimmed = std.mem.trim(u8, name, " ");
                if (std.mem.eql(u8, trimmed, "all")) {
                    enabled_mask = std.math.maxInt(u32);
                    return;
                }
                inline for (std.meta.fields(Category)) |field| {
                    if (std.mem.eql(u8, trimmed, field.name)) {
                        enabled_mask |= @as(u32, 1) << field.value;
                    }
                }
            }
        }
    };

    state.init();
    return (state.enabled_mask & (@as(u32, 1) << @intFromEnum(category))) != 0;
}

// ============================================================================
// Scoped Logging (Zig Pattern)
// ============================================================================

/// Create a scoped logger for a specific category.
/// Usage: const log = debug.scoped(.regalloc);
///        log.debug("allocated {s} to {s}", .{value, reg});
pub fn scoped(comptime category: Category) type {
    return struct {
        pub fn debug(comptime fmt: []const u8, args: anytype) void {
            if (builtin.mode != .Debug) return;
            if (!isEnabled(category)) return;
            const prefix = "[" ++ @tagName(category) ++ "] ";
            std.debug.print(prefix ++ fmt ++ "\n", args);
        }

        pub fn info(comptime fmt: []const u8, args: anytype) void {
            if (builtin.mode != .Debug) return;
            if (!isEnabled(category)) return;
            const prefix = "[" ++ @tagName(category) ++ "] ";
            std.debug.print(prefix ++ fmt ++ "\n", args);
        }

        pub fn warn(comptime fmt: []const u8, args: anytype) void {
            if (builtin.mode != .Debug) return;
            const prefix = "[" ++ @tagName(category) ++ " WARN] ";
            std.debug.print(prefix ++ fmt ++ "\n", args);
        }
    };
}

// ============================================================================
// Phase Dumping (Go/Kotlin Pattern)
// ============================================================================

/// Phase dump configuration.
pub const DumpConfig = struct {
    /// Dump IR after each phase.
    dump_ir: bool = false,
    /// Only dump specific function (null = all).
    dump_func: ?[]const u8 = null,
    /// Directory for dump files (null = stderr).
    dump_dir: ?[]const u8 = null,
    /// Validate IR after each phase.
    validate_ir: bool = false,
    /// Trace register allocation decisions.
    trace_regalloc: bool = false,

    /// Initialize from environment variables.
    pub fn fromEnv() DumpConfig {
        if (builtin.mode != .Debug) return .{};

        return .{
            .dump_ir = getEnvCrossPlat("COT_DUMP_IR") != null,
            .dump_func = getEnvCrossPlat("COT_DUMP_FUNC"),
            .dump_dir = getEnvCrossPlat("COT_DUMP_DIR"),
            .validate_ir = getEnvCrossPlat("COT_VALIDATE_IR") != null,
            .trace_regalloc = getEnvCrossPlat("COT_TRACE_REGALLOC") != null,
        };
    }
};

/// Global dump configuration (initialized once).
pub var config: DumpConfig = .{};

pub fn initConfig() void {
    config = DumpConfig.fromEnv();
}

// ============================================================================
// IR Dumping
// ============================================================================

/// Dump context for tracking phase sequence.
pub const DumpContext = struct {
    phase_num: u32 = 0,
    func_name: []const u8 = "",
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) DumpContext {
        return .{ .allocator = allocator };
    }

    /// Record entering a new phase.
    pub fn enterPhase(self: *DumpContext, phase_name: []const u8) void {
        self.phase_num += 1;
        if (config.dump_ir) {
            std.debug.print("\n=== Phase {d}: {s} ===\n", .{ self.phase_num, phase_name });
        }
    }

    /// Dump IR if configured.
    pub fn dumpIR(self: *DumpContext, comptime fmt: []const u8, args: anytype) void {
        if (!config.dump_ir) return;

        // Filter by function name if specified
        if (config.dump_func) |func| {
            if (!std.mem.eql(u8, self.func_name, func)) return;
        }

        std.debug.print(fmt ++ "\n", args);
    }

    /// Dump to file if dump_dir is set.
    pub fn dumpToFile(self: *DumpContext, phase_name: []const u8, content: []const u8) !void {
        const dir = config.dump_dir orelse {
            std.debug.print("{s}\n", .{content});
            return;
        };

        // Create filename: 01_after_ssa.txt
        var buf: [256]u8 = undefined;
        const filename = std.fmt.bufPrint(&buf, "{s}/{d:0>2}_{s}.txt", .{
            dir,
            self.phase_num,
            phase_name,
        }) catch return;

        const file = std.fs.cwd().createFile(filename, .{}) catch |err| {
            std.debug.print("Failed to create dump file: {}\n", .{err});
            return;
        };
        defer file.close();

        file.writeAll(content) catch {};
    }
};

// ============================================================================
// Register Allocation Tracing (Go Pattern)
// ============================================================================

/// Register allocation trace levels.
pub const RegAllocTraceLevel = enum(u8) {
    none = 0,
    spills = 1, // Log spill decisions
    allocations = 2, // Log all allocations
    full = 3, // Log everything including state dumps
};

/// Get the register allocation trace level.
pub fn regAllocTraceLevel() RegAllocTraceLevel {
    if (builtin.mode != .Debug) return .none;
    if (!config.trace_regalloc) return .none;

    const level_str = getEnvCrossPlat("COT_TRACE_REGALLOC") orelse return .spills;

    return std.fmt.parseInt(u8, level_str, 10) catch return .spills;
}

/// Log a register allocation event.
pub fn traceRegAlloc(level: RegAllocTraceLevel, comptime fmt: []const u8, args: anytype) void {
    if (builtin.mode != .Debug) return;
    if (@intFromEnum(regAllocTraceLevel()) < @intFromEnum(level)) return;
    std.debug.print("[regalloc] " ++ fmt ++ "\n", args);
}

// ============================================================================
// IR Validation (Roc/Kotlin Pattern)
// ============================================================================

/// Validation result.
pub const ValidationResult = struct {
    errors: std.ArrayList([]const u8),

    pub fn init(allocator: std.mem.Allocator) ValidationResult {
        return .{ .errors = std.ArrayList([]const u8).init(allocator) };
    }

    pub fn deinit(self: *ValidationResult) void {
        self.errors.deinit();
    }

    pub fn addError(self: *ValidationResult, msg: []const u8) !void {
        try self.errors.append(msg);
    }

    pub fn hasErrors(self: *const ValidationResult) bool {
        return self.errors.items.len > 0;
    }

    pub fn report(self: *const ValidationResult) void {
        if (!self.hasErrors()) return;
        std.debug.print("\n=== IR Validation Errors ===\n", .{});
        for (self.errors.items) |err| {
            std.debug.print("  - {s}\n", .{err});
        }
    }
};

/// Validate IR if configured.
pub fn validateIR(comptime ValidatorFn: type, ir: anytype) !void {
    if (builtin.mode != .Debug) return;
    if (!config.validate_ir) return;

    var result = ValidationResult.init(std.heap.page_allocator);
    defer result.deinit();

    try ValidatorFn.validate(ir, &result);

    if (result.hasErrors()) {
        result.report();
        return error.IRValidationFailed;
    }
}

// ============================================================================
// Code Verification (Roc Pattern - Disassembly Comparison)
// ============================================================================

/// Compare generated bytes against expected disassembly.
/// In debug builds, this can use capstone or similar to verify instructions.
pub fn verifyGeneratedCode(
    bytes: []const u8,
    expected_asm: []const u8,
) bool {
    if (builtin.mode != .Debug) return true;
    // TODO: Integrate with capstone or similar disassembler
    // For now, just log the bytes
    _ = expected_asm;
    if (bytes.len > 0) {
        std.debug.print("[verify] Generated {d} bytes\n", .{bytes.len});
    }
    return true;
}

// ============================================================================
// Convenience Macros/Functions
// ============================================================================

/// Debug assert that only runs in debug builds.
pub fn debugAssert(ok: bool, comptime msg: []const u8) void {
    if (builtin.mode != .Debug) return;
    if (!ok) {
        std.debug.print("Debug assertion failed: {s}\n", .{msg});
        @panic(msg);
    }
}

/// Dump a value with a label (only in debug builds).
pub fn dump(comptime label: []const u8, value: anytype) void {
    if (builtin.mode != .Debug) return;
    std.debug.print("{s}: {any}\n", .{ label, value });
}

// ============================================================================
// Tests
// ============================================================================

test "category enabled parsing" {
    // This test only works in debug builds
    if (builtin.mode != .Debug) return;

    // Without env var, nothing should be enabled
    try std.testing.expect(!isEnabled(.ssa));
    try std.testing.expect(!isEnabled(.regalloc));
}

test "dump config from env" {
    // This test only works in debug builds
    if (builtin.mode != .Debug) return;

    const cfg = DumpConfig.fromEnv();
    // Default should have everything disabled
    try std.testing.expect(!cfg.dump_ir);
    try std.testing.expect(cfg.dump_func == null);
}

test "scoped logger compiles" {
    const log = scoped(.ssa);
    // Should compile even if not enabled
    log.debug("test message: {d}", .{42});
}
