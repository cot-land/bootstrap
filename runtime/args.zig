///! Cot runtime command-line argument access.
///!
///! Provides FFI functions for accessing argc/argv.
///! The cot_args_init function must be called at the start of main
///! to save argc/argv before they're clobbered.

const std = @import("std");

/// Global storage for argc/argv
var g_argc: usize = 0;
var g_argv: [*]const [*:0]const u8 = undefined;
var g_initialized: bool = false;

/// Result struct for args_get - returns (ptr, len) for the arg string
const ArgsGetResult = extern struct {
    ptr: [*]allowzero const u8,
    len: usize,
};

/// Initialize args storage. Called at the start of main.
/// On ARM64: x0=argc, x1=argv
/// On x86_64: rdi=argc, rsi=argv
export fn cot_args_init(argc: usize, argv: [*]const [*:0]const u8) callconv(.c) void {
    g_argc = argc;
    g_argv = argv;
    g_initialized = true;
}

/// Get the number of command-line arguments.
/// Returns argc.
export fn cot_args_count() callconv(.c) usize {
    return g_argc;
}

/// Get a command-line argument by index.
/// Returns (ptr, len) for the argument string.
/// If index is out of bounds, returns (null, 0).
export fn cot_args_get(index: usize) callconv(.c) ArgsGetResult {
    if (!g_initialized or index >= g_argc) {
        return .{ .ptr = @ptrFromInt(0), .len = 0 };
    }

    const arg = g_argv[index];
    const len = std.mem.len(arg);
    return .{ .ptr = arg, .len = len };
}

test "cot_args_init and count" {
    // Simulate initialization
    const test_args = [_][*:0]const u8{ "test_prog", "arg1" };
    cot_args_init(2, &test_args);
    try std.testing.expectEqual(@as(usize, 2), cot_args_count());
}

test "cot_args_get" {
    const test_args = [_][*:0]const u8{ "test_prog", "arg1" };
    cot_args_init(2, &test_args);

    const result = cot_args_get(0);
    try std.testing.expect(result.len > 0);

    // Out of bounds should return null
    const bad = cot_args_get(999999);
    try std.testing.expectEqual(@as(usize, 0), bad.len);
}
