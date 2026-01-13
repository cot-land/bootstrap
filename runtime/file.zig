///! Cot runtime file operations.
///!
///! Provides FFI functions for file reading and writing.
///! Used by bootstrap compiler for source file reading and object file output.

const std = @import("std");

/// Result struct for file read - uses allowzero for null case
const FileReadResult = extern struct {
    ptr: [*]allowzero u8,
    len: usize,
};

/// Read entire file contents into heap-allocated buffer.
/// Returns (ptr, len) on success, (null, 0) on failure.
///
/// Calling convention:
///   x86_64: rdi=path_ptr, rsi=path_len
///           Returns: rax=data_ptr, rdx=data_len
///   aarch64: x0=path_ptr, x1=path_len
///            Returns: x0=data_ptr, x1=data_len
export fn cot_file_read(path_ptr: [*]const u8, path_len: usize) callconv(.c) FileReadResult {
    if (path_len == 0) {
        return .{ .ptr = @ptrFromInt(0), .len = 0 };
    }

    const path = path_ptr[0..path_len];

    // Open file
    const file = std.fs.cwd().openFile(path, .{}) catch {
        return .{ .ptr = @ptrFromInt(0), .len = 0 };
    };
    defer file.close();

    // Get file size
    const stat = file.stat() catch {
        return .{ .ptr = @ptrFromInt(0), .len = 0 };
    };
    const size = stat.size;

    if (size == 0) {
        return .{ .ptr = @ptrFromInt(0), .len = 0 };
    }

    // Allocate buffer
    const buf = std.c.malloc(size);
    if (buf == null) {
        return .{ .ptr = @ptrFromInt(0), .len = 0 };
    }

    const dest: [*]u8 = @ptrCast(buf);

    // Read file
    const bytes_read = file.readAll(dest[0..size]) catch {
        std.c.free(buf);
        return .{ .ptr = @ptrFromInt(0), .len = 0 };
    };

    return .{ .ptr = dest, .len = bytes_read };
}

/// Write data to file.
/// Returns 1 on success, 0 on failure.
///
/// Calling convention:
///   x86_64: rdi=path_ptr, rsi=path_len, rdx=data_ptr, rcx=data_len
///   aarch64: x0=path_ptr, x1=path_len, x2=data_ptr, x3=data_len
export fn cot_file_write(path_ptr: [*]const u8, path_len: usize, data_ptr: [*]const u8, data_len: usize) callconv(.c) i64 {
    if (path_len == 0) {
        return 0;
    }

    const path = path_ptr[0..path_len];

    // Create/truncate file
    const file = std.fs.cwd().createFile(path, .{ .truncate = true }) catch {
        return 0;
    };
    defer file.close();

    // Write data
    if (data_len > 0) {
        file.writeAll(data_ptr[0..data_len]) catch {
            return 0;
        };
    }

    return 1;
}

/// Free memory allocated by cot_file_read.
export fn cot_file_free(ptr: ?*anyopaque) callconv(.c) void {
    if (ptr) |p| {
        std.c.free(p);
    }
}

/// Check if file exists.
/// Returns 1 if exists, 0 if not.
export fn cot_file_exists(path_ptr: [*]const u8, path_len: usize) callconv(.c) i64 {
    if (path_len == 0) {
        return 0;
    }

    const path = path_ptr[0..path_len];
    std.fs.cwd().access(path, .{}) catch {
        return 0;
    };
    return 1;
}

test "cot_file_read nonexistent" {
    const result = cot_file_read("nonexistent_file_12345.txt", 26);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "cot_file_write and read" {
    const test_path = "/tmp/cot_file_test.txt";
    const test_data = "Hello, Cot!";

    // Write
    const write_result = cot_file_write(test_path, test_path.len, test_data, test_data.len);
    try std.testing.expectEqual(@as(i64, 1), write_result);

    // Read back
    const read_result = cot_file_read(test_path, test_path.len);
    defer cot_file_free(@ptrCast(read_result.ptr));

    try std.testing.expectEqual(test_data.len, read_result.len);
    const ptr: [*]const u8 = @ptrCast(read_result.ptr);
    try std.testing.expectEqualStrings(test_data, ptr[0..read_result.len]);

    // Clean up
    std.fs.cwd().deleteFile(test_path) catch {};
}

test "cot_file_exists" {
    // This file should exist (we're running tests in the project)
    const exists = cot_file_exists("build.zig", 9);
    try std.testing.expectEqual(@as(i64, 1), exists);

    // This file should not exist
    const not_exists = cot_file_exists("nonexistent_12345.txt", 21);
    try std.testing.expectEqual(@as(i64, 0), not_exists);
}
