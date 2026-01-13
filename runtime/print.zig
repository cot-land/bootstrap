///! Print functions for Cot runtime.
///!
///! These functions provide basic printing capabilities for cot programs.
///! They are called by the compiler when it encounters print/println statements.

const std = @import("std");

// Direct libc binding for write
extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

/// Print a string (no newline)
export fn print(ptr: [*]const u8, len: usize) callconv(.c) void {
    _ = write(1, ptr, len);
}

/// Print a string followed by a newline
export fn println(ptr: [*]const u8, len: usize) callconv(.c) void {
    _ = write(1, ptr, len);
    _ = write(1, "\n", 1);
}
