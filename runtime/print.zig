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

/// Print an integer (no newline)
export fn print_int(value: i64) callconv(.c) void {
    var buf: [24]u8 = undefined;
    var i: usize = 0;
    var n: u64 = undefined;
    var neg = false;

    if (value < 0) {
        neg = true;
        n = @intCast(-value);
    } else {
        n = @intCast(value);
    }

    if (n == 0) {
        buf[0] = '0';
        i = 1;
    } else {
        // Build digits in reverse
        var temp: [24]u8 = undefined;
        var ti: usize = 0;
        while (n > 0) {
            temp[ti] = @intCast((n % 10) + '0');
            n /= 10;
            ti += 1;
        }
        // Copy in reverse to get correct order
        if (neg) {
            buf[0] = '-';
            i = 1;
        }
        while (ti > 0) {
            ti -= 1;
            buf[i] = temp[ti];
            i += 1;
        }
    }

    _ = write(1, &buf, i);
}

/// Print an integer followed by a newline
export fn println_int(value: i64) callconv(.c) void {
    print_int(value);
    _ = write(1, "\n", 1);
}
