///! Cot runtime string operations.
///!
///! Provides FFI functions for string concatenation and related operations.
///! Strings in cot are fat pointers: (ptr, len).

const std = @import("std");

/// String handle: pointer to first byte. Length is known at call site.
/// For concatenation results, we allocate: [len1 + len2 bytes of data]
/// The length is returned separately (via second register in calling convention).

/// Concatenate two strings, returning a new heap-allocated string.
/// Returns a pointer to the new string data.
/// The length is returned in the second return register (rdx on x86_64, x1 on aarch64).
///
/// Calling convention:
///   x86_64: rdi=ptr1, rsi=len1, rdx=ptr2, rcx=len2
///           Returns: rax=new_ptr, rdx=new_len
///   aarch64: x0=ptr1, x1=len1, x2=ptr2, x3=len2
///            Returns: x0=new_ptr, x1=new_len
/// Result struct for str_concat - uses allowzero for null case
const StrConcatResult = extern struct {
    ptr: [*]allowzero u8,
    len: usize,
};

export fn cot_str_concat(ptr1: [*]const u8, len1: usize, ptr2: [*]const u8, len2: usize) callconv(.c) StrConcatResult {
    const total_len = len1 + len2;

    // Handle empty concatenation
    if (total_len == 0) {
        return .{ .ptr = @ptrFromInt(0), .len = 0 };
    }

    // Allocate new buffer using libc malloc
    const new_ptr = std.c.malloc(total_len);
    if (new_ptr == null) {
        // Return null pointer on allocation failure
        return .{ .ptr = @ptrFromInt(0), .len = 0 };
    }

    const dest: [*]u8 = @ptrCast(new_ptr);

    // Copy first string
    if (len1 > 0) {
        @memcpy(dest[0..len1], ptr1[0..len1]);
    }

    // Copy second string
    if (len2 > 0) {
        @memcpy(dest[len1..total_len], ptr2[0..len2]);
    }

    return .{ .ptr = dest, .len = total_len };
}

test "cot_str_concat basic" {
    const result = cot_str_concat("hello", 5, " world", 6);
    const ptr: [*]u8 = @ptrCast(result.ptr);
    defer std.c.free(ptr);

    try std.testing.expectEqual(@as(usize, 11), result.len);
    try std.testing.expectEqualStrings("hello world", ptr[0..result.len]);
}

test "cot_str_concat empty strings" {
    const r1 = cot_str_concat("", 0, "test", 4);
    const p1: [*]u8 = @ptrCast(r1.ptr);
    defer std.c.free(p1);
    try std.testing.expectEqual(@as(usize, 4), r1.len);
    try std.testing.expectEqualStrings("test", p1[0..r1.len]);

    const r2 = cot_str_concat("test", 4, "", 0);
    const p2: [*]u8 = @ptrCast(r2.ptr);
    defer std.c.free(p2);
    try std.testing.expectEqual(@as(usize, 4), r2.len);
    try std.testing.expectEqualStrings("test", p2[0..r2.len]);
}
