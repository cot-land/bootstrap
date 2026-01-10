///! List runtime for cot compiler.
///!
///! Provides a simple dynamic array implementation with i64 values.
///! Uses a 24-byte header (elements_ptr, length, capacity) with separate element storage.
///!
///! This is a C ABI compatible library that can be linked with compiled cot programs.

const std = @import("std");
const builtin = @import("builtin");

// ============================================================================
// Configuration
// ============================================================================

const debug_list = false; // Enable debug output for troubleshooting
const initial_capacity: u64 = 8;
const growth_factor: u64 = 2;

// ============================================================================
// Data Structures
// ============================================================================

/// List header layout (24 bytes):
///   elements_ptr: *i64 (8 bytes) - pointer to heap-allocated element array
///   length: u64 (8 bytes) - current number of elements
///   capacity: u64 (8 bytes) - allocated capacity
const ListHeader = extern struct {
    elements_ptr: ?[*]i64,
    length: u64,
    capacity: u64,
};

// ============================================================================
// Memory Allocation (using libc)
// ============================================================================

const c = @cImport({
    @cInclude("stdlib.h");
});

fn allocElements(count: u64) ?[*]i64 {
    const size = count * @sizeOf(i64);
    const ptr = c.malloc(size);
    if (ptr == null) return null;
    return @ptrCast(@alignCast(ptr));
}

fn reallocElements(old_ptr: ?[*]i64, new_count: u64) ?[*]i64 {
    const size = new_count * @sizeOf(i64);
    const ptr = c.realloc(@ptrCast(old_ptr), size);
    if (ptr == null) return null;
    return @ptrCast(@alignCast(ptr));
}

fn freeElements(ptr: ?[*]i64) void {
    if (ptr != null) {
        c.free(@ptrCast(ptr));
    }
}

// ============================================================================
// Internal Helpers
// ============================================================================

fn getHeader(list: ?[*]u8) ?*ListHeader {
    if (list == null) return null;
    return @ptrCast(@alignCast(list));
}

fn growList(header: *ListHeader) bool {
    const new_capacity = if (header.capacity == 0) initial_capacity else header.capacity * growth_factor;

    if (debug_list) {
        std.debug.print("[list] Growing from capacity {d} to {d}\n", .{ header.capacity, new_capacity });
    }

    const new_elements = if (header.elements_ptr == null)
        allocElements(new_capacity)
    else
        reallocElements(header.elements_ptr, new_capacity);

    if (new_elements == null) {
        if (debug_list) {
            std.debug.print("[list] Failed to allocate {d} elements\n", .{new_capacity});
        }
        return false;
    }

    header.elements_ptr = new_elements;
    header.capacity = new_capacity;
    return true;
}

// ============================================================================
// Exported FFI Functions
// ============================================================================

/// Push a value onto the list. Grows the list if needed.
/// Returns 0 on success, -1 on allocation failure.
export fn cot_native_list_push(list: ?[*]u8, value: i64) i64 {
    const header = getHeader(list) orelse return -1;

    if (debug_list) {
        std.debug.print("[list_push] list={*}, len={d}, cap={d}, value={d}\n", .{ list, header.length, header.capacity, value });
    }

    // Grow if needed
    if (header.length >= header.capacity) {
        if (!growList(header)) {
            return -1; // Allocation failure
        }
    }

    // Store the value
    const elements = header.elements_ptr orelse return -1;
    elements[header.length] = value;
    header.length += 1;

    if (debug_list) {
        std.debug.print("[list_push] After push: len={d}\n", .{header.length});
    }

    return 0;
}

/// Get an element from the list by index.
/// Returns the value at the index, or 0 if out of bounds.
export fn cot_native_list_get(list: ?[*]u8, index: i64) i64 {
    const header = getHeader(list) orelse return 0;

    if (debug_list) {
        std.debug.print("[list_get] list={*}, index={d}, len={d}\n", .{ list, index, header.length });
    }

    // Bounds check
    if (index < 0) return 0;
    const idx: u64 = @intCast(index);
    if (idx >= header.length) return 0;

    const elements = header.elements_ptr orelse return 0;
    return elements[idx];
}

/// Get the length of the list.
/// This is also available inline in codegen, but provided here for completeness.
export fn cot_native_list_len(list: ?[*]u8) i64 {
    const header = getHeader(list) orelse return 0;
    return @intCast(header.length);
}

/// Free the list's element array.
/// Note: The header itself is managed by the caller (allocated via calloc in codegen).
export fn cot_native_list_free(list: ?[*]u8) void {
    const header = getHeader(list) orelse return;

    if (debug_list) {
        std.debug.print("[list_free] list={*}, freeing {d} elements\n", .{ list, header.length });
    }

    freeElements(header.elements_ptr);
    header.elements_ptr = null;
    header.length = 0;
    header.capacity = 0;
}

// ============================================================================
// Tests
// ============================================================================

test "list push and get" {
    // Simulate the 24-byte header allocated by codegen
    var header: ListHeader = .{
        .elements_ptr = null,
        .length = 0,
        .capacity = 0,
    };
    const list_ptr: [*]u8 = @ptrCast(&header);

    // Push some values
    try std.testing.expectEqual(@as(i64, 0), cot_native_list_push(list_ptr, 10));
    try std.testing.expectEqual(@as(i64, 0), cot_native_list_push(list_ptr, 20));
    try std.testing.expectEqual(@as(i64, 0), cot_native_list_push(list_ptr, 30));

    // Check length
    try std.testing.expectEqual(@as(i64, 3), cot_native_list_len(list_ptr));

    // Get values
    try std.testing.expectEqual(@as(i64, 10), cot_native_list_get(list_ptr, 0));
    try std.testing.expectEqual(@as(i64, 20), cot_native_list_get(list_ptr, 1));
    try std.testing.expectEqual(@as(i64, 30), cot_native_list_get(list_ptr, 2));

    // Out of bounds returns 0
    try std.testing.expectEqual(@as(i64, 0), cot_native_list_get(list_ptr, 3));
    try std.testing.expectEqual(@as(i64, 0), cot_native_list_get(list_ptr, -1));

    // Free
    cot_native_list_free(list_ptr);
    try std.testing.expectEqual(@as(i64, 0), header.length);
}

test "list growth" {
    var header: ListHeader = .{
        .elements_ptr = null,
        .length = 0,
        .capacity = 0,
    };
    const list_ptr: [*]u8 = @ptrCast(&header);

    // Push more than initial capacity (8) to trigger growth
    var i: i64 = 0;
    while (i < 20) : (i += 1) {
        try std.testing.expectEqual(@as(i64, 0), cot_native_list_push(list_ptr, i * 10));
    }

    // Verify length
    try std.testing.expectEqual(@as(i64, 20), cot_native_list_len(list_ptr));

    // Verify values
    try std.testing.expectEqual(@as(i64, 0), cot_native_list_get(list_ptr, 0));
    try std.testing.expectEqual(@as(i64, 100), cot_native_list_get(list_ptr, 10));
    try std.testing.expectEqual(@as(i64, 190), cot_native_list_get(list_ptr, 19));

    // Capacity should have grown (8 -> 16 -> 32)
    try std.testing.expect(header.capacity >= 20);

    cot_native_list_free(list_ptr);
}

test "null list handling" {
    // All functions should handle null gracefully
    try std.testing.expectEqual(@as(i64, -1), cot_native_list_push(null, 42));
    try std.testing.expectEqual(@as(i64, 0), cot_native_list_get(null, 0));
    try std.testing.expectEqual(@as(i64, 0), cot_native_list_len(null));
    cot_native_list_free(null); // Should not crash
}
