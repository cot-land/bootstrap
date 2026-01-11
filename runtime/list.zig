///! List runtime for cot compiler.
///!
///! Provides a simple dynamic array implementation with i64 values.
///! Uses a handle-based API matching the Map API for consistency.
///!
///! This is a C ABI compatible library that can be linked with compiled cot programs.

const std = @import("std");

// ============================================================================
// Configuration
// ============================================================================

const debug_list = false; // Enable debug output for troubleshooting
const initial_capacity: u64 = 8;
const growth_factor: u64 = 2;

// ============================================================================
// Data Structures
// ============================================================================

/// List data block (allocated by runtime)
const ListData = struct {
    elements_ptr: ?[*]i64,
    length: u64,
    capacity: u64,
};

/// Stable external handle
const ListHandle = struct {
    data: *ListData,
};

/// Opaque list handle for external callers
pub const List = *ListHandle;

// ============================================================================
// Internal Helpers
// ============================================================================

fn debugPrint(comptime fmt: []const u8, args: anytype) void {
    if (debug_list) {
        std.debug.print("[LIST] " ++ fmt ++ "\n", args);
    }
}

fn growList(data: *ListData) bool {
    const allocator = std.heap.c_allocator;
    const new_capacity = if (data.capacity == 0) initial_capacity else data.capacity * growth_factor;

    debugPrint("Growing from capacity {d} to {d}", .{ data.capacity, new_capacity });

    const new_elements = if (data.elements_ptr == null)
        allocator.alloc(i64, new_capacity) catch return false
    else
        allocator.realloc(data.elements_ptr.?[0..data.capacity], new_capacity) catch return false;

    data.elements_ptr = new_elements.ptr;
    data.capacity = new_capacity;
    return true;
}

// ============================================================================
// Public C ABI Functions
// ============================================================================

/// Create a new list
export fn cot_list_new() ?*ListHandle {
    const allocator = std.heap.c_allocator;

    // Allocate handle
    const handle = allocator.create(ListHandle) catch return null;

    // Allocate data
    const data = allocator.create(ListData) catch {
        allocator.destroy(handle);
        return null;
    };

    data.elements_ptr = null;
    data.length = 0;
    data.capacity = 0;

    handle.data = data;

    debugPrint("List created at {*}", .{handle});

    return handle;
}

/// Push a value onto the list
/// Returns 1 on success, 0 on failure
export fn cot_list_push(handle: ?*ListHandle, value: i64) i64 {
    const h = handle orelse return 0;
    const data = h.data;

    debugPrint("push({d}) - len={d}, cap={d}", .{ value, data.length, data.capacity });

    // Grow if needed
    if (data.length >= data.capacity) {
        if (!growList(data)) {
            return 0;
        }
    }

    // Store the value
    const elements = data.elements_ptr orelse return 0;
    elements[data.length] = value;
    data.length += 1;

    debugPrint("  push success, new len={d}", .{data.length});
    return 1;
}

/// Get an element from the list by index
/// Returns the value at the index, or 0 if out of bounds
export fn cot_list_get(handle: ?*ListHandle, index: i64) i64 {
    const h = handle orelse return 0;
    const data = h.data;

    debugPrint("get({d}) - len={d}", .{ index, data.length });

    // Bounds check
    if (index < 0) return 0;
    const idx: u64 = @intCast(index);
    if (idx >= data.length) return 0;

    const elements = data.elements_ptr orelse return 0;
    return elements[idx];
}

/// Get the length of the list
export fn cot_list_len(handle: ?*ListHandle) i64 {
    const h = handle orelse return 0;
    return @intCast(h.data.length);
}

/// Free the list
export fn cot_list_free(handle: ?*ListHandle) void {
    const h = handle orelse return;
    const allocator = std.heap.c_allocator;

    debugPrint("Freeing list at {*}, len={d}", .{ h, h.data.length });

    // Free elements array
    if (h.data.elements_ptr) |elements| {
        allocator.free(elements[0..h.data.capacity]);
    }

    // Free data and handle
    allocator.destroy(h.data);
    allocator.destroy(h);
}

// ============================================================================
// Tests
// ============================================================================

test "list basic operations" {
    const list = cot_list_new() orelse return error.OutOfMemory;
    defer cot_list_free(list);

    // Initially empty
    try std.testing.expectEqual(@as(i64, 0), cot_list_len(list));

    // Push and get
    _ = cot_list_push(list, 10);
    _ = cot_list_push(list, 20);
    _ = cot_list_push(list, 30);

    try std.testing.expectEqual(@as(i64, 3), cot_list_len(list));
    try std.testing.expectEqual(@as(i64, 10), cot_list_get(list, 0));
    try std.testing.expectEqual(@as(i64, 20), cot_list_get(list, 1));
    try std.testing.expectEqual(@as(i64, 30), cot_list_get(list, 2));

    // Out of bounds returns 0
    try std.testing.expectEqual(@as(i64, 0), cot_list_get(list, 3));
    try std.testing.expectEqual(@as(i64, 0), cot_list_get(list, -1));
}

test "list growth" {
    const list = cot_list_new() orelse return error.OutOfMemory;
    defer cot_list_free(list);

    // Push more than initial capacity (8) to trigger growth
    var i: i64 = 0;
    while (i < 20) : (i += 1) {
        try std.testing.expectEqual(@as(i64, 1), cot_list_push(list, i * 10));
    }

    try std.testing.expectEqual(@as(i64, 20), cot_list_len(list));
    try std.testing.expectEqual(@as(i64, 0), cot_list_get(list, 0));
    try std.testing.expectEqual(@as(i64, 100), cot_list_get(list, 10));
    try std.testing.expectEqual(@as(i64, 190), cot_list_get(list, 19));
}

test "list null handle safety" {
    try std.testing.expectEqual(@as(i64, 0), cot_list_len(null));
    try std.testing.expectEqual(@as(i64, 0), cot_list_get(null, 0));
    try std.testing.expectEqual(@as(i64, 0), cot_list_push(null, 42));
    cot_list_free(null); // Should not crash
}
