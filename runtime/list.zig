///! List runtime for cot compiler.
///!
///! Provides a dynamic array implementation that supports arbitrary element sizes.
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
    elements_ptr: ?[*]u8, // Byte array - supports arbitrary element sizes
    length: u64,
    capacity: u64,
    elem_size: u64, // Size of each element in bytes
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
    const new_byte_size = new_capacity * data.elem_size;
    const old_byte_size = data.capacity * data.elem_size;

    debugPrint("Growing from capacity {d} to {d} (elem_size={d})", .{ data.capacity, new_capacity, data.elem_size });

    const new_elements = if (data.elements_ptr == null)
        allocator.alloc(u8, new_byte_size) catch return false
    else
        allocator.realloc(data.elements_ptr.?[0..old_byte_size], new_byte_size) catch return false;

    data.elements_ptr = new_elements.ptr;
    data.capacity = new_capacity;
    return true;
}

// ============================================================================
// Public C ABI Functions
// ============================================================================

/// Create a new list with specified element size
/// elem_size: size of each element in bytes (e.g., 8 for int, 16 for union)
export fn cot_list_new(elem_size: i64) ?*ListHandle {
    const allocator = std.heap.c_allocator;

    // Validate element size
    if (elem_size <= 0) {
        debugPrint("Invalid elem_size: {d}", .{elem_size});
        return null;
    }

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
    data.elem_size = @intCast(elem_size);

    handle.data = data;

    debugPrint("List created at {*}, elem_size={d}", .{ handle, elem_size });

    return handle;
}

/// Push a value onto the list (by pointer for arbitrary sizes)
/// For small values (<= 8 bytes), value_ptr can be the value itself cast to pointer
/// For larger values, value_ptr must point to the actual value
/// Returns 1 on success, 0 on failure
export fn cot_list_push(handle: ?*ListHandle, value_ptr: i64) i64 {
    const h = handle orelse return 0;
    const data = h.data;

    debugPrint("push(ptr={x}) - len={d}, cap={d}, elem_size={d}", .{ value_ptr, data.length, data.capacity, data.elem_size });

    // Grow if needed
    if (data.length >= data.capacity) {
        if (!growList(data)) {
            return 0;
        }
    }

    const elements = data.elements_ptr orelse return 0;
    const offset = data.length * data.elem_size;

    // For elements <= 8 bytes, the value is passed directly (as i64)
    // For larger elements, value_ptr is actually a pointer to the data
    if (data.elem_size <= 8) {
        // Small value - store directly
        const dest = elements + offset;
        const value_bytes = std.mem.asBytes(&value_ptr);
        @memcpy(dest[0..data.elem_size], value_bytes[0..data.elem_size]);
    } else {
        // Large value - value_ptr is a pointer to the source data
        const src: [*]const u8 = @ptrFromInt(@as(usize, @intCast(value_ptr)));
        const dest = elements + offset;
        @memcpy(dest[0..data.elem_size], src[0..data.elem_size]);
    }

    data.length += 1;

    debugPrint("  push success, new len={d}", .{data.length});
    return 1;
}

/// Get an element from the list by index
/// For elements <= 8 bytes, returns the value directly
/// For larger elements, returns a pointer to the element (valid until list is modified)
export fn cot_list_get(handle: ?*ListHandle, index: i64) i64 {
    const h = handle orelse return 0;
    const data = h.data;

    debugPrint("get({d}) - len={d}, elem_size={d}", .{ index, data.length, data.elem_size });

    // Bounds check
    if (index < 0) return 0;
    const idx: u64 = @intCast(index);
    if (idx >= data.length) return 0;

    const elements = data.elements_ptr orelse return 0;
    const offset = idx * data.elem_size;

    if (data.elem_size <= 8) {
        // Small element - return value directly
        var result: i64 = 0;
        const result_bytes = std.mem.asBytes(&result);
        const src = elements + offset;
        @memcpy(result_bytes[0..data.elem_size], src[0..data.elem_size]);
        return result;
    } else {
        // Large element - return pointer to element
        const elem_ptr = elements + offset;
        return @intCast(@intFromPtr(elem_ptr));
    }
}

/// Get the length of the list
export fn cot_list_len(handle: ?*ListHandle) i64 {
    const h = handle orelse return 0;
    return @intCast(h.data.length);
}

/// Free the list and all its resources
export fn cot_list_free(handle: ?*ListHandle) void {
    const h = handle orelse return;
    const data = h.data;
    const allocator = std.heap.c_allocator;

    debugPrint("Freeing list at {*}", .{h});

    // Free elements array
    if (data.elements_ptr) |elements| {
        const byte_size = data.capacity * data.elem_size;
        allocator.free(elements[0..byte_size]);
    }

    // Free data struct
    allocator.destroy(data);

    // Free handle
    allocator.destroy(h);
}

/// Get the element size of the list
export fn cot_list_elem_size(handle: ?*ListHandle) i64 {
    const h = handle orelse return 0;
    return @intCast(h.data.elem_size);
}

/// Get raw data pointer for the list's internal storage.
/// Returns the byte pointer, or null (0) if empty or invalid.
/// Used for file I/O where we need direct access to the bytes.
export fn cot_list_data_ptr(handle: ?*ListHandle) i64 {
    const h = handle orelse return 0;
    const data = h.data;
    const ptr = data.elements_ptr orelse return 0;
    return @intCast(@intFromPtr(ptr));
}

/// Get total byte size of list data (length * elem_size).
/// Returns 0 if empty or invalid.
export fn cot_list_byte_size(handle: ?*ListHandle) i64 {
    const h = handle orelse return 0;
    const data = h.data;
    return @intCast(data.length * data.elem_size);
}

/// Write list elements as bytes to a file.
/// Each list element is written as a single byte (low 8 bits only).
/// Used for writing byte buffers stored in List<int>.
/// Returns bytes written on success, -1 on failure.
export fn cot_file_write_list_bytes(path_ptr: i64, path_len: i64, list_handle: ?*ListHandle) i64 {
    const h = list_handle orelse return -1;
    const data = h.data;

    // Build path slice
    const path_slice = blk: {
        const ptr: [*]const u8 = @ptrFromInt(@as(usize, @intCast(path_ptr)));
        break :blk ptr[0..@intCast(path_len)];
    };

    // Create file
    const file = std.fs.cwd().createFile(path_slice, .{}) catch return -1;
    defer file.close();

    if (data.length == 0) return 0;

    const elements = data.elements_ptr orelse return -1;
    const elem_size = data.elem_size;

    // Write each element's low byte
    var i: u64 = 0;
    while (i < data.length) : (i += 1) {
        const offset = i * elem_size;
        const byte_val = elements[offset];
        const single_byte = [_]u8{byte_val};
        file.writeAll(&single_byte) catch return -1;
    }

    return @intCast(data.length);
}

/// Set an element in the list at a specific index
/// For elements <= 8 bytes, value is passed directly
/// For larger elements, value is a pointer to the source data
/// Returns 1 on success, 0 on failure (out of bounds)
export fn cot_list_set(handle: ?*ListHandle, index: i64, value: i64) i64 {
    const h = handle orelse return 0;
    const data = h.data;

    debugPrint("set({d}, {x}) - len={d}, elem_size={d}", .{ index, value, data.length, data.elem_size });

    // Bounds check
    if (index < 0) return 0;
    const idx: u64 = @intCast(index);
    if (idx >= data.length) return 0;

    const elements = data.elements_ptr orelse return 0;
    const offset = idx * data.elem_size;

    if (data.elem_size <= 8) {
        // Small element - store value directly
        const dest = elements + offset;
        const value_bytes = std.mem.asBytes(&value);
        @memcpy(dest[0..data.elem_size], value_bytes[0..data.elem_size]);
    } else {
        // Large element - value is a pointer to the source data
        const src: [*]const u8 = @ptrFromInt(@as(usize, @intCast(value)));
        const dest = elements + offset;
        @memcpy(dest[0..data.elem_size], src[0..data.elem_size]);
    }

    debugPrint("  set success", .{});
    return 1;
}

// ============================================================================
// Tests
// ============================================================================

test "list basic operations with 8-byte elements" {
    const handle = cot_list_new(8) orelse return error.CreateFailed;
    defer cot_list_free(handle);

    // Push some values
    try std.testing.expectEqual(@as(i64, 1), cot_list_push(handle, 42));
    try std.testing.expectEqual(@as(i64, 1), cot_list_push(handle, 100));
    try std.testing.expectEqual(@as(i64, 1), cot_list_push(handle, -5));

    // Check length
    try std.testing.expectEqual(@as(i64, 3), cot_list_len(handle));

    // Get values
    try std.testing.expectEqual(@as(i64, 42), cot_list_get(handle, 0));
    try std.testing.expectEqual(@as(i64, 100), cot_list_get(handle, 1));
    try std.testing.expectEqual(@as(i64, -5), cot_list_get(handle, 2));
}

test "list with 16-byte elements" {
    const handle = cot_list_new(16) orelse return error.CreateFailed;
    defer cot_list_free(handle);

    // Create a 16-byte value (simulating a union with tag + payload)
    var value1: [16]u8 = undefined;
    value1[0] = 0; // tag = 0
    @memset(value1[1..8], 0);
    std.mem.writeInt(i64, value1[8..16], 42, .little); // payload = 42

    var value2: [16]u8 = undefined;
    value2[0] = 1; // tag = 1
    @memset(value2[1..8], 0);
    std.mem.writeInt(i64, value2[8..16], 100, .little); // payload = 100

    // Push by pointer
    try std.testing.expectEqual(@as(i64, 1), cot_list_push(handle, @intCast(@intFromPtr(&value1))));
    try std.testing.expectEqual(@as(i64, 1), cot_list_push(handle, @intCast(@intFromPtr(&value2))));

    try std.testing.expectEqual(@as(i64, 2), cot_list_len(handle));

    // Get returns pointer for large elements
    const ptr1: [*]u8 = @ptrFromInt(@as(usize, @intCast(cot_list_get(handle, 0))));
    const ptr2: [*]u8 = @ptrFromInt(@as(usize, @intCast(cot_list_get(handle, 1))));

    try std.testing.expectEqual(@as(u8, 0), ptr1[0]); // tag
    try std.testing.expectEqual(@as(i64, 42), std.mem.readInt(i64, ptr1[8..16], .little));

    try std.testing.expectEqual(@as(u8, 1), ptr2[0]); // tag
    try std.testing.expectEqual(@as(i64, 100), std.mem.readInt(i64, ptr2[8..16], .little));
}

test "list bounds checking" {
    const handle = cot_list_new(8) orelse return error.CreateFailed;
    defer cot_list_free(handle);

    _ = cot_list_push(handle, 42);

    // Out of bounds returns 0
    try std.testing.expectEqual(@as(i64, 0), cot_list_get(handle, -1));
    try std.testing.expectEqual(@as(i64, 0), cot_list_get(handle, 1));
    try std.testing.expectEqual(@as(i64, 0), cot_list_get(handle, 100));
}

test "list growth" {
    const handle = cot_list_new(8) orelse return error.CreateFailed;
    defer cot_list_free(handle);

    // Push more than initial capacity
    var i: i64 = 0;
    while (i < 100) : (i += 1) {
        try std.testing.expectEqual(@as(i64, 1), cot_list_push(handle, i * 10));
    }

    try std.testing.expectEqual(@as(i64, 100), cot_list_len(handle));

    // Verify all values
    i = 0;
    while (i < 100) : (i += 1) {
        try std.testing.expectEqual(i * 10, cot_list_get(handle, i));
    }
}

test "list set" {
    const handle = cot_list_new(8) orelse return error.CreateFailed;
    defer cot_list_free(handle);

    // Push initial values
    _ = cot_list_push(handle, 10);
    _ = cot_list_push(handle, 20);
    _ = cot_list_push(handle, 30);

    // Verify initial values
    try std.testing.expectEqual(@as(i64, 10), cot_list_get(handle, 0));
    try std.testing.expectEqual(@as(i64, 20), cot_list_get(handle, 1));
    try std.testing.expectEqual(@as(i64, 30), cot_list_get(handle, 2));

    // Set values
    try std.testing.expectEqual(@as(i64, 1), cot_list_set(handle, 0, 100));
    try std.testing.expectEqual(@as(i64, 1), cot_list_set(handle, 1, 200));
    try std.testing.expectEqual(@as(i64, 1), cot_list_set(handle, 2, 300));

    // Verify updated values
    try std.testing.expectEqual(@as(i64, 100), cot_list_get(handle, 0));
    try std.testing.expectEqual(@as(i64, 200), cot_list_get(handle, 1));
    try std.testing.expectEqual(@as(i64, 300), cot_list_get(handle, 2));

    // Out of bounds set should return 0
    try std.testing.expectEqual(@as(i64, 0), cot_list_set(handle, -1, 999));
    try std.testing.expectEqual(@as(i64, 0), cot_list_set(handle, 3, 999));
    try std.testing.expectEqual(@as(i64, 0), cot_list_set(handle, 100, 999));

    // Length should be unchanged
    try std.testing.expectEqual(@as(i64, 3), cot_list_len(handle));
}
