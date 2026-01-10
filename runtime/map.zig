///! Map runtime for cot compiler.
///!
///! Provides a simple hash map implementation with string keys and i64 values.
///! Based on Zig's std.HashMap design with linear probing and 7-bit fingerprints.
///!
///! This is a C ABI compatible library that can be linked with compiled cot programs.

const std = @import("std");
const builtin = @import("builtin");

// ============================================================================
// Configuration
// ============================================================================

const debug_map = false; // Enable debug output for troubleshooting
const max_load_percentage: u64 = 80;
const initial_capacity: u32 = 8;

// ============================================================================
// Data Structures
// ============================================================================

/// Metadata for a slot: 7-bit fingerprint + 1-bit used flag
const Metadata = packed struct {
    fingerprint: u7 = 0,
    used: u1 = 0,

    const free: u8 = 0;
    const tombstone: u8 = 1;

    fn isUsed(self: Metadata) bool {
        return self.used == 1;
    }

    fn isFree(self: Metadata) bool {
        return @as(u8, @bitCast(self)) == free;
    }

    fn isTombstone(self: Metadata) bool {
        return @as(u8, @bitCast(self)) == tombstone;
    }

    fn fingerprint7(hash: u64) u7 {
        // Use upper 7 bits for fingerprint (avoid 0 and 1 which are free/tombstone)
        const fp = @as(u7, @truncate(hash >> 57));
        return if (fp < 2) fp + 2 else fp;
    }
};

/// String key: pointer + length
const StringKey = extern struct {
    ptr: [*]const u8,
    len: u64,

    fn slice(self: StringKey) []const u8 {
        return self.ptr[0..@intCast(self.len)];
    }

    fn eql(self: StringKey, other: StringKey) bool {
        if (self.len != other.len) return false;
        return std.mem.eql(u8, self.slice(), other.slice());
    }
};

/// Internal data block header
const DataHeader = struct {
    capacity: u32,
    size: u32,
    available: u32, // Slots available before grow needed
    _padding: u32 = 0,
    // Followed by:
    // - metadata: [capacity]u8
    // - keys: [capacity]StringKey
    // - values: [capacity]i64
};

/// Stable external handle - contains pointer to data that may be reallocated
const MapHandle = struct {
    data: *DataHeader,
};

/// Opaque map handle for external callers
pub const Map = *MapHandle;

// ============================================================================
// Hash Function (FNV-1a)
// ============================================================================

fn hashString(s: []const u8) u64 {
    // FNV-1a hash for strings
    var hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    for (s) |byte| {
        hash ^= byte;
        hash *%= 0x100000001b3; // FNV prime
    }
    return hash;
}

// ============================================================================
// Internal Helpers
// ============================================================================

fn getMetadata(header: *DataHeader) [*]u8 {
    const base = @intFromPtr(header);
    return @ptrFromInt(base + @sizeOf(DataHeader));
}

fn getKeys(header: *DataHeader) [*]StringKey {
    const base = @intFromPtr(header);
    const metadata_size = header.capacity;
    // Align to 8 bytes
    const aligned = (metadata_size + 7) & ~@as(u32, 7);
    return @ptrFromInt(base + @sizeOf(DataHeader) + aligned);
}

fn getValues(header: *DataHeader) [*]i64 {
    const base = @intFromPtr(header);
    const metadata_size = header.capacity;
    const aligned_meta = (metadata_size + 7) & ~@as(u32, 7);
    const keys_size = header.capacity * @sizeOf(StringKey);
    return @ptrFromInt(base + @sizeOf(DataHeader) + aligned_meta + keys_size);
}

fn dataAllocationSize(capacity: u32) usize {
    const aligned_meta = (capacity + 7) & ~@as(u32, 7);
    return @sizeOf(DataHeader) +
        aligned_meta + // metadata
        capacity * @sizeOf(StringKey) + // keys
        capacity * @sizeOf(i64); // values
}

fn debugPrint(comptime fmt: []const u8, args: anytype) void {
    if (debug_map) {
        std.debug.print("[MAP] " ++ fmt ++ "\n", args);
    }
}

// ============================================================================
// Core Map Operations
// ============================================================================

fn findSlot(header: *DataHeader, key: StringKey, hash: u64) struct { index: u32, found: bool } {
    const metadata = getMetadata(header);
    const keys = getKeys(header);
    const capacity = header.capacity;
    const fp = Metadata.fingerprint7(hash);

    var idx: u32 = @truncate(hash % capacity);
    var probes: u32 = 0;

    while (probes < capacity) {
        const meta: Metadata = @bitCast(metadata[idx]);

        if (meta.isFree()) {
            // Empty slot - key not found
            return .{ .index = idx, .found = false };
        }

        if (meta.isUsed() and meta.fingerprint == fp) {
            // Fingerprint matches - check actual key
            if (keys[idx].eql(key)) {
                return .{ .index = idx, .found = true };
            }
        }

        // Linear probing
        idx = (idx + 1) % capacity;
        probes += 1;
    }

    // Table is full (shouldn't happen with proper load factor)
    return .{ .index = 0, .found = false };
}

fn findSlotForInsert(header: *DataHeader, key: StringKey, hash: u64) struct { index: u32, found: bool } {
    const metadata = getMetadata(header);
    const keys = getKeys(header);
    const capacity = header.capacity;
    const fp = Metadata.fingerprint7(hash);

    var idx: u32 = @truncate(hash % capacity);
    var probes: u32 = 0;
    var first_tombstone: ?u32 = null;

    while (probes < capacity) {
        const meta: Metadata = @bitCast(metadata[idx]);

        if (meta.isFree()) {
            // Empty slot - use tombstone if we found one, otherwise use this slot
            const insert_idx = first_tombstone orelse idx;
            return .{ .index = insert_idx, .found = false };
        }

        if (meta.isTombstone()) {
            // Remember first tombstone for potential reuse
            if (first_tombstone == null) {
                first_tombstone = idx;
            }
        } else if (meta.fingerprint == fp) {
            // Fingerprint matches - check actual key
            if (keys[idx].eql(key)) {
                return .{ .index = idx, .found = true };
            }
        }

        // Linear probing
        idx = (idx + 1) % capacity;
        probes += 1;
    }

    // Use tombstone or fail
    if (first_tombstone) |ts| {
        return .{ .index = ts, .found = false };
    }
    return .{ .index = 0, .found = false };
}

fn allocateData(capacity: u32) ?*DataHeader {
    const allocator = std.heap.c_allocator;
    const size = dataAllocationSize(capacity);

    debugPrint("Allocating data with capacity {d}, size {d}", .{ capacity, size });

    const ptr = allocator.alloc(u8, size) catch return null;
    @memset(ptr, 0);

    const header: *DataHeader = @ptrCast(@alignCast(ptr.ptr));
    header.capacity = capacity;
    header.size = 0;
    header.available = @intCast((capacity * max_load_percentage) / 100);

    return header;
}

/// Free only the data block, not the key strings (used during grow when keys are moved)
fn freeDataBlockOnly(header: *DataHeader) void {
    const allocator = std.heap.c_allocator;
    const size = dataAllocationSize(header.capacity);
    const ptr: [*]u8 = @ptrCast(header);
    allocator.free(ptr[0..size]);
}

/// Free the data block AND all key strings (used for final cleanup)
fn freeData(header: *DataHeader) void {
    const allocator = std.heap.c_allocator;

    // Free all copied key strings
    const metadata = getMetadata(header);
    const keys = getKeys(header);
    var i: u32 = 0;
    while (i < header.capacity) : (i += 1) {
        const meta: Metadata = @bitCast(metadata[i]);
        if (meta.isUsed()) {
            const key = keys[i];
            const key_ptr: [*]u8 = @constCast(key.ptr);
            allocator.free(key_ptr[0..@intCast(key.len)]);
        }
    }

    // Free the data block
    freeDataBlockOnly(header);
}

fn grow(handle: *MapHandle) bool {
    const old_header = handle.data;
    const old_capacity = old_header.capacity;
    const new_capacity = old_capacity * 2;

    debugPrint("Growing map from {d} to {d} slots", .{ old_capacity, new_capacity });

    // Allocate new data block
    const new_header = allocateData(new_capacity) orelse return false;

    // Copy all entries
    const old_metadata = getMetadata(old_header);
    const old_keys = getKeys(old_header);
    const old_values = getValues(old_header);

    const new_metadata = getMetadata(new_header);
    const new_keys = getKeys(new_header);
    const new_values = getValues(new_header);

    var i: u32 = 0;
    while (i < old_capacity) : (i += 1) {
        const meta: Metadata = @bitCast(old_metadata[i]);
        if (meta.isUsed()) {
            // Re-hash and insert into new data
            const key = old_keys[i];
            const hash = hashString(key.slice());
            const fp = Metadata.fingerprint7(hash);

            var idx: u32 = @truncate(hash % new_capacity);
            while (true) {
                const new_meta: Metadata = @bitCast(new_metadata[idx]);
                if (new_meta.isFree()) {
                    new_metadata[idx] = @bitCast(Metadata{ .fingerprint = fp, .used = 1 });
                    new_keys[idx] = key;
                    new_values[idx] = old_values[i];
                    new_header.size += 1;
                    new_header.available -= 1;
                    break;
                }
                idx = (idx + 1) % new_capacity;
            }
        }
    }

    // Update handle to point to new data
    handle.data = new_header;

    // Free old data block only - keys have been moved to new table, don't free them!
    freeDataBlockOnly(old_header);

    debugPrint("Grow complete, new size={d}, available={d}", .{ new_header.size, new_header.available });
    return true;
}

fn setInternal(header: *DataHeader, key: StringKey, value: i64) bool {
    const hash = hashString(key.slice());
    const result = findSlotForInsert(header, key, hash);

    const metadata = getMetadata(header);
    const keys = getKeys(header);
    const values = getValues(header);

    if (!result.found) {
        // New entry - copy the key string
        const allocator = std.heap.c_allocator;
        const key_copy = allocator.alloc(u8, @intCast(key.len)) catch return false;
        @memcpy(key_copy, key.slice());

        keys[result.index] = StringKey{
            .ptr = key_copy.ptr,
            .len = key.len,
        };

        header.size += 1;
        header.available -= 1;
    }
    // If updating existing key, we keep the old key (it should be equal anyway)

    // Set metadata, value
    const fp = Metadata.fingerprint7(hash);
    metadata[result.index] = @bitCast(Metadata{ .fingerprint = fp, .used = 1 });
    values[result.index] = value;

    return true;
}

// ============================================================================
// Public C ABI Functions
// ============================================================================

/// Create a new map with default capacity
export fn cot_map_new() ?*MapHandle {
    return cot_map_new_with_capacity(initial_capacity);
}

/// Create a new map with specified capacity
export fn cot_map_new_with_capacity(capacity: u32) ?*MapHandle {
    const allocator = std.heap.c_allocator;

    // Allocate handle
    const handle = allocator.create(MapHandle) catch return null;

    // Allocate data
    const data = allocateData(capacity) orelse {
        allocator.destroy(handle);
        return null;
    };

    handle.data = data;

    debugPrint("Map created at {*}, capacity={d}, available={d}", .{ handle, capacity, data.available });

    return handle;
}

/// Set a key-value pair in the map
/// Returns 1 on success, 0 on failure
export fn cot_map_set(handle: ?*MapHandle, key_ptr: [*]const u8, key_len: u64, value: i64) i64 {
    const h = handle orelse return 0;

    const key = StringKey{ .ptr = key_ptr, .len = key_len };

    debugPrint("set(\"{s}\", {d}) - size={d}, available={d}", .{
        key.slice(),
        value,
        h.data.size,
        h.data.available,
    });

    // Check if we need to grow
    if (h.data.available == 0) {
        if (!grow(h)) return 0;
    }

    if (setInternal(h.data, key, value)) {
        debugPrint("  set success, new size={d}", .{h.data.size});
        return 1;
    }
    return 0;
}

/// Get a value from the map
/// Returns the value if found, or a sentinel value (MIN_INT) if not found
export fn cot_map_get(handle: ?*MapHandle, key_ptr: [*]const u8, key_len: u64) i64 {
    const h = handle orelse return std.math.minInt(i64);

    const key = StringKey{ .ptr = key_ptr, .len = key_len };
    const hash = hashString(key.slice());
    const result = findSlot(h.data, key, hash);

    if (result.found) {
        const values = getValues(h.data);
        debugPrint("get(\"{s}\") = {d}", .{ key.slice(), values[result.index] });
        return values[result.index];
    }

    debugPrint("get(\"{s}\") = NOT FOUND", .{key.slice()});
    return std.math.minInt(i64);
}

/// Check if a key exists in the map
/// Returns 1 if found, 0 if not
export fn cot_map_has(handle: ?*MapHandle, key_ptr: [*]const u8, key_len: u64) i64 {
    const h = handle orelse return 0;

    const key = StringKey{ .ptr = key_ptr, .len = key_len };
    const hash = hashString(key.slice());
    const result = findSlot(h.data, key, hash);

    debugPrint("has(\"{s}\") = {d}", .{ key.slice(), if (result.found) @as(i64, 1) else @as(i64, 0) });
    return if (result.found) 1 else 0;
}

/// Get the number of entries in the map
export fn cot_map_size(handle: ?*MapHandle) i64 {
    const h = handle orelse return 0;
    return h.data.size;
}

/// Free the map
export fn cot_map_free(handle: ?*MapHandle) void {
    const h = handle orelse return;

    debugPrint("Freeing map at {*}, size={d}", .{ h, h.data.size });

    freeData(h.data);

    const allocator = std.heap.c_allocator;
    allocator.destroy(h);
}

// ============================================================================
// Debug Functions
// ============================================================================

/// Dump map contents for debugging
export fn cot_map_dump(handle: ?*MapHandle) void {
    const h = handle orelse {
        debugPrint("Map is null", .{});
        return;
    };

    const header = h.data;
    const metadata = getMetadata(header);
    const keys = getKeys(header);
    const values = getValues(header);

    debugPrint("=== Map Dump ===", .{});
    debugPrint("Capacity: {d}, Size: {d}, Available: {d}", .{ header.capacity, header.size, header.available });

    var i: u32 = 0;
    while (i < header.capacity) : (i += 1) {
        const meta: Metadata = @bitCast(metadata[i]);
        if (meta.isUsed()) {
            debugPrint("  [{d}] \"{s}\" = {d} (fp={d})", .{ i, keys[i].slice(), values[i], meta.fingerprint });
        }
    }
    debugPrint("================", .{});
}

// ============================================================================
// Tests
// ============================================================================

test "map basic operations" {
    const map = cot_map_new() orelse return error.OutOfMemory;
    defer cot_map_free(map);

    // Initially empty
    try std.testing.expectEqual(@as(i64, 0), cot_map_size(map));

    // Set and get
    const key = "hello";
    _ = cot_map_set(map, key.ptr, key.len, 42);
    try std.testing.expectEqual(@as(i64, 42), cot_map_get(map, key.ptr, key.len));
    try std.testing.expectEqual(@as(i64, 1), cot_map_has(map, key.ptr, key.len));
    try std.testing.expectEqual(@as(i64, 1), cot_map_size(map));

    // Key not found
    const unknown = "unknown";
    try std.testing.expectEqual(@as(i64, 0), cot_map_has(map, unknown.ptr, unknown.len));

    // Update existing key
    _ = cot_map_set(map, key.ptr, key.len, 100);
    try std.testing.expectEqual(@as(i64, 100), cot_map_get(map, key.ptr, key.len));
    try std.testing.expectEqual(@as(i64, 1), cot_map_size(map)); // Size unchanged
}

test "map multiple entries" {
    const map = cot_map_new() orelse return error.OutOfMemory;
    defer cot_map_free(map);

    const keys = [_][]const u8{ "one", "two", "three", "four", "five" };
    const values = [_]i64{ 1, 2, 3, 4, 5 };

    // Insert all
    for (keys, values) |k, v| {
        _ = cot_map_set(map, k.ptr, k.len, v);
    }

    try std.testing.expectEqual(@as(i64, 5), cot_map_size(map));

    // Verify all
    for (keys, values) |k, v| {
        try std.testing.expectEqual(v, cot_map_get(map, k.ptr, k.len));
    }
}

test "map grow" {
    const map = cot_map_new_with_capacity(4) orelse return error.OutOfMemory;
    defer cot_map_free(map);

    // Insert more than capacity * load_factor to trigger grow
    var i: i64 = 0;
    while (i < 20) : (i += 1) {
        var buf: [16]u8 = undefined;
        const key = std.fmt.bufPrint(&buf, "key{d}", .{i}) catch unreachable;
        _ = cot_map_set(map, key.ptr, key.len, i * 10);
    }

    try std.testing.expectEqual(@as(i64, 20), cot_map_size(map));

    // Verify all entries still accessible after grow
    i = 0;
    while (i < 20) : (i += 1) {
        var buf: [16]u8 = undefined;
        const key = std.fmt.bufPrint(&buf, "key{d}", .{i}) catch unreachable;
        try std.testing.expectEqual(i * 10, cot_map_get(map, key.ptr, key.len));
    }
}

test "map hash distribution" {
    // Test that different keys hash differently
    const h1 = hashString("hello");
    const h2 = hashString("world");
    const h3 = hashString("hello"); // Same as h1

    try std.testing.expect(h1 != h2);
    try std.testing.expectEqual(h1, h3);
}

test "map stress test" {
    const map = cot_map_new() orelse return error.OutOfMemory;
    defer cot_map_free(map);

    // Insert 1000 entries
    var i: i64 = 0;
    while (i < 1000) : (i += 1) {
        var buf: [32]u8 = undefined;
        const key = std.fmt.bufPrint(&buf, "stress_key_{d}", .{i}) catch unreachable;
        _ = cot_map_set(map, key.ptr, key.len, i);
    }

    try std.testing.expectEqual(@as(i64, 1000), cot_map_size(map));

    // Verify random samples
    const samples = [_]i64{ 0, 100, 500, 999 };
    for (samples) |idx| {
        var buf: [32]u8 = undefined;
        const key = std.fmt.bufPrint(&buf, "stress_key_{d}", .{idx}) catch unreachable;
        try std.testing.expectEqual(idx, cot_map_get(map, key.ptr, key.len));
    }
}

test "map empty string key" {
    const map = cot_map_new() orelse return error.OutOfMemory;
    defer cot_map_free(map);

    // Empty string as key should work
    const empty = "";
    _ = cot_map_set(map, empty.ptr, empty.len, 123);
    try std.testing.expectEqual(@as(i64, 123), cot_map_get(map, empty.ptr, empty.len));
    try std.testing.expectEqual(@as(i64, 1), cot_map_has(map, empty.ptr, empty.len));
}

test "map long key" {
    const map = cot_map_new() orelse return error.OutOfMemory;
    defer cot_map_free(map);

    // Very long key
    const long_key = "this_is_a_very_long_key_that_might_cause_issues_if_not_handled_correctly_" ++
        "and_it_keeps_going_and_going_for_a_while_to_test_long_string_hashing";
    _ = cot_map_set(map, long_key.ptr, long_key.len, 999);
    try std.testing.expectEqual(@as(i64, 999), cot_map_get(map, long_key.ptr, long_key.len));
}

test "map update same key multiple times" {
    const map = cot_map_new() orelse return error.OutOfMemory;
    defer cot_map_free(map);

    const key = "counter";

    // Update same key 100 times
    var i: i64 = 0;
    while (i < 100) : (i += 1) {
        _ = cot_map_set(map, key.ptr, key.len, i);
    }

    // Size should still be 1 (only one key)
    try std.testing.expectEqual(@as(i64, 1), cot_map_size(map));
    // Value should be last set value
    try std.testing.expectEqual(@as(i64, 99), cot_map_get(map, key.ptr, key.len));
}

test "map similar keys" {
    const map = cot_map_new() orelse return error.OutOfMemory;
    defer cot_map_free(map);

    // Keys with same prefix
    const keys = [_][]const u8{ "key", "key1", "key12", "key123", "key1234" };

    for (keys, 0..) |k, i| {
        _ = cot_map_set(map, k.ptr, k.len, @intCast(i * 10));
    }

    try std.testing.expectEqual(@as(i64, 5), cot_map_size(map));

    // Verify each key has correct value
    for (keys, 0..) |k, i| {
        try std.testing.expectEqual(@as(i64, @intCast(i * 10)), cot_map_get(map, k.ptr, k.len));
    }
}

test "map null handle safety" {
    // All operations should be safe with null handle
    try std.testing.expectEqual(@as(i64, 0), cot_map_size(null));
    try std.testing.expectEqual(@as(i64, 0), cot_map_has(null, "key".ptr, 3));
    try std.testing.expectEqual(std.math.minInt(i64), cot_map_get(null, "key".ptr, 3));
    try std.testing.expectEqual(@as(i64, 0), cot_map_set(null, "key".ptr, 3, 42));
    cot_map_free(null); // Should not crash
}

// ============================================================================
// Native Layout FFI Helpers
// ============================================================================
//
// Native map layout (allocated by codegen via calloc):
//   Header (32 bytes at offset 0):
//     - capacity: u64 (offset 0)
//     - size: u64 (offset 8)
//     - seed: u64 (offset 16) - FNV offset basis, unused currently
//     - unused: u64 (offset 24)
//   Slots (starting at offset 32, each slot is 32 bytes):
//     - meta: u8 (offset 0) - 0=empty, 1=occupied, 2=deleted
//     - padding: 7 bytes
//     - key_ptr: u64 (offset 8)
//     - key_len: u64 (offset 16)
//     - value: i64 (offset 24)

const NativeHeader = extern struct {
    capacity: u64,
    size: u64,
    seed: u64,
    unused: u64,
};

const NativeSlot = extern struct {
    meta: u8,
    _pad: [7]u8,
    key_ptr: u64,
    key_len: u64,
    value: i64,
};

fn getNativeSlots(map: [*]u8) [*]NativeSlot {
    return @ptrCast(@alignCast(map + 32)); // Slots start after 32-byte header
}

fn getNativeHeader(map: [*]u8) *NativeHeader {
    return @ptrCast(@alignCast(map));
}

/// FNV-1a hash for native layout
fn fnvHash(key_ptr: [*]const u8, key_len: u64) u64 {
    var hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    var i: u64 = 0;
    while (i < key_len) : (i += 1) {
        hash ^= key_ptr[i];
        hash *%= 0x100000001b3; // FNV prime
    }
    return hash;
}

/// Native map set - works with codegen-allocated layout
/// map: pointer to native map (from calloc)
/// key_ptr: pointer to key string
/// key_len: length of key
/// value: value to store
/// Returns 1 on success, 0 on failure (map full)
export fn cot_native_map_set(map: ?[*]u8, key_ptr: [*]const u8, key_len: u64, value: i64) i64 {
    const m = map orelse return 0;
    const header = getNativeHeader(m);
    const slots = getNativeSlots(m);
    const capacity = header.capacity;

    if (capacity == 0) return 0;

    const hash = fnvHash(key_ptr, key_len);
    var idx = hash % capacity;
    var probes: u64 = 0;

    // Linear probe to find empty slot or existing key
    while (probes < capacity) {
        const slot = &slots[idx];

        if (slot.meta == 0 or slot.meta == 2) {
            // Empty or deleted slot - insert here
            // Copy key string (allocate new storage for it)
            const key_copy = std.heap.c_allocator.alloc(u8, key_len) catch return 0;
            @memcpy(key_copy, key_ptr[0..key_len]);

            slot.meta = 1; // occupied
            slot.key_ptr = @intFromPtr(key_copy.ptr);
            slot.key_len = key_len;
            slot.value = value;
            header.size += 1;
            return 1;
        }

        if (slot.meta == 1) {
            // Occupied slot - check if same key
            if (slot.key_len == key_len) {
                const existing_key: [*]const u8 = @ptrFromInt(slot.key_ptr);
                if (std.mem.eql(u8, existing_key[0..key_len], key_ptr[0..key_len])) {
                    // Same key - update value
                    slot.value = value;
                    return 1;
                }
            }
        }

        // Collision - linear probe
        idx = (idx + 1) % capacity;
        probes += 1;
    }

    // Map is full
    return 0;
}

/// Native map get - works with codegen-allocated layout
/// Returns value if found, MIN_INT if not found
export fn cot_native_map_get(map: ?[*]u8, key_ptr: [*]const u8, key_len: u64) i64 {
    const m = map orelse return std.math.minInt(i64);
    const header = getNativeHeader(m);
    const slots = getNativeSlots(m);
    const capacity = header.capacity;

    if (capacity == 0) return std.math.minInt(i64);

    const hash = fnvHash(key_ptr, key_len);
    var idx = hash % capacity;
    var probes: u64 = 0;

    while (probes < capacity) {
        const slot = &slots[idx];

        if (slot.meta == 0) {
            // Empty slot - key not found
            return std.math.minInt(i64);
        }

        if (slot.meta == 1 and slot.key_len == key_len) {
            const existing_key: [*]const u8 = @ptrFromInt(slot.key_ptr);
            if (std.mem.eql(u8, existing_key[0..key_len], key_ptr[0..key_len])) {
                return slot.value;
            }
        }

        // Continue probing (skip tombstones too)
        idx = (idx + 1) % capacity;
        probes += 1;
    }

    return std.math.minInt(i64);
}

/// Native map has - check if key exists
/// Returns 1 if found, 0 if not
export fn cot_native_map_has(map: ?[*]u8, key_ptr: [*]const u8, key_len: u64) i64 {
    const m = map orelse return 0;
    const header = getNativeHeader(m);
    const slots = getNativeSlots(m);
    const capacity = header.capacity;

    if (capacity == 0) return 0;

    const hash = fnvHash(key_ptr, key_len);
    var idx = hash % capacity;
    var probes: u64 = 0;

    while (probes < capacity) {
        const slot = &slots[idx];

        if (slot.meta == 0) {
            return 0; // Empty - not found
        }

        if (slot.meta == 1 and slot.key_len == key_len) {
            const existing_key: [*]const u8 = @ptrFromInt(slot.key_ptr);
            if (std.mem.eql(u8, existing_key[0..key_len], key_ptr[0..key_len])) {
                return 1;
            }
        }

        idx = (idx + 1) % capacity;
        probes += 1;
    }

    return 0;
}

/// Native map size - get number of entries
export fn cot_native_map_size(map: ?[*]u8) i64 {
    const m = map orelse return 0;
    const header = getNativeHeader(m);
    return @intCast(header.size);
}

/// Native map free - free map and all keys
export fn cot_native_map_free(map: ?[*]u8) void {
    const m = map orelse return;
    const header = getNativeHeader(m);
    const slots = getNativeSlots(m);
    const capacity = header.capacity;

    // Free all key strings
    var i: u64 = 0;
    while (i < capacity) : (i += 1) {
        if (slots[i].meta == 1) {
            const key_ptr: [*]u8 = @ptrFromInt(slots[i].key_ptr);
            const key_len = slots[i].key_len;
            std.heap.c_allocator.free(key_ptr[0..key_len]);
        }
    }

    // Free the map itself (was allocated via calloc)
    // Total size: 32 header + capacity * 32 slots
    const total_size = 32 + capacity * 32;
    std.heap.c_allocator.free(m[0..total_size]);
}

// ============================================================================
// Native Layout Tests
// ============================================================================

test "native map basic operations" {
    // Allocate map like codegen does
    const allocator = std.heap.c_allocator;
    const capacity: u64 = 64;
    const total_size: usize = 32 + @as(usize, capacity) * 32; // header + slots
    const map = allocator.alloc(u8, total_size) catch return error.OutOfMemory;
    @memset(map, 0);

    // Initialize header like codegen does
    const header: *NativeHeader = @ptrCast(@alignCast(map.ptr));
    header.capacity = capacity;
    header.size = 0;
    header.seed = 0xcbf29ce484222325;

    // Test basic operations
    const key = "hello";
    try std.testing.expectEqual(@as(i64, 0), cot_native_map_has(map.ptr, key.ptr, key.len));

    _ = cot_native_map_set(map.ptr, key.ptr, key.len, 42);
    try std.testing.expectEqual(@as(i64, 1), cot_native_map_has(map.ptr, key.ptr, key.len));
    try std.testing.expectEqual(@as(i64, 42), cot_native_map_get(map.ptr, key.ptr, key.len));
    try std.testing.expectEqual(@as(i64, 1), cot_native_map_size(map.ptr));

    // Update
    _ = cot_native_map_set(map.ptr, key.ptr, key.len, 100);
    try std.testing.expectEqual(@as(i64, 100), cot_native_map_get(map.ptr, key.ptr, key.len));
    try std.testing.expectEqual(@as(i64, 1), cot_native_map_size(map.ptr)); // Size unchanged

    // Free
    cot_native_map_free(map.ptr);
}

test "native map multiple entries" {
    const allocator = std.heap.c_allocator;
    const capacity: u64 = 64;
    const total_size: usize = 32 + @as(usize, capacity) * 32;
    const map = allocator.alloc(u8, total_size) catch return error.OutOfMemory;
    @memset(map, 0);

    const header: *NativeHeader = @ptrCast(@alignCast(map.ptr));
    header.capacity = capacity;

    const keys = [_][]const u8{ "one", "two", "three", "four", "five" };
    const values = [_]i64{ 1, 2, 3, 4, 5 };

    for (keys, values) |k, v| {
        _ = cot_native_map_set(map.ptr, k.ptr, k.len, v);
    }

    try std.testing.expectEqual(@as(i64, 5), cot_native_map_size(map.ptr));

    for (keys, values) |k, v| {
        try std.testing.expectEqual(v, cot_native_map_get(map.ptr, k.ptr, k.len));
    }

    cot_native_map_free(map.ptr);
}
