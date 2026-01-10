///! Cot runtime library.
///!
///! This is the root module that includes all runtime components.
///! Compiled cot programs link against this library for Map and List operations.
///!
///! The export functions in submodules are automatically included in the static library.

// Import submodules - their `export fn` declarations become symbols
const map = @import("map.zig");
const list = @import("list.zig");

// Reference the modules to ensure they're not optimized away
comptime {
    _ = map;
    _ = list;
}

test {
    // Run tests from all submodules
    _ = @import("map.zig");
    _ = @import("list.zig");
}
