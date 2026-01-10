# Cot 0.2 Implementation Guide

How each file maps Go's compiler design to Zig.

## Roadmap to Self-Hosting

### Phase 1: Working Zig Compiler (Current)

Build a complete compiler in Zig that can compile simple cot programs.

**Milestone 1.1: Core Pipeline** ✓ Complete
- [x] Scanner/lexer (scanner.zig)
- [x] Parser (parser.zig)
- [x] Type checker (check.zig)
- [x] IR generation (ir.zig)
- [x] SSA form (ssa.zig)
- [x] x86-64 codegen (codegen/x86_64.zig)
- [x] ARM64 codegen (codegen/aarch64.zig)
- [x] Object file generation (codegen/object.zig)
- [x] Debug infrastructure (debug.zig)

**Milestone 1.2: Working CLI** ✓ Complete
- [x] Driver (driver.zig) - orchestrate full pipeline
- [x] Linker integration - shell out to system linker (cc)
- [x] CLI arguments - `cot build file.cot`
- [x] Test with simple programs (parses and type-checks)

**Milestone 1.3: Language Completeness**
- [x] String handling and string literals in codegen
- [x] len() builtin for strings
- [x] String equality (==, !=) with constant folding
- [x] Function calls with arguments
- [x] If/else control flow in codegen
- [x] While loops in codegen
- [x] Struct support (definition, literal init, field access)
- [x] Array literals and constant indexing
- [x] Dynamic array indexing (runtime index) - ARM64 working, x86_64 has stack layout issues with large arrays
- [x] Slice support (compile-time) - arr[i:j] syntax, len() constant folding
- [x] Slice support (runtime) - ptr+len storage (16 bytes), len() on slice variables
- [x] Slice indexing (runtime) - s[i] access
- [x] Switch expressions - switch x { 1 => a, 2 => b, else => c }
- [x] Multi-value switch cases - `.a, .b, .c => x` (multiple patterns per arm)
- [x] For-in loops - `for x in arr { ... }` (arrays and slices)
- [x] Enum with backing type - `enum Color: i64 { red = 10, green = 20 }`
- [x] @intFromEnum builtin - `@intFromEnum(Color.green)` returns 20
- [x] @enumFromInt builtin - `@enumFromInt(Color, 20)` returns Color.green
- [x] Tagged union parsing - `union Result { ok: int, err: string }` (parse + type check only)
- [x] Tagged union codegen - construction (`Result.ok(42)`) and switch matching with payload capture (`switch r { .ok |val| => val }`)
- [ ] Standard library basics (print, memory)

**Automated Test Runner**

A test runner script (`run_tests.sh`) verifies all tests produce expected exit codes:
```bash
./run_tests.sh  # Runs all tests, reports pass/fail
```

**Unhandled SSA Op Detection**

Running with `--debug-codegen` will show warnings for any unhandled SSA operations:
```bash
./zig-out/bin/cot tests/test_file.cot --debug-codegen -o test
# Output: [WARN] Unhandled AArch64 SSA op: <op_name>
```

### Verified Test Results (January 2026)

**Test Counts:**
- 135+ Zig embedded tests (unit tests in source files)
- 41 binary tests (.cot test files)

**Both ARM64 and x86_64** - 41/41 tests pass (41 + 1 skip)

| Test File | Expected | ARM64 | x86_64 |
|-----------|----------|-------|--------|
| test_return.cot (return 42) | 42 | PASS | PASS |
| test_const.cot (return 42) | 42 | PASS | PASS |
| test_bool.cot (return true as int) | 1 | PASS | PASS |
| test_call.cot (function call) | 42 | PASS | PASS |
| test_len.cot (len("hello")) | 5 | PASS | PASS |
| test_len2.cot (len("hello world!")) | 12 | PASS | PASS |
| test_string.cot (string length) | 5 | PASS | PASS |
| test_struct.cot (struct field .x access) | 10 | PASS | PASS |
| test_struct2.cot (struct field .y access) | 20 | PASS | PASS |
| test_array.cot (arr[0]) | 10 | PASS | PASS |
| test_array2.cot (arr[1]) | 20 | PASS | PASS |
| test_array3.cot (arr[2]) | 30 | PASS | PASS |
| test_array_dyn.cot (arr[i] where i=1) | 20 | PASS | PASS |
| test_array_dyn2.cot (arr[i] where i=4, 5-elem) | 50 | PASS | PASS |
| test_array_dyn3.cot (arr[i] where i=1, 2-elem) | 20 | PASS | PASS |
| test_5elem.cot (5-element array) | 50 | PASS | PASS |
| test_slice.cot (create slice arr[1:3]) | 42 | PASS | PASS |
| test_slice_len.cot (len(s) where s=arr[1:4]) | 3 | PASS | PASS |
| test_slice_len2.cot (len(arr[1:4]) inline) | 3 | PASS | PASS |
| test_sub.cot (50 - 8) | 42 | PASS | PASS |
| test_mul.cot (6 * 7) | 42 | PASS | PASS |
| test_div.cot (84 / 2) | 42 | PASS | PASS |
| test_switch.cot (switch expression) | 42 | PASS | PASS |
| test_switch_multi.cot (multi-value switch cases) | 42 | PASS | PASS |
| test_slice_index.cot (s[i] access) | 30 | PASS | PASS |
| test_for_array.cot (for x in arr) | 60 | PASS | PASS |
| test_for_slice.cot (for x in slice) | 90 | PASS | PASS |
| test_union.cot (union construction) | 42 | PASS | PASS |
| test_union_switch.cot (switch with payload capture) | 42 | PASS | PASS |

**All tests pass** - conditionals, while loops, string comparisons, switch expressions, slice indexing, for-in loops, and tagged unions with payload capture now working.

### Testing Commands

```bash
# Run ARM64 tests (native macOS)
./run_tests.sh

# Run x86_64 tests (Docker)
./docker_test.sh

# Build x86_64 and run all tests (builds Docker image if needed)
./docker_test.sh --build-image
```

**Docker Setup for x86_64 Testing**

The project includes a pre-configured Docker setup for x86_64 testing:
- `Dockerfile.x86_64` - Debian-based image with gcc, libc6-dev, binutils pre-installed
- `run_tests_x86_64.sh` - Test runner script for use inside Docker container
- `docker_test.sh` - Convenience script that builds cot, manages Docker image, and runs tests

```bash
# Single test on ARM64 (native macOS)
zig build && ./zig-out/bin/cot tests/test_file.cot -o test && ./test; echo "Exit: $?"

# Single test on x86_64 (no Docker needed - zig cc cross-links!)
zig build && ./zig-out/bin/cot tests/test_file.cot -o ignored && \
  zig cc test_file.o -o test -target x86_64-linux-gnu && ./test; echo "Exit: $?"

# Or still use Docker if preferred
zig build -Dtarget=x86_64-linux-gnu
docker run --platform linux/amd64 -v $(pwd):/cot -w /cot cot-x86_64 \
  sh -c "./zig-out/bin/cot tests/test_file.cot -o ignored; zig cc -o test test_file.o && ./test; echo Exit: \$?"
```

**Note**: We use `zig cc` as the linker instead of system `gcc`/`ld`. Benefits:
- Cross-platform: works on macOS, Linux, Windows
- Cross-compilation: link for any target from any host
- No additional dependencies: Zig bundles LLD and libc
- Consistent behavior across all platforms

### Phase 2: Bootstrap Preparation ✓ Complete

Write cot source files that will form the self-hosted compiler.

**Milestone 2.1: Core Data Structures** ✓ Complete
- [x] token.cot - Token enum and keyword table
- [x] source.cot - Source text handling
- [x] ast.cot - AST node types

**Milestone 2.2: Frontend** ✓ Complete
- [x] scanner.cot - Lexer
- [x] parser.cot - Parser
- [x] errors.cot - Error handling

**Milestone 2.3: Middle-end** ✓ Complete
- [x] types.cot - Type system
- [x] checker.cot - Type checker (maps to check.zig)
- [x] ir.cot - IR generation

### Phase 3: Self-Hosting

Use the Zig compiler to compile the cot compiler written in cot.

**Milestone 3.1: Compile cot with Zig**
- [ ] Compile token.cot, scanner.cot, etc. to object files
- [ ] Link into working cot-stage1 executable
- [ ] Verify cot-stage1 can parse itself

**Milestone 3.2: Full Bootstrap**
- [ ] cot-stage1 compiles cot source → cot-stage2
- [ ] cot-stage2 compiles cot source → cot-stage3
- [ ] Verify stage2 == stage3 (bootstrap complete)

### Phase 4: Post-Bootstrap (Future)

Features that can wait until after self-hosting.

- [ ] Optimization passes (constant folding, DCE, etc.)
- [ ] ARC memory management
- [ ] Traits/interfaces
- [ ] Generics
- [ ] Package system
- [ ] REPL
- [ ] LSP server

---

## Phase 5: Standard Library via Zig FFI

After self-hosting, Cot needs a standard library (HTTP, crypto, JSON, file I/O, etc.). Rather than rewriting everything from scratch, we leverage Zig's battle-tested `std` library via C ABI exports.

### Design Principles

1. **Zig for the hard stuff** - HTTP, crypto, JSON parsing, async I/O
2. **Pure Cot for everything else** - Data structures, algorithms, business logic
3. **Thin FFI layer** - Runtime only wraps what truly benefits from Zig's std
4. **Explicit memory ownership** - Clear rules for who allocates/frees

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Cot Application                          │
│   import "std/http"                                          │
│   const resp = http.get("https://example.com")?             │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ calls Cot wrapper (high-level API)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     std/http.cot                             │
│   (Pure Cot - error handling, Result types, ergonomics)     │
│                                                              │
│   pub fn get(url: string) Result(Response, HttpError)       │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ calls extern fn (C ABI)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    libcot_runtime.a                          │
│   (Zig implementation, exported via C ABI)                   │
│                                                              │
│   export fn cot_http_get(...) callconv(.C) i64              │
│   export fn cot_file_read_alloc(...) callconv(.C) i64       │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ uses internally
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Zig std library                          │
│   std.http.Client, std.json, std.fs, std.crypto             │
└─────────────────────────────────────────────────────────────┘
```

### Memory Ownership Conventions

**Rule 1: Caller allocates output buffers**
```cot
// Caller provides buffer, runtime fills it
extern fn cot_file_read(path: *u8, out_buf: *u8, buf_len: i64) i64
```

**Rule 2: Runtime owns opaque handles**
```cot
// Runtime allocates, caller must free with paired function
extern fn cot_json_parse(data: *u8, len: i64) ?*JsonHandle
extern fn cot_json_free(handle: *JsonHandle) void
```

**Rule 3: Runtime-allocated data uses explicit alloc functions**
```cot
// For large/unknown-size data, runtime allocates
extern fn cot_file_read_alloc(path: *u8, out_ptr: **u8, out_len: *i64) i64
extern fn cot_free(ptr: *u8, len: i64) void
```

**Rule 4: Strings are always ptr+len pairs (no null termination assumption)**
```cot
// Runtime receives ptr+len, not null-terminated strings
extern fn cot_http_post(url: *u8, url_len: i64, body: *u8, body_len: i64, ...) i64
```

### Error Handling Strategy

**Runtime level:** Return error codes (negative values) or null pointers
```zig
// In cot_runtime.zig
export fn cot_file_read(...) callconv(.C) i64 {
    // Returns: >= 0 for bytes read, negative for error code
    //   -1 = file not found
    //   -2 = permission denied
    //   -3 = I/O error
}
```

**Cot wrapper level:** Convert to Result/Error types
```cot
// In std/fs.cot
pub const FsError = enum {
    not_found,
    permission_denied,
    io_error,
    unknown,
}

pub fn read_file(path: string) Result(string, FsError) {
    var buf: [1048576]u8 = undefined
    const result = cot_file_read(path.ptr, &buf, 1048576)

    if (result == -1) return .{ .err = .not_found }
    if (result == -2) return .{ .err = .permission_denied }
    if (result < 0) return .{ .err = .io_error }

    return .{ .ok = string.from_bytes(buf[0..result]) }
}
```

### Step 1: extern fn Syntax

All `extern fn` declarations use C calling convention implicitly:

```cot
// External function declaration (no body, C ABI assumed)
extern fn cot_http_get(url: *u8, url_len: i64, out: *u8, out_len: i64) i64
extern fn cot_json_parse(data: *u8, len: i64) ?*JsonHandle
extern fn cot_sha256(data: *u8, len: i64, out: *u8) void

// Usage - called like any other function
fn example() {
    var buf: [4096]u8 = undefined
    const len = cot_http_get("https://api.example.com".ptr, 23, &buf, 4096)
}
```

**Compiler implementation:**
1. **Parser:** `extern fn name(params) return_type` (no body)
2. **Type checker:** Validate parameter types are FFI-compatible (primitives, pointers)
3. **Codegen:** Emit external symbol reference (relocation, no code)
4. **Linker:** Resolve against libcot_runtime.a

### Step 2: Zig Runtime Library

**File:** `runtime/cot_runtime.zig`

```zig
const std = @import("std");

const allocator = std.heap.c_allocator;

// ============================================================
// Error Codes (documented, stable across versions)
// ============================================================

pub const ERR_NOT_FOUND: i64 = -1;
pub const ERR_PERMISSION: i64 = -2;
pub const ERR_IO: i64 = -3;
pub const ERR_INVALID: i64 = -4;
pub const ERR_TIMEOUT: i64 = -5;
pub const ERR_NO_MEMORY: i64 = -6;
pub const ERR_BUFFER_TOO_SMALL: i64 = -7;

// ============================================================
// File I/O
// ============================================================

/// Read file into caller-provided buffer
/// Returns: bytes read (>= 0), or negative error code
export fn cot_file_read(
    path_ptr: [*]const u8,
    path_len: usize,
    out_buf: [*]u8,
    buf_len: usize,
) callconv(.C) i64 {
    const path = path_ptr[0..path_len];

    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        return switch (err) {
            error.FileNotFound => ERR_NOT_FOUND,
            error.AccessDenied => ERR_PERMISSION,
            else => ERR_IO,
        };
    };
    defer file.close();

    const bytes_read = file.read(out_buf[0..buf_len]) catch return ERR_IO;
    return @intCast(bytes_read);
}

/// Read entire file, runtime allocates buffer
/// Caller must free with cot_free(out_ptr, out_len)
export fn cot_file_read_alloc(
    path_ptr: [*]const u8,
    path_len: usize,
    out_ptr: *[*]u8,
    out_len: *usize,
) callconv(.C) i64 {
    const path = path_ptr[0..path_len];

    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        return switch (err) {
            error.FileNotFound => ERR_NOT_FOUND,
            error.AccessDenied => ERR_PERMISSION,
            else => ERR_IO,
        };
    };
    defer file.close();

    const content = file.readToEndAlloc(allocator, 1024 * 1024 * 100) catch return ERR_IO;
    out_ptr.* = content.ptr;
    out_len.* = content.len;
    return @intCast(content.len);
}

export fn cot_file_write(
    path_ptr: [*]const u8,
    path_len: usize,
    data_ptr: [*]const u8,
    data_len: usize,
) callconv(.C) i64 {
    const path = path_ptr[0..path_len];
    const data = data_ptr[0..data_len];

    const file = std.fs.cwd().createFile(path, .{}) catch |err| {
        return switch (err) {
            error.AccessDenied => ERR_PERMISSION,
            else => ERR_IO,
        };
    };
    defer file.close();

    file.writeAll(data) catch return ERR_IO;
    return @intCast(data_len);
}

export fn cot_file_exists(
    path_ptr: [*]const u8,
    path_len: usize,
) callconv(.C) bool {
    const path = path_ptr[0..path_len];
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

// ============================================================
// HTTP Client
// ============================================================

export fn cot_http_get(
    url_ptr: [*]const u8,
    url_len: usize,
    out_buf: [*]u8,
    buf_len: usize,
) callconv(.C) i64 {
    const url = url_ptr[0..url_len];

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var response = client.fetch(allocator, .{
        .url = url,
    }) catch |err| {
        return switch (err) {
            error.ConnectionRefused => ERR_IO,
            error.Timeout => ERR_TIMEOUT,
            else => ERR_IO,
        };
    };
    defer response.deinit();

    const body = response.body orelse return 0;
    if (body.len > buf_len) return ERR_BUFFER_TOO_SMALL;

    @memcpy(out_buf[0..body.len], body);
    return @intCast(body.len);
}

/// HTTP GET with runtime-allocated response
export fn cot_http_get_alloc(
    url_ptr: [*]const u8,
    url_len: usize,
    out_ptr: *[*]u8,
    out_len: *usize,
    out_status: *i32,
) callconv(.C) i64 {
    const url = url_ptr[0..url_len];

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var response = client.fetch(allocator, .{
        .url = url,
    }) catch return ERR_IO;
    // Don't defer deinit - we're giving body ownership to caller

    out_status.* = @intFromEnum(response.status);

    if (response.body) |body| {
        // Dupe the body so we can deinit the response
        const owned = allocator.dupe(u8, body) catch return ERR_NO_MEMORY;
        out_ptr.* = owned.ptr;
        out_len.* = owned.len;
        response.deinit();
        return @intCast(owned.len);
    }

    response.deinit();
    out_ptr.* = undefined;
    out_len.* = 0;
    return 0;
}

// ============================================================
// JSON (Opaque Handle Pattern)
// ============================================================

pub const JsonHandle = opaque {};

export fn cot_json_parse(
    json_ptr: [*]const u8,
    json_len: usize,
) callconv(.C) ?*JsonHandle {
    const json_str = json_ptr[0..json_len];
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        json_str,
        .{},
    ) catch return null;

    const result = allocator.create(std.json.Parsed(std.json.Value)) catch return null;
    result.* = parsed;
    return @ptrCast(result);
}

export fn cot_json_free(handle: ?*JsonHandle) callconv(.C) void {
    if (handle) |h| {
        const parsed: *std.json.Parsed(std.json.Value) = @ptrCast(@alignCast(h));
        parsed.deinit();
        allocator.destroy(parsed);
    }
}

export fn cot_json_get_string(
    handle: *JsonHandle,
    key_ptr: [*]const u8,
    key_len: usize,
    out_buf: [*]u8,
    buf_len: usize,
) callconv(.C) i64 {
    const parsed: *std.json.Parsed(std.json.Value) = @ptrCast(@alignCast(handle));
    const key = key_ptr[0..key_len];

    if (parsed.value != .object) return ERR_INVALID;
    const val = parsed.value.object.get(key) orelse return ERR_NOT_FOUND;
    if (val != .string) return ERR_INVALID;

    const str = val.string;
    if (str.len > buf_len) return ERR_BUFFER_TOO_SMALL;

    @memcpy(out_buf[0..str.len], str);
    return @intCast(str.len);
}

// ============================================================
// Crypto
// ============================================================

export fn cot_sha256(
    data_ptr: [*]const u8,
    data_len: usize,
    out_hash: [*]u8,  // Must be 32 bytes
) callconv(.C) void {
    const data = data_ptr[0..data_len];
    const hash = std.crypto.hash.sha2.Sha256.hash(data, .{});
    @memcpy(out_hash[0..32], &hash);
}

// ============================================================
// Memory Management
// ============================================================

export fn cot_alloc(size: usize) callconv(.C) ?[*]u8 {
    const mem = allocator.alloc(u8, size) catch return null;
    return mem.ptr;
}

export fn cot_free(ptr: ?[*]u8, size: usize) callconv(.C) void {
    if (ptr) |p| {
        allocator.free(p[0..size]);
    }
}

export fn cot_realloc(
    ptr: ?[*]u8,
    old_size: usize,
    new_size: usize,
) callconv(.C) ?[*]u8 {
    if (ptr) |p| {
        const new_mem = allocator.realloc(p[0..old_size], new_size) catch return null;
        return new_mem.ptr;
    }
    return cot_alloc(new_size);
}

// ============================================================
// Print (stdout)
// ============================================================

export fn cot_print(ptr: [*]const u8, len: usize) callconv(.C) void {
    const stdout = std.io.getStdOut().writer();
    stdout.writeAll(ptr[0..len]) catch {};
}

export fn cot_println(ptr: [*]const u8, len: usize) callconv(.C) void {
    const stdout = std.io.getStdOut().writer();
    stdout.writeAll(ptr[0..len]) catch {};
    stdout.writeByte('\n') catch {};
}
```

### Step 3: Cot Standard Library Wrappers

**File:** `std/error.cot`

```cot
// Common error types used across std library

pub const IoError = enum {
    not_found,
    permission_denied,
    io_error,
    timeout,
    buffer_too_small,
    unknown,
}

// Generic Result type (until we have generics, use specific versions)
pub struct ResultString {
    ok: ?string,
    err: ?IoError,

    pub fn is_ok(self: ResultString) bool {
        return self.ok != null
    }

    pub fn unwrap(self: ResultString) string {
        return self.ok.?
    }
}
```

**File:** `std/fs.cot`

```cot
import "std/error"

extern fn cot_file_read(path: *u8, path_len: i64, out: *u8, out_len: i64) i64
extern fn cot_file_read_alloc(path: *u8, path_len: i64, out_ptr: **u8, out_len: *i64) i64
extern fn cot_file_write(path: *u8, path_len: i64, data: *u8, data_len: i64) i64
extern fn cot_file_exists(path: *u8, path_len: i64) bool
extern fn cot_free(ptr: *u8, len: i64) void

fn error_from_code(code: i64) IoError {
    if (code == -1) return .not_found
    if (code == -2) return .permission_denied
    if (code == -7) return .buffer_too_small
    return .io_error
}

/// Read file contents (up to 1MB)
pub fn read_file(path: string) ResultString {
    var buf: [1048576]u8 = undefined
    const result = cot_file_read(path.ptr, path.len, &buf, 1048576)

    if (result < 0) {
        return .{ .ok = null, .err = error_from_code(result) }
    }

    return .{ .ok = string.from_bytes(buf[0..result]), .err = null }
}

/// Read file of any size (runtime allocates)
pub fn read_file_alloc(path: string) ResultString {
    var ptr: *u8 = undefined
    var len: i64 = 0
    const result = cot_file_read_alloc(path.ptr, path.len, &ptr, &len)

    if (result < 0) {
        return .{ .ok = null, .err = error_from_code(result) }
    }

    // Note: caller is responsible for freeing via string.deinit()
    return .{ .ok = string.from_owned(ptr, len), .err = null }
}

pub fn write_file(path: string, content: string) ?IoError {
    const result = cot_file_write(path.ptr, path.len, content.ptr, content.len)
    if (result < 0) return error_from_code(result)
    return null
}

pub fn exists(path: string) bool {
    return cot_file_exists(path.ptr, path.len)
}
```

**File:** `std/http.cot`

```cot
import "std/error"

extern fn cot_http_get(url: *u8, url_len: i64, out: *u8, out_len: i64) i64
extern fn cot_http_get_alloc(url: *u8, url_len: i64, out_ptr: **u8, out_len: *i64, status: *i32) i64

pub struct Response {
    status: i32,
    body: string,
}

pub struct ResultResponse {
    ok: ?Response,
    err: ?IoError,
}

/// HTTP GET (up to 1MB response)
pub fn get(url: string) ResultResponse {
    var buf: [1048576]u8 = undefined
    const result = cot_http_get(url.ptr, url.len, &buf, 1048576)

    if (result < 0) {
        return .{ .ok = null, .err = error_from_code(result) }
    }

    return .{
        .ok = Response{ .status = 200, .body = string.from_bytes(buf[0..result]) },
        .err = null
    }
}

/// HTTP GET (any size response, runtime allocates)
pub fn get_alloc(url: string) ResultResponse {
    var ptr: *u8 = undefined
    var len: i64 = 0
    var status: i32 = 0
    const result = cot_http_get_alloc(url.ptr, url.len, &ptr, &len, &status)

    if (result < 0) {
        return .{ .ok = null, .err = error_from_code(result) }
    }

    return .{
        .ok = Response{ .status = status, .body = string.from_owned(ptr, len) },
        .err = null
    }
}

fn error_from_code(code: i64) IoError {
    if (code == -5) return .timeout
    if (code == -7) return .buffer_too_small
    return .io_error
}
```

### Step 4: Compiler Integration

**Auto-linking with opt-out:**

```bash
# Normal compilation - auto-links runtime
cot build app.cot -o app

# Disable auto-linking (for debugging or custom runtime)
cot build app.cot -o app --no-runtime

# Explicit runtime path
cot build app.cot -o app --runtime=/path/to/libcot_runtime.a
```

**Implementation in driver.zig:**

```zig
fn link(self: *Driver, objects: []const []const u8, output: []const u8) !void {
    var args = std.ArrayList([]const u8).init(self.allocator);
    defer args.deinit();

    try args.append("cc");
    for (objects) |obj| {
        try args.append(obj);
    }

    // Auto-link runtime unless --no-runtime specified
    if (!self.options.no_runtime) {
        const runtime_path = self.options.runtime_path orelse blk: {
            const cot_home = std.posix.getenv("COT_HOME") orelse "/usr/local/cot";
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{s}/lib/libcot_runtime.a",
                .{cot_home}
            );
        };
        try args.append(runtime_path);
    }

    try args.append("-o");
    try args.append(output);

    var child = std.process.Child.init(args.items, self.allocator);
    _ = try child.spawnAndWait();
}
```

### Step 5: Distribution Structure

```
cot/
├── bin/
│   └── cot                      # The compiler executable
├── lib/
│   └── libcot_runtime.a         # Zig runtime (auto-linked)
└── std/
    ├── error.cot                # Common error types
    ├── http.cot                 # HTTP client wrappers
    ├── fs.cot                   # File system wrappers
    ├── json.cot                 # JSON parsing wrappers
    ├── crypto.cot               # Crypto wrappers
    └── ...
```

### What Goes in Zig vs Pure Cot

| Category | Zig Runtime | Pure Cot |
|----------|-------------|----------|
| HTTP client/server | ✓ (std.http) | Wrappers + Response types |
| JSON parsing | ✓ (std.json) | Wrappers + typed access |
| File I/O | ✓ (std.fs) | Wrappers + Result types |
| Crypto | ✓ (std.crypto) | Wrappers only |
| Memory allocation | ✓ (allocator) | Uses runtime |
| String operations | concat only | Most logic (split, trim, etc.) |
| Data structures | - | ✓ (List, Map, Set, etc.) |
| Math | - | ✓ (pure computation) |
| Error types | codes only | ✓ (enums, Result types) |
| Business logic | - | ✓ (always) |

### Timeline

| Task | Effort | Dependencies |
|------|--------|--------------|
| `extern fn` in parser | 0.5 days | - |
| `extern fn` in type checker | 0.5 days | Parser |
| External symbol codegen | 0.5 days | Type checker |
| Auto-link + --no-runtime | 0.5 days | Codegen |
| libcot_runtime.a (file, print) | 1 day | - |
| libcot_runtime.a (http, json, crypto) | 2 days | - |
| std/ Cot wrappers + Result types | 2 days | Runtime |
| **Total** | ~1 week | After self-hosting |

---

## Phase 6: Windows Support

Windows support is important for broader adoption. The good news: x86_64 instruction encoding is already complete and identical on Windows. Only the packaging and calling convention differ.

### What's Reusable (100%)

| Component | Notes |
|-----------|-------|
| x86_64 instruction encoding | Same bytes on Windows and Linux |
| Register allocation | Architecture-level, OS-independent |
| SSA/IR/frontend | Completely OS-independent |

### New Work Required

#### 1. PE/COFF Object Format

Windows uses PE/COFF instead of ELF (Linux) or Mach-O (macOS):

```
codegen/object.zig:
├── writeMachO()   ← macOS (done)
├── writeELF()     ← Linux (done)
└── writePE()      ← Windows (new)
```

**Effort:** 1-2 days

PE/COFF structure:
- DOS header (legacy stub)
- PE signature
- COFF file header
- Optional header (PE32+)
- Section headers (.text, .data, .rdata)
- Section data
- Symbol table
- Relocation entries

#### 2. Win64 Calling Convention

Windows x64 uses different parameter registers than SystemV (Linux/macOS):

| Parameter | SystemV (Unix) | Win64 (Windows) |
|-----------|----------------|-----------------|
| 1st | rdi | rcx |
| 2nd | rsi | rdx |
| 3rd | rdx | r8 |
| 4th | rcx | r9 |
| 5th+ | stack | stack |
| Shadow space | None | 32 bytes required |
| Callee-saved | rbx, r12-r15, rbp | rbx, rsi, rdi, r12-r15, rbp |

**Implementation:**

```zig
// In codegen/x86_64.zig or codegen/callconv.zig

pub const Win64 = CallConv{
    .param_regs = &.{ .rcx, .rdx, .r8, .r9 },
    .float_param_regs = &.{ .xmm0, .xmm1, .xmm2, .xmm3 },
    .callee_saved = &.{ .rbx, .rsi, .rdi, .r12, .r13, .r14, .r15, .rbp },
    .return_reg = .rax,
    .shadow_space = 32,  // Must reserve 32 bytes for callee
    .stack_align = 16,
};

// Prologue needs shadow space:
// sub rsp, 32 + locals + alignment
```

**Effort:** 0.5-1 day

#### 3. Runtime / System Integration

**Option A: Link against UCRT (Recommended)**

Use Microsoft's Universal C Runtime. Just call standard C functions:
- `printf` / `puts` for output
- `malloc` / `free` for memory
- `exit` for program termination

```zig
// Linker flags:
// link.exe app.obj /OUT:app.exe msvcrt.lib
```

**Option B: Direct Windows API**

Call Windows APIs directly via kernel32.dll imports:
- `WriteConsoleA` for output
- `HeapAlloc` / `HeapFree` for memory
- `ExitProcess` for termination

```zig
// Requires import table in PE file
// More complex but no CRT dependency
```

**Effort:** 0.5-1 day

#### 4. Linker Integration

Use `zig cc` for consistent cross-platform linking (same approach as Linux/macOS):

```zig
fn link(objects: []const []const u8, output: []const u8, target: Target) !void {
    var args = std.ArrayList([]const u8).init(allocator);
    try args.append("zig");
    try args.append("cc");

    for (objects) |obj| try args.append(obj);

    try args.append("-o");
    try args.append(output);

    // Target specification
    switch (target.os) {
        .macos => try args.append("-target"),
                  try args.append("aarch64-macos"),  // or x86_64-macos
        .linux => try args.append("-target"),
                  try args.append("x86_64-linux-gnu"),
        .windows => try args.append("-target"),
                    try args.append("x86_64-windows"),
    }

    var child = std.process.Child.init(args.items, allocator);
    _ = try child.spawnAndWait();
}
```

**Benefits of zig cc for Windows:**
- Cross-compile from macOS/Linux to Windows (no Windows machine needed for development)
- Bundles LLD and mingw-w64 libc
- No need to install Visual Studio or Windows SDK
- Same command works on all host platforms

**Alternative: Native link.exe** (if targeting MSVC ABI specifically):
```bash
link.exe app.obj /OUT:app.exe /SUBSYSTEM:CONSOLE kernel32.lib msvcrt.lib
```

**Effort:** 0.5 day

### Cross-Compilation Support

Once PE/COFF is implemented, cross-compilation from macOS to Windows becomes possible:

```bash
# On macOS, produce Windows executable:
cot build app.cot --target=x86_64-windows -o app.exe

# The .exe can be copied to Windows and run directly
```

This requires:
1. PE/COFF writer (no Windows machine needed)
2. Win64 calling convention
3. Either: embed minimal CRT, or require user has Windows SDK

### Testing Strategy

**Option A: Windows VM/Machine**
- Most reliable
- Full integration testing
- Requires Windows license

**Option B: Wine on Linux/macOS**
- Can run simple Windows executables
- Free, no license needed
- May have compatibility issues

**Option C: CI with GitHub Actions**
- Windows runners available
- Automated testing on push
- Free for open source

### Recommended Implementation Order

1. **PE/COFF writer** - Can develop/test on macOS using hex dumps
2. **Win64 calling convention** - Modify existing x86_64 backend
3. **Linker integration** - Use lld-link for cross-platform
4. **Runtime stubs** - Minimal printf/exit via UCRT
5. **Full testing** - VM or CI

### Timeline Summary

| Task | Effort |
|------|--------|
| PE/COFF object writer | 1-2 days |
| Win64 calling convention | 0.5-1 day |
| Runtime (print, exit) | 0.5-1 day |
| Linker integration | 0.5 day |
| Testing/debugging | 1-2 days |
| **Total** | **3-5 days** |

### When to Implement

**Recommended: After self-hosting**

- Write PE/COFF support in Cot, not Zig
- Use Zig implementation as reference
- Iterate faster in self-hosted compiler
- The Zig x86_64 code serves as documentation

**Alternative: Before self-hosting**

- If Windows users are blocked
- Adds ~3-5 days to bootstrap timeline
- Work would need to be redone in Cot anyway

---

## Current Status

```
cot/
  build.zig       ✓ Project configuration
  src/
    main.zig      ✓ Entry point
    token.zig     ✓ Token definitions (4 tests passing)
    source.zig    ✓ Source text handling (4 tests passing)
    scanner.zig   ✓ Lexer (6 tests passing)
    errors.zig    ✓ Error handling (4 tests passing)
    ast.zig       ✓ AST nodes (4 tests passing)
    parser.zig    ✓ Parser (7 tests passing)
    types.zig     ✓ Type representation (6 tests passing)
    check.zig     ✓ Type checker (6 tests passing)
    ir.zig        ✓ Intermediate representation (6 tests passing)
    ssa.zig       ✓ SSA form (6 tests passing)
    debug.zig     ✓ Debug/trace infrastructure (3 tests passing)
    driver.zig    ✓ Compilation driver (3 tests passing)
    codegen/
      backend.zig   ✓ Backend interface & storage (3 tests passing)
      x86_64.zig    ✓ x86-64 assembler (7 tests passing)
      aarch64.zig   ✓ ARM64 assembler (5 tests passing)
      object.zig    ✓ ELF/Mach-O generation (5 tests passing)

    # Bootstrap wireframes (.cot files for self-hosting)
    token.cot     ✓ Token definitions (wireframe)
    source.cot    ✓ Source text handling (wireframe)
    ast.cot       ✓ AST node types (wireframe)
    scanner.cot   ✓ Lexer (wireframe)
    parser.cot    ✓ Parser (wireframe)
    errors.cot    ✓ Error handling (wireframe)
    types.cot     ✓ Type system (wireframe)
    checker.cot   ✓ Type checker (wireframe)
    ir.cot        ✓ IR generation (wireframe)
```

## File Descriptions

### build.zig

**Purpose:** Zig build configuration.

**Commands:**
- `zig build` - compile the compiler
- `zig build run -- file.cot` - run compiler on a file
- `zig build test` - run all tests

---

### src/main.zig

**Purpose:** Compiler entry point. Parses command-line args, orchestrates compilation.

**Go equivalent:** `cmd/compile/main.go`

---

### src/token.zig (next)

**Purpose:** Defines all tokens in the language.

**Go equivalent:** `cmd/compile/internal/syntax/tokens.go`

**What it contains:**
- Token enum (keywords, operators, literals, delimiters)
- Operator precedence levels
- Keyword lookup table

**Key pattern from Go:**
```go
// Go uses iota for sequential token values
const (
    _EOF token = iota
    _Name
    _Literal
    // ...
)
```

**Zig equivalent:**
```zig
// Zig uses enum with explicit values
pub const Token = enum(u8) {
    eof,
    identifier,
    literal,
    // ...
};
```

---

### src/source.zig

**Purpose:** Manages source text, tracks positions for error messages.

**Go equivalent:** `cmd/compile/internal/syntax/source.go`, `cmd/internal/src/pos.go`

**What it contains:**
- Source struct (holds file content)
- Position tracking (line, column)
- Span for error ranges

**Key pattern from Go:**
Go uses `src.XPos` which is a compact position encoding. We'll use a simpler struct initially.

---

### src/scanner.zig

**Purpose:** Lexer - converts source text into tokens.

**Go equivalent:** `cmd/compile/internal/syntax/scanner.go`

**What it contains:**
- Scanner struct with source and position
- `next()` function to advance and return token
- Character classification helpers
- String/number literal parsing

**Key pattern from Go:**
```go
func (s *scanner) next() {
    // skip whitespace
    // identify token type
    // consume token characters
}
```

---

### src/errors.zig

**Purpose:** Error handling infrastructure for consistent error reporting.

**Go equivalent:** Error handling patterns from `cmd/compile/internal/syntax/syntax.go` and `parser.go`

**What it contains:**
- Error struct with span, message, and optional error code
- ErrorCode enum for categorized errors (scanner: 1xx, parser: 2xx, type: 3xx)
- ErrorHandler callback type for external error handling
- ErrorReporter struct for collecting and displaying errors
- Trace mode flag for debug output

**Key pattern from Go:**
```go
// Go's simple error struct
type Error struct {
    Pos Pos
    Msg string
}

// ErrorHandler callback
type ErrorHandler func(err error)
```

**Zig equivalent:**
```zig
pub const Error = struct {
    span: Span,
    msg: []const u8,
    code: ?ErrorCode = null,
};

pub const ErrorHandler = *const fn (err: Error) void;

pub const ErrorReporter = struct {
    src: *Source,
    handler: ?ErrorHandler,
    first: ?Error,
    count: u32,
    // ...
};
```

---

### src/ast.zig

**Purpose:** Defines all AST node types.

**Go equivalent:** `cmd/compile/internal/syntax/nodes.go`

**What it contains:**
- `NodeIndex` (u32) for referencing nodes in the pool
- `Decl` union (fn_decl, var_decl, const_decl, struct_decl, enum_decl)
- `Expr` union (identifier, literal, binary, unary, call, index, field_access, etc.)
- `Stmt` union (expr_stmt, return_stmt, var_stmt, assign_stmt, if_stmt, while_stmt, for_stmt)
- `TypeExpr` for type expressions (named, pointer, optional, slice, array)
- `Ast` struct for arena-based storage with addNode/getNode/getExpr/getStmt/getDecl

**Key pattern from Go:**
Go uses interface embedding with `node` base struct. Zig uses tagged unions.

```zig
// Zig pattern:
pub const Expr = union(enum) {
    identifier: Identifier,
    literal: Literal,
    binary: Binary,
    // ...
};

pub const Ast = struct {
    nodes: std.ArrayList(Node),
    pub fn addNode(self: *Ast, node: Node) !NodeIndex { ... }
    pub fn getNode(self: *const Ast, idx: NodeIndex) Node { ... }
};
```

---

### src/parser.zig

**Purpose:** Parses tokens into AST.

**Go equivalent:** `cmd/compile/internal/syntax/parser.go`

**What it contains:**
- Parser struct with scanner, current token, AST, and error reporter
- `parseFile()` - parses complete source file into declarations
- `parseDecl()` - function, var, const, struct declarations
- `parseExpr()` / `parseBinaryExpr()` - precedence climbing for expressions
- `parseStmt()` - statements (return, if, while, for, assignment)
- Error recovery via error reporting without crashing

**Key pattern from Go:**
Go's parser uses recursive descent with precedence levels for binary expressions.

```zig
// Precedence climbing (from Go's binaryExpr)
fn parseBinaryExpr(self: *Parser, min_prec: u8) ParseError!?NodeIndex {
    var left = try self.parseUnaryExpr() orelse return null;
    while (true) {
        const prec = token.binaryPrecedence(self.tok.tok);
        if (@intFromEnum(prec) <= min_prec) break;
        // ... parse right operand with higher precedence
    }
    return left;
}
```

**Declarations supported:**
- `fn name(params) type { body }`
- `var/let name: type = value`
- `const name: type = value`
- `struct Name { fields }`

**Statements supported:**
- `return value`
- `if cond { } else { }`
- `while cond { }`
- `for item in iter { }`
- `break`, `continue`
- Expression statements and assignments

---

### src/types.zig

**Purpose:** Type representation and type registry.

**Go equivalent:** `cmd/compile/internal/types2/basic.go`, `pointer.go`, `slice.go`, `struct.go`

**What it contains:**
- `BasicKind` enum for primitive types (i8-i64, u8-u64, f32, f64, bool, string, void)
- `AlphaType` / `DecimalType` for DBL-compatible fixed types
- `PointerType`, `OptionalType`, `SliceType`, `ArrayType` for composite types
- `StructType`, `FuncType`, `NamedType` for complex types
- `Type` tagged union containing all type variants
- `TypeRegistry` for type interning with pre-registered basic types

**Key pattern from Go:**
Go uses separate struct types for each kind, we use a tagged union.

```zig
// Type indices for fast comparison
pub const TypeIndex = u32;

// Pre-registered basic types
pub const TypeRegistry = struct {
    pub const BOOL: TypeIndex = 1;
    pub const INT: TypeIndex = 5;  // i64
    pub const STRING: TypeIndex = 12;
    // ...
};

// Type aliases (cot's friendly names)
pub const INT = I64;    // int = i64
pub const FLOAT = F64;  // float = f64
pub const BYTE = U8;    // byte = u8
```

**DBL-compatible fixed types:**
- `alpha(N)` - fixed-length string (like DBL's a30)
- `decimal(N)` - fixed-point integer (like DBL's d10)
- `decimal(N,P)` - fixed-point with scale (like DBL's d8.2)

---

## Design Principles (from Go)

1. **Dense token IDs** - Token enum values are sequential, enabling array lookups.

2. **Position tracking** - Every token carries its source position for error messages.

3. **Precedence climbing** - Binary expression parsing uses precedence levels, not separate functions per level.

4. **No separate lexer pass** - Parser calls scanner on demand, not tokenizing entire file first.

5. **Simple error recovery** - On error, skip to synchronization point (`;`, `}`, etc.).

---

### src/check.zig

**Purpose:** Type checker - validates AST and resolves types.

**Go equivalent:** `cmd/compile/internal/types2/` (checker.go, resolver.go, decl.go, expr.go, stmt.go)

**What it contains:**
- `Checker` struct with type registry, current scope, error reporter
- `Scope` struct for lexical scoping (nested symbol tables)
- `Symbol` for variables, functions, types in scope
- `checkFile()` - type check all declarations
- `checkDecl()` - validate function signatures, struct fields
- `checkExpr()` - infer/check expression types, return TypeIndex
- `checkStmt()` - validate statements, check return types match

**Key responsibilities:**
1. **Name resolution** - resolve identifiers to their declarations
2. **Type inference** - infer types for `var x = expr`
3. **Type checking** - verify operand types match operators
4. **Constant folding** - evaluate compile-time constants
5. **Mode enforcement** - reject pointer syntax in `@mode safe`

**Key pattern from Go:**
```go
// Go's Checker walks the AST and builds typed info
type Checker struct {
    conf    *Config
    pkg     *Package
    info    *Info  // type information collected
    scope   *Scope
}

func (check *Checker) expr(x *operand, e ast.Expr) {
    // determine type of expression
}
```

**Zig equivalent:**
```zig
pub const Checker = struct {
    types: *TypeRegistry,
    scope: *Scope,
    err: *ErrorReporter,
    ast: *const Ast,

    pub fn checkExpr(self: *Checker, idx: NodeIndex) !TypeIndex { ... }
    pub fn checkStmt(self: *Checker, idx: NodeIndex) !void { ... }
};

pub const Scope = struct {
    parent: ?*Scope,
    symbols: std.StringHashMap(Symbol),
};
```

**Output:** Annotated AST with type information attached to each node, ready for IR generation.

---

### src/ir.zig

**Purpose:** Typed intermediate representation - bridge between AST and SSA.

**Go equivalent:** `cmd/compile/internal/ir/` (node.go, func.go, expr.go, stmt.go)

**What it contains:**
- `IR` struct holding all IR nodes
- `Func` for function bodies with typed parameters/returns
- `Node` union for IR operations (simpler than AST)
- `LocalVar` for stack-allocated variables with types
- Control flow representation (basic structure, not SSA yet)

**Key pattern from Go:**
Go's IR is a typed, lowered form of the AST. Many AST constructs desugar:
- `for item in array` → index-based loop
- `a += b` → `a = a + b`
- Method calls → function calls with receiver

```go
// Go's IR nodes are simpler than AST
type Node struct {
    op   Op
    Type *types.Type
    // ...
}
```

**Zig equivalent:**
```zig
pub const Node = struct {
    op: Op,
    type_idx: TypeIndex,
    args: []const NodeIndex,
    span: Span,
};

pub const Op = enum {
    // Constants
    const_int,
    const_float,
    const_string,

    // Operations
    add, sub, mul, div,
    eq, ne, lt, le, gt, ge,

    // Memory
    local,      // stack variable
    load,       // read from address
    store,      // write to address

    // Control
    call,
    ret,
    branch,
    phi,        // SSA phi node (added in SSA pass)
};
```

**Output:** Flat list of typed operations per function, ready for SSA construction.

---

### src/ssa.zig (next)

**Purpose:** SSA form construction and optimization passes.

**Go equivalent:** `cmd/compile/internal/ssa/` (compile.go, func.go, block.go, value.go)

**What it contains:**
- `SSA` struct for SSA representation
- `Block` for basic blocks with predecessors/successors
- `Value` for SSA values (each assigned exactly once)
- `buildSSA()` - convert IR to SSA form
- Dominator tree construction
- Phi node insertion

**Key pattern from Go:**
```go
// Go's SSA structure
type Func struct {
    Blocks []*Block
    Entry  *Block
}

type Block struct {
    ID      ID
    Preds   []*Block
    Succs   []*Block
    Values  []*Value
    Control *Value  // branch condition
}

type Value struct {
    ID   ID
    Op   Op
    Type *types.Type
    Args []*Value
}
```

**Zig equivalent:**
```zig
pub const Func = struct {
    blocks: std.ArrayList(Block),
    entry: BlockIndex,
};

pub const Block = struct {
    id: BlockIndex,
    preds: []const BlockIndex,
    succs: []const BlockIndex,
    values: []const ValueIndex,
    control: ?ValueIndex,
};

pub const Value = struct {
    id: ValueIndex,
    op: Op,
    type_idx: TypeIndex,
    args: []const ValueIndex,
    block: BlockIndex,
};
```

**SSA construction algorithm:**
1. Build control flow graph (basic blocks)
2. Compute dominance frontiers
3. Insert phi nodes at dominance frontiers
4. Rename variables to SSA form

**Output:** SSA form ready for optimization passes and code generation.

---

### src/ssa/passes.zig

**Purpose:** SSA optimization passes.

**Go equivalent:** `cmd/compile/internal/ssa/*.go` (opt.go, lower.go, deadcode.go, etc.)

**Passes to implement (in order of importance):**

1. **Dead code elimination** - remove unused values
2. **Constant propagation** - replace variables with known constants
3. **Copy propagation** - eliminate redundant copies
4. **Common subexpression elimination** - reuse computed values
5. **Strength reduction** - replace expensive ops (mul → shift)
6. **Inlining** - inline small functions (post-bootstrap)

**Key pattern from Go:**
Each pass is a function that transforms the SSA:
```go
func deadcode(f *Func) {
    // mark live values, remove dead ones
}
```

**Zig equivalent:**
```zig
pub fn deadcode(func: *ssa.Func) void { ... }
pub fn constprop(func: *ssa.Func) void { ... }
pub fn copyprop(func: *ssa.Func) void { ... }
```

---

### src/codegen/ (directory)

**Purpose:** Generate native machine code from SSA. Direct x86-64 and ARM64 emission.

**Go equivalent:** `cmd/compile/internal/ssagen/ssa.go`, `cmd/compile/internal/amd64/`, `cmd/internal/obj/`

**Roc reference:** `~/learning/roc/crates/compiler/gen_dev/src/generic64/`

**Architecture:** Trait-based polymorphism (from Roc's design)

```
           ┌──────────────────────────┐
           │    Backend (trait)        │
           │  (high-level operations)  │
           └──────────────────────────┘
                       ↑
         ┌─────────────┴─────────────┐
         ↓                           ↓
    Assembler Trait            CallConv Trait
    (instruction encoding)     (calling conventions)
         │                           │
    ├─ x86_64.zig              ├─ SystemV (Unix)
    └─ aarch64.zig             └─ Win64 (Windows)
```

**File structure:**
```
src/codegen/
  backend.zig       - Backend trait, StorageManager
  x86_64.zig        - x86-64 instruction encoding (~1500 lines)
  aarch64.zig       - ARM64 instruction encoding (~1500 lines)
  callconv.zig      - Calling convention traits
  object.zig        - ELF/Mach-O object file generation
  reloc.zig         - Relocation handling
```

**Key traits (Zig interfaces):**

```zig
// Instruction encoding - each arch implements this
pub fn Assembler(comptime Reg: type, comptime FloatReg: type) type {
    return struct {
        pub const Iface = struct {
            addRegReg: *const fn (*Self, Reg, Reg) void,
            subRegReg: *const fn (*Self, Reg, Reg) void,
            movRegImm: *const fn (*Self, Reg, i64) void,
            movRegMem: *const fn (*Self, Reg, i32) void,  // [rbp+offset]
            call: *const fn (*Self, Reg) void,
            ret: *const fn (*Self) void,
            // ... ~50 methods
        };
    };
}

// Calling convention - SystemV, Win64, etc.
pub fn CallConv(comptime Reg: type, comptime FloatReg: type) type {
    return struct {
        // Which registers hold arguments
        param_regs: []const Reg,
        // Which registers are callee-saved
        callee_saved: []const Reg,
        // Return value register(s)
        return_regs: []const Reg,
        // Stack alignment requirement
        stack_align: u8,
    };
}
```

**x86-64 register definitions:**
```zig
pub const X86Reg = enum(u4) {
    rax = 0, rcx = 1, rdx = 2, rbx = 3,
    rsp = 4, rbp = 5, rsi = 6, rdi = 7,
    r8 = 8, r9 = 9, r10 = 10, r11 = 11,
    r12 = 12, r13 = 13, r14 = 14, r15 = 15,

    pub fn encoding(self: X86Reg) u4 {
        return @intFromEnum(self);
    }
};

// SystemV ABI (Linux, macOS)
pub const SystemV = CallConv(X86Reg, X86FloatReg){
    .param_regs = &.{ .rdi, .rsi, .rdx, .rcx, .r8, .r9 },
    .callee_saved = &.{ .rbx, .r12, .r13, .r14, .r15, .rbp },
    .return_regs = &.{ .rax, .rdx },
    .stack_align = 16,
};
```

**Storage Manager (register allocation):**
```zig
pub const StorageManager = struct {
    symbol_storage: std.StringHashMap(Storage),
    stack_offset: i32,
    free_regs: RegSet,

    pub const Storage = union(enum) {
        reg: Reg,                    // Value in register
        stack: i32,                  // Value at [rbp+offset]
        spilled: struct { reg: Reg, stack: i32 },  // Both
    };

    pub fn allocate(self: *StorageManager, sym: []const u8, size: u32) Storage { ... }
    pub fn spill(self: *StorageManager, reg: Reg) void { ... }
    pub fn free(self: *StorageManager, sym: []const u8) void { ... }
};
```

**Instruction encoding example (x86-64 ADD):**
```zig
// ADD r64, r64 → REX.W + 01 /r
pub fn addRegReg(self: *X86Backend, dst: X86Reg, src: X86Reg) void {
    const rex = 0x48 | (src.needsRex() << 2) | dst.needsRex();
    self.emit(&.{ rex, 0x01, modrm(.reg, src, dst) });
}

fn modrm(mod: Mod, reg: X86Reg, rm: X86Reg) u8 {
    return (@intFromEnum(mod) << 6) | (reg.low3() << 3) | rm.low3();
}
```

**Object file generation:**
```zig
pub const ObjectFile = struct {
    sections: std.ArrayList(Section),
    symbols: std.ArrayList(Symbol),
    relocations: std.ArrayList(Relocation),

    pub fn emit(self: *ObjectFile, writer: anytype) !void {
        // Write ELF or Mach-O header
        // Write sections (.text, .data, .rodata)
        // Write symbol table
        // Write relocations
    }
};
```

**Code generation flow:**
```
SSA Func
    ↓
StorageManager.allocate() for each value
    ↓
For each SSA Block:
    For each SSA Value:
        Backend.emitValue(value)
            → Assembler.addRegReg() / movRegMem() / etc.
    ↓
ObjectFile.emit() → .o file
    ↓
System linker → executable
```

**Output:** Native object files (.o), linked with system linker to produce executable.

---

### src/arc.zig (future)

**Purpose:** Automatic Reference Counting runtime support.

**What it contains:**
- Reference count fields in heap objects
- `retain()` / `release()` intrinsics
- Weak reference support (post-bootstrap)
- Cycle detection (post-bootstrap, or use weak refs)

**Key pattern:**
```zig
pub const RcHeader = struct {
    count: u32,
};

pub fn retain(ptr: anytype) void {
    const header = @ptrCast(*RcHeader, ptr - @sizeOf(RcHeader));
    header.count += 1;
}

pub fn release(ptr: anytype) void {
    const header = @ptrCast(*RcHeader, ptr - @sizeOf(RcHeader));
    header.count -= 1;
    if (header.count == 0) {
        // call destructor, free memory
    }
}
```

The compiler inserts retain/release calls at appropriate points during IR generation.

---

## Compilation Pipeline Summary

```
Source (.cot)
    ↓
Scanner (source.zig, scanner.zig)
    ↓ tokens
Parser (parser.zig)
    ↓ AST (ast.zig)
Type Checker (check.zig)
    ↓ typed AST + type info
IR Generation (ir.zig)
    ↓ typed IR
SSA Construction (ssa.zig)
    ↓ SSA form
Optimization Passes (ssa/passes.zig)
    ↓ optimized SSA
Code Generation (codegen/)
    ↓ native machine code
Object File (codegen/object.zig)
    ↓ .o file (ELF/Mach-O)
System Linker (ld/lld)
    ↓
Executable
```

**Target architectures:**
- x86-64 (Linux, macOS, Windows)
- ARM64 (macOS, Linux)

**Design influences:**
- Go: SSA structure, compilation phases
- Roc: Trait-based backend architecture, direct object file generation
- Zig: Memory model, comptime patterns

---

## Code Quality Verification

Before any milestone is considered complete, verify:

1. **Zero TODO statements in code**
   ```bash
   grep -r "TODO" src/ --include="*.zig" | wc -l
   # Must be 0
   ```

2. **All tests pass**
   ```bash
   zig build test
   ```

3. **No compiler warnings**
   ```bash
   zig build 2>&1 | grep -i warning | wc -l
   # Must be 0
   ```

TODOs indicate unfinished work. Every TODO must be either:
- Completed and removed
- Converted to a GitHub issue and removed from code
- Explicitly deferred to a future milestone (documented in this file)
