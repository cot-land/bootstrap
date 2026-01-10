///! Source text handling and position tracking.
///!
///! Maps to Go's cmd/compile/internal/syntax/source.go and cmd/internal/src/pos.go
///! Simplified: we read entire file into memory rather than streaming.

const std = @import("std");

/// A position in source code (offset-based).
/// Compact representation - line/column computed on demand.
pub const Pos = struct {
    offset: u32,

    pub const zero = Pos{ .offset = 0 };

    pub fn advance(self: Pos, n: u32) Pos {
        return .{ .offset = self.offset + n };
    }
};

/// A span in source code (start and end positions).
/// Used for AST nodes and error messages.
pub const Span = struct {
    start: Pos,
    end: Pos,

    pub fn init(start: Pos, end: Pos) Span {
        return .{ .start = start, .end = end };
    }

    pub fn fromPos(pos: Pos) Span {
        return .{ .start = pos, .end = pos };
    }
};

/// Human-readable location (for error messages).
pub const Location = struct {
    line: u32, // 1-based
    column: u32, // 1-based
    offset: u32, // 0-based byte offset

    pub fn format(
        self: Location,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("{}:{}", .{ self.line, self.column });
    }
};

/// Source holds the content of a source file.
pub const Source = struct {
    /// File name (for error messages)
    filename: []const u8,

    /// Source content (UTF-8)
    content: []const u8,

    /// Byte offsets of line starts (computed lazily)
    line_offsets: ?[]u32,

    /// Allocator for line offset computation
    allocator: std.mem.Allocator,

    /// Initialize a source from content.
    pub fn init(allocator: std.mem.Allocator, filename: []const u8, content: []const u8) Source {
        return .{
            .filename = filename,
            .content = content,
            .line_offsets = null,
            .allocator = allocator,
        };
    }

    /// Free resources.
    pub fn deinit(self: *Source) void {
        if (self.line_offsets) |offsets| {
            self.allocator.free(offsets);
        }
    }

    /// Get the byte at a position, or null if past end.
    pub fn at(self: *const Source, pos: Pos) ?u8 {
        if (pos.offset >= self.content.len) return null;
        return self.content[pos.offset];
    }

    /// Get a slice of source content.
    pub fn slice(self: *const Source, start: Pos, end: Pos) []const u8 {
        const s = @min(start.offset, @as(u32, @intCast(self.content.len)));
        const e = @min(end.offset, @as(u32, @intCast(self.content.len)));
        return self.content[s..e];
    }

    /// Get the text for a span.
    pub fn spanText(self: *const Source, span: Span) []const u8 {
        return self.slice(span.start, span.end);
    }

    /// Convert a position to a human-readable location.
    pub fn location(self: *Source, pos: Pos) Location {
        self.ensureLineOffsets();

        const offsets = self.line_offsets.?;
        const offset = pos.offset;

        // Binary search for the line containing this offset
        var line: u32 = 0;
        var lo: usize = 0;
        var hi: usize = offsets.len;

        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (offsets[mid] <= offset) {
                line = @intCast(mid);
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        const line_start = offsets[line];
        const column = offset - line_start;

        return .{
            .line = line + 1, // 1-based
            .column = column + 1, // 1-based
            .offset = offset,
        };
    }

    /// Compute line offsets if not already done.
    fn ensureLineOffsets(self: *Source) void {
        if (self.line_offsets != null) return;

        // Count newlines first
        var count: usize = 1; // Line 1 starts at offset 0
        for (self.content) |c| {
            if (c == '\n') count += 1;
        }

        // Allocate and fill
        const offsets = self.allocator.alloc(u32, count) catch return;
        offsets[0] = 0;
        var idx: usize = 1;
        for (self.content, 0..) |c, i| {
            if (c == '\n') {
                offsets[idx] = @intCast(i + 1);
                idx += 1;
            }
        }

        self.line_offsets = offsets;
    }

    /// Format an error message with source location.
    pub fn formatError(
        self: *Source,
        pos: Pos,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        const loc = self.location(pos);
        std.debug.print("{s}:{}:{}: error: ", .{ self.filename, loc.line, loc.column });
        std.debug.print(fmt ++ "\n", args);
    }

    /// Get the line containing a position (for error context).
    pub fn getLine(self: *Source, pos: Pos) []const u8 {
        self.ensureLineOffsets();
        const loc = self.location(pos);
        const offsets = self.line_offsets.?;

        const line_idx = loc.line - 1;
        const start = offsets[line_idx];

        var end = start;
        while (end < self.content.len and self.content[end] != '\n') {
            end += 1;
        }

        return self.content[start..end];
    }
};

// Tests
test "source position and location" {
    const content = "fn main() {\n    return 0\n}";
    var source = Source.init(std.testing.allocator, "test.cot", content);
    defer source.deinit();

    // First character
    const loc0 = source.location(Pos{ .offset = 0 });
    try std.testing.expectEqual(@as(u32, 1), loc0.line);
    try std.testing.expectEqual(@as(u32, 1), loc0.column);

    // 'm' in 'main'
    const loc3 = source.location(Pos{ .offset = 3 });
    try std.testing.expectEqual(@as(u32, 1), loc3.line);
    try std.testing.expectEqual(@as(u32, 4), loc3.column);

    // 'r' in 'return' (second line)
    const loc16 = source.location(Pos{ .offset = 16 });
    try std.testing.expectEqual(@as(u32, 2), loc16.line);
    try std.testing.expectEqual(@as(u32, 5), loc16.column);
}

test "source slice" {
    const content = "hello world";
    var source = Source.init(std.testing.allocator, "test.cot", content);
    defer source.deinit();

    const span = Span.init(Pos{ .offset = 0 }, Pos{ .offset = 5 });
    try std.testing.expectEqualStrings("hello", source.spanText(span));
}

test "source getLine" {
    const content = "line one\nline two\nline three";
    var source = Source.init(std.testing.allocator, "test.cot", content);
    defer source.deinit();

    try std.testing.expectEqualStrings("line one", source.getLine(Pos{ .offset = 0 }));
    try std.testing.expectEqualStrings("line two", source.getLine(Pos{ .offset = 10 }));
    try std.testing.expectEqualStrings("line three", source.getLine(Pos{ .offset = 20 }));
}

test "source at" {
    const content = "abc";
    var source = Source.init(std.testing.allocator, "test.cot", content);
    defer source.deinit();

    try std.testing.expectEqual(@as(?u8, 'a'), source.at(Pos{ .offset = 0 }));
    try std.testing.expectEqual(@as(?u8, 'b'), source.at(Pos{ .offset = 1 }));
    try std.testing.expectEqual(@as(?u8, 'c'), source.at(Pos{ .offset = 2 }));
    try std.testing.expectEqual(@as(?u8, null), source.at(Pos{ .offset = 3 }));
}
