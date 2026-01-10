///! Error handling infrastructure.
///!
///! Maps to Go's error pattern from cmd/compile/internal/syntax/syntax.go
///! - Simple Error struct with position and message
///! - ErrorHandler callback for external handling
///! - First error tracking for return values
///! - Optional trace mode for debugging

const std = @import("std");
const source = @import("source.zig");
const Span = source.Span;
const Pos = source.Pos;
const Source = source.Source;

/// Compile-time trace flag for debug output.
/// Set to true when debugging parser/scanner issues.
pub const trace = false;

/// An error at a specific source location.
pub const Error = struct {
    span: Span,
    msg: []const u8,
    code: ?ErrorCode = null,

    /// Format for display.
    pub fn format(
        self: Error,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        // Just print the message; location is added by ErrorReporter
        try writer.writeAll(self.msg);
    }
};

/// Error codes for categorizing errors.
/// Useful for tooling, IDE integration, and documentation references.
pub const ErrorCode = enum(u16) {
    // Scanner errors (1xx)
    E100 = 100, // unterminated string literal
    E101 = 101, // unterminated character literal
    E102 = 102, // invalid escape sequence
    E103 = 103, // invalid number literal
    E104 = 104, // unexpected character

    // Parser errors (2xx)
    E200 = 200, // unexpected token
    E201 = 201, // expected expression
    E202 = 202, // expected type
    E203 = 203, // expected identifier
    E204 = 204, // expected '{'
    E205 = 205, // expected '}'
    E206 = 206, // expected '('
    E207 = 207, // expected ')'
    E208 = 208, // expected ';' or newline

    // Type errors (3xx)
    E300 = 300, // type mismatch
    E301 = 301, // undefined identifier
    E302 = 302, // redefined identifier
    E303 = 303, // invalid operation

    pub fn description(self: ErrorCode) []const u8 {
        return switch (self) {
            .E100 => "unterminated string literal",
            .E101 => "unterminated character literal",
            .E102 => "invalid escape sequence",
            .E103 => "invalid number literal",
            .E104 => "unexpected character",
            .E200 => "unexpected token",
            .E201 => "expected expression",
            .E202 => "expected type",
            .E203 => "expected identifier",
            .E204 => "expected '{'",
            .E205 => "expected '}'",
            .E206 => "expected '('",
            .E207 => "expected ')'",
            .E208 => "expected ';' or newline",
            .E300 => "type mismatch",
            .E301 => "undefined identifier",
            .E302 => "redefined identifier",
            .E303 => "invalid operation",
        };
    }
};

/// Callback type for error handling.
/// Called for each error encountered during parsing.
pub const ErrorHandler = *const fn (err: Error) void;

/// Collects and reports errors during compilation.
pub const ErrorReporter = struct {
    src: *Source,
    handler: ?ErrorHandler,
    first: ?Error,
    count: u32,

    pub fn init(src: *Source, handler: ?ErrorHandler) ErrorReporter {
        return .{
            .src = src,
            .handler = handler,
            .first = null,
            .count = 0,
        };
    }

    /// Report an error at a position.
    pub fn errorAt(self: *ErrorReporter, pos: Pos, msg: []const u8) void {
        self.errorAtSpan(Span.fromPos(pos), msg, null);
    }

    /// Report an error with an error code.
    pub fn errorWithCode(self: *ErrorReporter, pos: Pos, code: ErrorCode, msg: []const u8) void {
        self.errorAtSpan(Span.fromPos(pos), msg, code);
    }

    /// Report an error at a span.
    pub fn errorAtSpan(self: *ErrorReporter, span: Span, msg: []const u8, code: ?ErrorCode) void {
        const err = Error{
            .span = span,
            .msg = msg,
            .code = code,
        };

        if (self.first == null) {
            self.first = err;
        }
        self.count += 1;

        if (self.handler) |h| {
            h(err);
        } else {
            // Default: print to stderr
            self.printError(err);
        }
    }

    /// Print an error with source context.
    fn printError(self: *ErrorReporter, err: Error) void {
        const loc = self.src.location(err.span.start);

        // filename:line:column: error: message
        if (err.code) |code| {
            std.debug.print("{s}:{}:{}: error[E{d}]: {s}\n", .{
                self.src.filename,
                loc.line,
                loc.column,
                @intFromEnum(code),
                err.msg,
            });
        } else {
            std.debug.print("{s}:{}:{}: error: {s}\n", .{
                self.src.filename,
                loc.line,
                loc.column,
                err.msg,
            });
        }

        // Show the source line
        const line = self.src.getLine(err.span.start);
        std.debug.print("    {s}\n", .{line});

        // Show the caret indicator
        const col = loc.column;
        if (col > 0) {
            // Print spaces for indentation (4 for "    " prefix + column-1)
            var i: u32 = 0;
            std.debug.print("    ", .{});
            while (i < col - 1) : (i += 1) {
                // Preserve tabs in the indicator line
                if (i < line.len and line[i] == '\t') {
                    std.debug.print("\t", .{});
                } else {
                    std.debug.print(" ", .{});
                }
            }
            std.debug.print("^\n", .{});
        }
    }

    /// Check if any errors were reported.
    pub fn hasErrors(self: *const ErrorReporter) bool {
        return self.count > 0;
    }

    /// Get the first error (for return value).
    pub fn firstError(self: *const ErrorReporter) ?Error {
        return self.first;
    }
};

/// Print a trace message if trace mode is enabled.
pub fn traceMsg(comptime fmt: []const u8, args: anytype) void {
    if (trace) {
        std.debug.print("[trace] " ++ fmt ++ "\n", args);
    }
}

// Tests
test "error reporter basic" {
    const content = "fn main() {\n    x = 1\n}";
    var src = Source.init(std.testing.allocator, "test.cot", content);
    defer src.deinit();

    var reporter = ErrorReporter.init(&src, null);

    try std.testing.expect(!reporter.hasErrors());

    // Report an error (this will print to stderr in tests)
    reporter.errorAt(Pos{ .offset = 16 }, "undefined variable 'x'");

    try std.testing.expect(reporter.hasErrors());
    try std.testing.expectEqual(@as(u32, 1), reporter.count);
    try std.testing.expect(reporter.first != null);
}

test "error reporter with code" {
    const content = "let s = \"unterminated";
    var src = Source.init(std.testing.allocator, "test.cot", content);
    defer src.deinit();

    var reporter = ErrorReporter.init(&src, null);
    reporter.errorWithCode(Pos{ .offset = 8 }, .E100, "string literal not terminated");

    try std.testing.expect(reporter.first != null);
    try std.testing.expectEqual(ErrorCode.E100, reporter.first.?.code.?);
}

test "error code descriptions" {
    try std.testing.expectEqualStrings("unterminated string literal", ErrorCode.E100.description());
    try std.testing.expectEqualStrings("unexpected token", ErrorCode.E200.description());
}

test "multiple errors" {
    const content = "x y z";
    var src = Source.init(std.testing.allocator, "test.cot", content);
    defer src.deinit();

    var reporter = ErrorReporter.init(&src, null);
    reporter.errorAt(Pos{ .offset = 0 }, "error 1");
    reporter.errorAt(Pos{ .offset = 2 }, "error 2");
    reporter.errorAt(Pos{ .offset = 4 }, "error 3");

    try std.testing.expectEqual(@as(u32, 3), reporter.count);
    // First error is preserved
    try std.testing.expectEqualStrings("error 1", reporter.first.?.msg);
}
