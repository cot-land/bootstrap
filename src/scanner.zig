///! Lexical scanner for cot.
///!
///! Maps to Go's cmd/compile/internal/syntax/scanner.go
///! Simplified: works on a slice, not streaming.

const std = @import("std");
const token = @import("token.zig");
const source = @import("source.zig");
const errors = @import("errors.zig");

const Token = token.Token;
const Pos = source.Pos;
const Span = source.Span;
const Source = source.Source;
const ErrorReporter = errors.ErrorReporter;
const ErrorCode = errors.ErrorCode;

/// A scanned token with position and text.
pub const TokenInfo = struct {
    tok: Token,
    span: Span,
    /// For identifiers and literals, the text of the token.
    /// For keywords and operators, this is empty (use tok.toString()).
    text: []const u8,
};

/// Scanner tokenizes source code.
pub const Scanner = struct {
    src: *Source,
    pos: Pos,
    /// Current character (or null if at end)
    ch: ?u8,
    /// Error reporter (optional)
    err: ?*ErrorReporter,
    /// Track if we're inside an interpolated string (after seeing ${ )
    in_interp_string: bool,
    /// Track brace depth for nested expressions in interpolated strings
    interp_brace_depth: u32,

    /// Initialize scanner with source.
    pub fn init(src: *Source) Scanner {
        return initWithErrors(src, null);
    }

    /// Initialize scanner with source and error reporter.
    pub fn initWithErrors(src: *Source, err: ?*ErrorReporter) Scanner {
        var s = Scanner{
            .src = src,
            .pos = Pos.zero,
            .ch = null,
            .err = err,
            .in_interp_string = false,
            .interp_brace_depth = 0,
        };
        s.ch = src.at(s.pos);
        return s;
    }

    /// Report an error at the current position.
    fn errorAt(self: *Scanner, pos: Pos, code: ErrorCode, msg: []const u8) void {
        if (self.err) |reporter| {
            reporter.errorWithCode(pos, code, msg);
        }
    }

    /// Scan and return the next token.
    pub fn next(self: *Scanner) TokenInfo {
        self.skipWhitespaceAndComments();

        const start = self.pos;

        // Check for end of file
        if (self.ch == null) {
            return .{
                .tok = .eof,
                .span = Span.fromPos(start),
                .text = "",
            };
        }

        const c = self.ch.?;

        // Identifier or keyword
        if (isAlpha(c) or c == '_') {
            return self.scanIdentifier(start);
        }

        // Number
        if (isDigit(c)) {
            return self.scanNumber(start);
        }

        // String literal
        if (c == '"') {
            return self.scanString(start);
        }

        // Character literal
        if (c == '\'') {
            return self.scanChar(start);
        }

        // Operators and delimiters
        return self.scanOperator(start);
    }

    /// Skip whitespace and comments.
    fn skipWhitespaceAndComments(self: *Scanner) void {
        while (self.ch) |c| {
            if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
                self.advance();
            } else if (c == '/') {
                // Check for comments
                if (self.peek(1) == '/') {
                    self.skipLineComment();
                } else if (self.peek(1) == '*') {
                    self.skipBlockComment();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    fn skipLineComment(self: *Scanner) void {
        // Skip //
        self.advance();
        self.advance();
        // Skip until newline or EOF
        while (self.ch) |c| {
            if (c == '\n') {
                self.advance();
                break;
            }
            self.advance();
        }
    }

    fn skipBlockComment(self: *Scanner) void {
        // Skip /*
        self.advance();
        self.advance();
        // Skip until */
        while (self.ch != null) {
            if (self.ch == '*' and self.peek(1) == '/') {
                self.advance();
                self.advance();
                break;
            }
            self.advance();
        }
    }

    /// Scan an identifier or keyword.
    fn scanIdentifier(self: *Scanner, start: Pos) TokenInfo {
        while (self.ch) |c| {
            if (isAlphaNumeric(c) or c == '_') {
                self.advance();
            } else {
                break;
            }
        }

        const text = self.src.content[start.offset..self.pos.offset];

        // Check if it's a keyword
        if (token.keywords.get(text)) |kw| {
            return .{
                .tok = kw,
                .span = Span.init(start, self.pos),
                .text = "",
            };
        }

        return .{
            .tok = .identifier,
            .span = Span.init(start, self.pos),
            .text = text,
        };
    }

    /// Scan a number literal (integer or float).
    fn scanNumber(self: *Scanner, start: Pos) TokenInfo {
        var is_float = false;

        // Handle hex, octal, binary prefixes
        if (self.ch == '0') {
            self.advance();
            if (self.ch) |c| {
                if (c == 'x' or c == 'X') {
                    self.advance();
                    self.scanHexDigits();
                    return self.makeNumberToken(start, false);
                } else if (c == 'o' or c == 'O') {
                    self.advance();
                    self.scanOctalDigits();
                    return self.makeNumberToken(start, false);
                } else if (c == 'b' or c == 'B') {
                    self.advance();
                    self.scanBinaryDigits();
                    return self.makeNumberToken(start, false);
                }
            }
        }

        // Decimal digits
        self.scanDecimalDigits();

        // Fractional part
        if (self.ch == '.' and self.peek(1) != '.') {
            is_float = true;
            self.advance();
            self.scanDecimalDigits();
        }

        // Exponent
        if (self.ch) |c| {
            if (c == 'e' or c == 'E') {
                is_float = true;
                self.advance();
                if (self.ch == '+' or self.ch == '-') {
                    self.advance();
                }
                self.scanDecimalDigits();
            }
        }

        return self.makeNumberToken(start, is_float);
    }

    fn makeNumberToken(self: *Scanner, start: Pos, is_float: bool) TokenInfo {
        const text = self.src.content[start.offset..self.pos.offset];
        return .{
            .tok = if (is_float) .float_literal else .int_literal,
            .span = Span.init(start, self.pos),
            .text = text,
        };
    }

    fn scanDecimalDigits(self: *Scanner) void {
        while (self.ch) |c| {
            if (isDigit(c) or c == '_') {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn scanHexDigits(self: *Scanner) void {
        while (self.ch) |c| {
            if (isHexDigit(c) or c == '_') {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn scanOctalDigits(self: *Scanner) void {
        while (self.ch) |c| {
            if (c >= '0' and c <= '7' or c == '_') {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn scanBinaryDigits(self: *Scanner) void {
        while (self.ch) |c| {
            if (c == '0' or c == '1' or c == '_') {
                self.advance();
            } else {
                break;
            }
        }
    }

    /// Scan a string literal (may be interpolated).
    fn scanString(self: *Scanner, start: Pos) TokenInfo {
        self.advance(); // consume opening "

        var terminated = false;
        var found_interp = false;
        while (self.ch) |c| {
            if (c == '"') {
                self.advance();
                terminated = true;
                break;
            } else if (c == '\\') {
                self.advance(); // skip backslash
                if (self.ch != null) {
                    self.advance(); // skip escaped char
                }
            } else if (c == '$') {
                // Check for ${ interpolation
                const next_ch = self.src.at(self.pos.advance(1));
                if (next_ch != null and next_ch.? == '{') {
                    self.advance(); // consume $
                    self.advance(); // consume {
                    found_interp = true;
                    self.in_interp_string = true;
                    self.interp_brace_depth = 1;
                    break;
                } else {
                    self.advance(); // just a regular $
                }
            } else if (c == '\n') {
                // Unterminated string - newline before closing quote
                break;
            } else {
                self.advance();
            }
        }

        if (!terminated and !found_interp) {
            self.errorAt(start, .E100, "string literal not terminated");
        }

        const text = self.src.content[start.offset..self.pos.offset];
        if (found_interp) {
            return .{
                .tok = .string_interp_start,
                .span = Span.init(start, self.pos),
                .text = text,
            };
        }
        return .{
            .tok = .string_literal,
            .span = Span.init(start, self.pos),
            .text = text,
        };
    }

    /// Continue scanning an interpolated string after an expression.
    /// Called when we see } and are in interpolated string mode.
    fn scanStringContinuation(self: *Scanner, start: Pos) TokenInfo {
        var terminated = false;
        var found_interp = false;

        while (self.ch) |c| {
            if (c == '"') {
                self.advance();
                terminated = true;
                self.in_interp_string = false;
                break;
            } else if (c == '\\') {
                self.advance(); // skip backslash
                if (self.ch != null) {
                    self.advance(); // skip escaped char
                }
            } else if (c == '$') {
                // Check for ${ interpolation
                const next_ch = self.src.at(self.pos.advance(1));
                if (next_ch != null and next_ch.? == '{') {
                    self.advance(); // consume $
                    self.advance(); // consume {
                    found_interp = true;
                    self.interp_brace_depth = 1;
                    break;
                } else {
                    self.advance(); // just a regular $
                }
            } else if (c == '\n') {
                // Unterminated string - newline before closing quote
                break;
            } else {
                self.advance();
            }
        }

        if (!terminated and !found_interp) {
            self.errorAt(start, .E100, "string literal not terminated");
        }

        const text = self.src.content[start.offset..self.pos.offset];
        if (found_interp) {
            return .{
                .tok = .string_interp_mid,
                .span = Span.init(start, self.pos),
                .text = text,
            };
        }
        return .{
            .tok = .string_interp_end,
            .span = Span.init(start, self.pos),
            .text = text,
        };
    }

    /// Scan a character literal.
    fn scanChar(self: *Scanner, start: Pos) TokenInfo {
        self.advance(); // consume opening '

        if (self.ch == '\\') {
            self.advance();
            if (self.ch != null) {
                self.advance();
            }
        } else if (self.ch != null and self.ch != '\'') {
            self.advance();
        }

        var terminated = false;
        if (self.ch == '\'') {
            self.advance();
            terminated = true;
        }

        if (!terminated) {
            self.errorAt(start, .E101, "character literal not terminated");
        }

        const text = self.src.content[start.offset..self.pos.offset];
        return .{
            .tok = .char_literal,
            .span = Span.init(start, self.pos),
            .text = text,
        };
    }

    /// Scan operators and delimiters.
    fn scanOperator(self: *Scanner, start: Pos) TokenInfo {
        const c = self.ch.?;
        self.advance();

        // Handle braces specially when in interpolated string mode
        if (c == '{' and self.in_interp_string) {
            self.interp_brace_depth += 1;
            return .{
                .tok = .lbrace,
                .span = Span.init(start, self.pos),
                .text = "",
            };
        }

        if (c == '}' and self.in_interp_string) {
            self.interp_brace_depth -= 1;
            if (self.interp_brace_depth == 0) {
                // End of interpolated expression - continue scanning string
                return self.scanStringContinuation(start);
            }
            return .{
                .tok = .rbrace,
                .span = Span.init(start, self.pos),
                .text = "",
            };
        }

        const tok: Token = switch (c) {
            '(' => .lparen,
            ')' => .rparen,
            '[' => .lbracket,
            ']' => .rbracket,
            '{' => .lbrace,
            '}' => .rbrace,
            ',' => .comma,
            ';' => .semicolon,
            ':' => .colon,
            '~' => .tilde,
            '@' => .at,

            '+' => if (self.ch == '=') blk: {
                self.advance();
                break :blk .plus_equal;
            } else .plus,

            '-' => if (self.ch == '=') blk: {
                self.advance();
                break :blk .minus_equal;
            } else if (self.ch == '>') blk: {
                self.advance();
                break :blk .arrow;
            } else .minus,

            '*' => if (self.ch == '=') blk: {
                self.advance();
                break :blk .star_equal;
            } else .star,

            '/' => if (self.ch == '=') blk: {
                self.advance();
                break :blk .slash_equal;
            } else .slash,

            '%' => if (self.ch == '=') blk: {
                self.advance();
                break :blk .percent_equal;
            } else .percent,

            '&' => if (self.ch == '=') blk: {
                self.advance();
                break :blk .ampersand_equal;
            } else .ampersand,

            '|' => if (self.ch == '=') blk: {
                self.advance();
                break :blk .pipe_equal;
            } else .pipe,

            '^' => if (self.ch == '=') blk: {
                self.advance();
                break :blk .caret_equal;
            } else .caret,

            '=' => if (self.ch == '=') blk: {
                self.advance();
                break :blk .equal_equal;
            } else if (self.ch == '>') blk: {
                self.advance();
                break :blk .fat_arrow;
            } else .equal,

            '!' => if (self.ch == '=') blk: {
                self.advance();
                break :blk .bang_equal;
            } else .bang,

            '<' => if (self.ch == '=') blk: {
                self.advance();
                break :blk .less_equal;
            } else if (self.ch == '<') blk: {
                self.advance();
                break :blk .less_less;
            } else .less,

            '>' => if (self.ch == '=') blk: {
                self.advance();
                break :blk .greater_equal;
            } else if (self.ch == '>') blk: {
                self.advance();
                break :blk .greater_greater;
            } else .greater,

            '.' => if (self.ch == '.') blk: {
                self.advance();
                break :blk .dot_dot;
            } else if (self.ch == '*') blk: {
                self.advance();
                break :blk .dot_star;
            } else if (self.ch == '?') blk: {
                self.advance();
                break :blk .dot_question;
            } else .dot,

            '?' => if (self.ch == '?') blk: {
                self.advance();
                break :blk .question_question;
            } else if (self.ch == '.') blk: {
                self.advance();
                break :blk .question_dot;
            } else .question,

            else => .invalid,
        };

        if (tok == .invalid) {
            self.errorAt(start, .E104, "unexpected character");
        }

        return .{
            .tok = tok,
            .span = Span.init(start, self.pos),
            .text = "",
        };
    }

    /// Advance to next character.
    fn advance(self: *Scanner) void {
        self.pos = self.pos.advance(1);
        self.ch = self.src.at(self.pos);
    }

    /// Peek ahead n characters.
    fn peek(self: *Scanner, n: u32) ?u8 {
        return self.src.at(self.pos.advance(n));
    }
};

// Character classification
fn isAlpha(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
}

fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}

fn isHexDigit(c: u8) bool {
    return isDigit(c) or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

fn isAlphaNumeric(c: u8) bool {
    return isAlpha(c) or isDigit(c);
}

// Tests
test "scanner basics" {
    const content = "fn main() { return 42 }";
    var src = Source.init(std.testing.allocator, "test.cot", content);
    defer src.deinit();

    var scanner = Scanner.init(&src);

    // fn
    var tok = scanner.next();
    try std.testing.expectEqual(Token.kw_fn, tok.tok);

    // main
    tok = scanner.next();
    try std.testing.expectEqual(Token.identifier, tok.tok);
    try std.testing.expectEqualStrings("main", tok.text);

    // (
    tok = scanner.next();
    try std.testing.expectEqual(Token.lparen, tok.tok);

    // )
    tok = scanner.next();
    try std.testing.expectEqual(Token.rparen, tok.tok);

    // {
    tok = scanner.next();
    try std.testing.expectEqual(Token.lbrace, tok.tok);

    // return
    tok = scanner.next();
    try std.testing.expectEqual(Token.kw_return, tok.tok);

    // 42
    tok = scanner.next();
    try std.testing.expectEqual(Token.int_literal, tok.tok);
    try std.testing.expectEqualStrings("42", tok.text);

    // }
    tok = scanner.next();
    try std.testing.expectEqual(Token.rbrace, tok.tok);

    // EOF
    tok = scanner.next();
    try std.testing.expectEqual(Token.eof, tok.tok);
}

test "scanner operators" {
    const content = "== != <= >= << >> .. .* .? ?? ?.";
    var src = Source.init(std.testing.allocator, "test.cot", content);
    defer src.deinit();

    var scanner = Scanner.init(&src);

    try std.testing.expectEqual(Token.equal_equal, scanner.next().tok);
    try std.testing.expectEqual(Token.bang_equal, scanner.next().tok);
    try std.testing.expectEqual(Token.less_equal, scanner.next().tok);
    try std.testing.expectEqual(Token.greater_equal, scanner.next().tok);
    try std.testing.expectEqual(Token.less_less, scanner.next().tok);
    try std.testing.expectEqual(Token.greater_greater, scanner.next().tok);
    try std.testing.expectEqual(Token.dot_dot, scanner.next().tok);
    try std.testing.expectEqual(Token.dot_star, scanner.next().tok);
    try std.testing.expectEqual(Token.dot_question, scanner.next().tok);
    try std.testing.expectEqual(Token.question_question, scanner.next().tok);
    try std.testing.expectEqual(Token.question_dot, scanner.next().tok);
    try std.testing.expectEqual(Token.eof, scanner.next().tok);
}

test "scanner strings" {
    const content =
        \\"hello world" "with \"escape\""
    ;
    var src = Source.init(std.testing.allocator, "test.cot", content);
    defer src.deinit();

    var scanner = Scanner.init(&src);

    var tok = scanner.next();
    try std.testing.expectEqual(Token.string_literal, tok.tok);
    try std.testing.expectEqualStrings("\"hello world\"", tok.text);

    tok = scanner.next();
    try std.testing.expectEqual(Token.string_literal, tok.tok);
}

test "scanner numbers" {
    const content = "42 3.14 0xFF 0b1010 0o777 1_000_000";
    var src = Source.init(std.testing.allocator, "test.cot", content);
    defer src.deinit();

    var scanner = Scanner.init(&src);

    var tok = scanner.next();
    try std.testing.expectEqual(Token.int_literal, tok.tok);
    try std.testing.expectEqualStrings("42", tok.text);

    tok = scanner.next();
    try std.testing.expectEqual(Token.float_literal, tok.tok);
    try std.testing.expectEqualStrings("3.14", tok.text);

    tok = scanner.next();
    try std.testing.expectEqual(Token.int_literal, tok.tok);
    try std.testing.expectEqualStrings("0xFF", tok.text);

    tok = scanner.next();
    try std.testing.expectEqual(Token.int_literal, tok.tok);
    try std.testing.expectEqualStrings("0b1010", tok.text);

    tok = scanner.next();
    try std.testing.expectEqual(Token.int_literal, tok.tok);
    try std.testing.expectEqualStrings("0o777", tok.text);

    tok = scanner.next();
    try std.testing.expectEqual(Token.int_literal, tok.tok);
    try std.testing.expectEqualStrings("1_000_000", tok.text);
}

test "scanner comments" {
    const content =
        \\// line comment
        \\fn test() /* block comment */ { }
    ;
    var src = Source.init(std.testing.allocator, "test.cot", content);
    defer src.deinit();

    var scanner = Scanner.init(&src);

    try std.testing.expectEqual(Token.kw_fn, scanner.next().tok);
    try std.testing.expectEqual(Token.identifier, scanner.next().tok);
    try std.testing.expectEqual(Token.lparen, scanner.next().tok);
    try std.testing.expectEqual(Token.rparen, scanner.next().tok);
    try std.testing.expectEqual(Token.lbrace, scanner.next().tok);
    try std.testing.expectEqual(Token.rbrace, scanner.next().tok);
    try std.testing.expectEqual(Token.eof, scanner.next().tok);
}

test "scanner keywords" {
    const content = "var let const if else while for in return and or not";
    var src = Source.init(std.testing.allocator, "test.cot", content);
    defer src.deinit();

    var scanner = Scanner.init(&src);

    try std.testing.expectEqual(Token.kw_var, scanner.next().tok);
    try std.testing.expectEqual(Token.kw_let, scanner.next().tok);
    try std.testing.expectEqual(Token.kw_const, scanner.next().tok);
    try std.testing.expectEqual(Token.kw_if, scanner.next().tok);
    try std.testing.expectEqual(Token.kw_else, scanner.next().tok);
    try std.testing.expectEqual(Token.kw_while, scanner.next().tok);
    try std.testing.expectEqual(Token.kw_for, scanner.next().tok);
    try std.testing.expectEqual(Token.kw_in, scanner.next().tok);
    try std.testing.expectEqual(Token.kw_return, scanner.next().tok);
    try std.testing.expectEqual(Token.kw_and, scanner.next().tok);
    try std.testing.expectEqual(Token.kw_or, scanner.next().tok);
    try std.testing.expectEqual(Token.kw_not, scanner.next().tok);
}
