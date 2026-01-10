///! Token definitions for cot.
///!
///! Maps to Go's cmd/compile/internal/syntax/tokens.go
///! Uses Zig enums instead of Go's iota constants.

const std = @import("std");

/// Token represents a lexical token in the cot language.
pub const Token = enum(u8) {
    // Special tokens
    eof,
    invalid,

    // Literals and identifiers
    identifier, // variable names, function names
    int_literal, // 123, 0xFF
    float_literal, // 3.14, 1e10
    string_literal, // "hello" (non-interpolated)
    string_interp_start, // "text ${ (start of interpolated string)
    string_interp_mid, // } text ${ (middle part between interpolations)
    string_interp_end, // } text" (end of interpolated string)
    char_literal, // 'a'

    // Operators (single char)
    plus, // +
    minus, // -
    star, // *
    slash, // /
    percent, // %
    ampersand, // &
    pipe, // |
    caret, // ^
    tilde, // ~
    bang, // !
    equal, // =
    less, // <
    greater, // >
    dot, // .
    question, // ?
    at, // @

    // Operators (multi char)
    plus_equal, // +=
    minus_equal, // -=
    star_equal, // *=
    slash_equal, // /=
    percent_equal, // %=
    ampersand_equal, // &=
    pipe_equal, // |=
    caret_equal, // ^=
    equal_equal, // ==
    bang_equal, // !=
    less_equal, // <=
    greater_equal, // >=
    less_less, // <<
    greater_greater, // >>
    dot_dot, // ..
    dot_star, // .*
    question_question, // ??
    question_dot, // ?.
    arrow, // ->
    fat_arrow, // =>

    // Delimiters
    lparen, // (
    rparen, // )
    lbracket, // [
    rbracket, // ]
    lbrace, // {
    rbrace, // }
    comma, // ,
    colon, // :
    semicolon, // ;

    // Keywords
    kw_fn,
    kw_var,
    kw_let,
    kw_const,
    kw_struct,
    kw_enum,
    kw_union,
    kw_if,
    kw_else,
    kw_switch,
    kw_while,
    kw_for,
    kw_in,
    kw_return,
    kw_break,
    kw_continue,
    kw_defer,
    kw_import,
    kw_new,
    kw_null,
    kw_true,
    kw_false,

    // Logical operators as keywords (cot-specific)
    kw_and,
    kw_or,
    kw_not,

    // Type keywords
    kw_int,
    kw_float,
    kw_bool,
    kw_string,
    kw_byte,
    kw_decimal,
    kw_alpha,

    // Sized type keywords
    kw_i8,
    kw_i16,
    kw_i32,
    kw_i64,
    kw_u8,
    kw_u16,
    kw_u32,
    kw_u64,
    kw_f32,
    kw_f64,

    /// Returns the string representation of this token.
    pub fn toString(self: Token) []const u8 {
        return switch (self) {
            .eof => "EOF",
            .invalid => "invalid",
            .identifier => "identifier",
            .int_literal => "integer",
            .float_literal => "float",
            .string_literal => "string",
            .string_interp_start => "string_interp_start",
            .string_interp_mid => "string_interp_mid",
            .string_interp_end => "string_interp_end",
            .char_literal => "char",
            .plus => "+",
            .minus => "-",
            .star => "*",
            .slash => "/",
            .percent => "%",
            .ampersand => "&",
            .pipe => "|",
            .caret => "^",
            .tilde => "~",
            .bang => "!",
            .equal => "=",
            .less => "<",
            .greater => ">",
            .dot => ".",
            .question => "?",
            .at => "@",
            .plus_equal => "+=",
            .minus_equal => "-=",
            .star_equal => "*=",
            .slash_equal => "/=",
            .percent_equal => "%=",
            .ampersand_equal => "&=",
            .pipe_equal => "|=",
            .caret_equal => "^=",
            .equal_equal => "==",
            .bang_equal => "!=",
            .less_equal => "<=",
            .greater_equal => ">=",
            .less_less => "<<",
            .greater_greater => ">>",
            .dot_dot => "..",
            .dot_star => ".*",
            .question_question => "??",
            .question_dot => "?.",
            .arrow => "->",
            .fat_arrow => "=>",
            .lparen => "(",
            .rparen => ")",
            .lbracket => "[",
            .rbracket => "]",
            .lbrace => "{",
            .rbrace => "}",
            .comma => ",",
            .colon => ":",
            .semicolon => ";",
            .kw_fn => "fn",
            .kw_var => "var",
            .kw_let => "let",
            .kw_const => "const",
            .kw_struct => "struct",
            .kw_enum => "enum",
            .kw_union => "union",
            .kw_if => "if",
            .kw_else => "else",
            .kw_switch => "switch",
            .kw_while => "while",
            .kw_for => "for",
            .kw_in => "in",
            .kw_return => "return",
            .kw_break => "break",
            .kw_continue => "continue",
            .kw_defer => "defer",
            .kw_import => "import",
            .kw_new => "new",
            .kw_null => "null",
            .kw_true => "true",
            .kw_false => "false",
            .kw_and => "and",
            .kw_or => "or",
            .kw_not => "not",
            .kw_int => "int",
            .kw_float => "float",
            .kw_bool => "bool",
            .kw_string => "string",
            .kw_byte => "byte",
            .kw_decimal => "decimal",
            .kw_alpha => "alpha",
            .kw_i8 => "i8",
            .kw_i16 => "i16",
            .kw_i32 => "i32",
            .kw_i64 => "i64",
            .kw_u8 => "u8",
            .kw_u16 => "u16",
            .kw_u32 => "u32",
            .kw_u64 => "u64",
            .kw_f32 => "f32",
            .kw_f64 => "f64",
        };
    }

    /// Returns true if this token is a keyword.
    pub fn isKeyword(self: Token) bool {
        return @intFromEnum(self) >= @intFromEnum(Token.kw_fn);
    }
};

/// Keyword lookup table using compile-time string map.
pub const keywords = std.StaticStringMap(Token).initComptime(.{
    .{ "fn", .kw_fn },
    .{ "var", .kw_var },
    .{ "let", .kw_let },
    .{ "const", .kw_const },
    .{ "struct", .kw_struct },
    .{ "enum", .kw_enum },
    .{ "union", .kw_union },
    .{ "if", .kw_if },
    .{ "else", .kw_else },
    .{ "switch", .kw_switch },
    .{ "while", .kw_while },
    .{ "for", .kw_for },
    .{ "in", .kw_in },
    .{ "return", .kw_return },
    .{ "break", .kw_break },
    .{ "continue", .kw_continue },
    .{ "defer", .kw_defer },
    .{ "import", .kw_import },
    .{ "new", .kw_new },
    .{ "null", .kw_null },
    .{ "true", .kw_true },
    .{ "false", .kw_false },
    .{ "and", .kw_and },
    .{ "or", .kw_or },
    .{ "not", .kw_not },
    .{ "int", .kw_int },
    .{ "float", .kw_float },
    .{ "bool", .kw_bool },
    .{ "string", .kw_string },
    .{ "byte", .kw_byte },
    .{ "decimal", .kw_decimal },
    .{ "alpha", .kw_alpha },
    .{ "i8", .kw_i8 },
    .{ "i16", .kw_i16 },
    .{ "i32", .kw_i32 },
    .{ "i64", .kw_i64 },
    .{ "u8", .kw_u8 },
    .{ "u16", .kw_u16 },
    .{ "u32", .kw_u32 },
    .{ "u64", .kw_u64 },
    .{ "f32", .kw_f32 },
    .{ "f64", .kw_f64 },
});

/// Operator precedence levels (higher = binds tighter).
/// Follows Go's precedence but with cot's keyword operators.
pub const Precedence = enum(u8) {
    none = 0,
    or_prec = 1, // or
    and_prec = 2, // and
    compare = 3, // == != < <= > >=
    add = 4, // + - | ^
    mul = 5, // * / % & << >>
    unary = 6, // not ! - ~ & *
};

/// Returns the binary operator precedence for a token.
pub fn binaryPrecedence(tok: Token) Precedence {
    return switch (tok) {
        .kw_or => .or_prec,
        .kw_and => .and_prec,
        .equal_equal, .bang_equal, .less, .less_equal, .greater, .greater_equal => .compare,
        .plus, .minus, .pipe, .caret => .add,
        .star, .slash, .percent, .ampersand, .less_less, .greater_greater => .mul,
        else => .none,
    };
}

// Tests
test "keyword lookup" {
    try std.testing.expectEqual(Token.kw_fn, keywords.get("fn").?);
    try std.testing.expectEqual(Token.kw_var, keywords.get("var").?);
    try std.testing.expectEqual(Token.kw_and, keywords.get("and").?);
    try std.testing.expect(keywords.get("notakeyword") == null);
}

test "token toString" {
    try std.testing.expectEqualStrings("+", Token.plus.toString());
    try std.testing.expectEqualStrings("fn", Token.kw_fn.toString());
    try std.testing.expectEqualStrings("==", Token.equal_equal.toString());
}

test "isKeyword" {
    try std.testing.expect(Token.kw_fn.isKeyword());
    try std.testing.expect(Token.kw_and.isKeyword());
    try std.testing.expect(!Token.plus.isKeyword());
    try std.testing.expect(!Token.identifier.isKeyword());
}

test "precedence" {
    try std.testing.expectEqual(Precedence.mul, binaryPrecedence(.star));
    try std.testing.expectEqual(Precedence.add, binaryPrecedence(.plus));
    try std.testing.expectEqual(Precedence.compare, binaryPrecedence(.equal_equal));
    try std.testing.expectEqual(Precedence.none, binaryPrecedence(.lparen));
}
