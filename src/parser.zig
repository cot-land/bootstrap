///! Recursive descent parser for cot.
///!
///! Maps to Go's cmd/compile/internal/syntax/parser.go
///! Uses precedence climbing for binary expressions.

const std = @import("std");
const token = @import("token.zig");
const source = @import("source.zig");
const scanner = @import("scanner.zig");
const errors = @import("errors.zig");
const ast = @import("ast.zig");

const Token = token.Token;
const Precedence = token.Precedence;
const Pos = source.Pos;
const Span = source.Span;
const Source = source.Source;
const Scanner = scanner.Scanner;
const TokenInfo = scanner.TokenInfo;
const ErrorReporter = errors.ErrorReporter;
const ErrorCode = errors.ErrorCode;

const Ast = ast.Ast;
const NodeIndex = ast.NodeIndex;
const null_node = ast.null_node;
const Expr = ast.Expr;
const Stmt = ast.Stmt;
const Decl = ast.Decl;

/// Parser error type.
pub const ParseError = error{OutOfMemory};

/// Parser state.
pub const Parser = struct {
    scanner: *Scanner,
    tok: TokenInfo,
    ast: *Ast,
    err: *ErrorReporter,
    allocator: std.mem.Allocator,

    /// Initialize parser.
    pub fn init(
        allocator: std.mem.Allocator,
        scan: *Scanner,
        tree: *Ast,
        reporter: *ErrorReporter,
    ) Parser {
        var p = Parser{
            .scanner = scan,
            .tok = undefined,
            .ast = tree,
            .err = reporter,
            .allocator = allocator,
        };
        // Prime the parser with the first token
        p.advance();
        return p;
    }

    // ========================================================================
    // Token handling
    // ========================================================================

    /// Advance to next token.
    fn advance(self: *Parser) void {
        self.tok = self.scanner.next();
    }

    /// Check if current token matches.
    fn check(self: *Parser, t: Token) bool {
        return self.tok.tok == t;
    }

    /// Check if next token (after current) matches, without consuming.
    fn peekCheck(self: *Parser, t: Token) bool {
        // Save scanner state
        const saved_pos = self.scanner.pos;
        const saved_ch = self.scanner.ch;
        const saved_tok = self.tok;

        // Advance to next token
        self.advance();
        const result = self.tok.tok == t;

        // Restore scanner state
        self.scanner.pos = saved_pos;
        self.scanner.ch = saved_ch;
        self.tok = saved_tok;

        return result;
    }

    /// Consume token if it matches, return true if consumed.
    fn match(self: *Parser, t: Token) bool {
        if (self.check(t)) {
            self.advance();
            return true;
        }
        return false;
    }

    /// Expect a token, report error if not found.
    fn expect(self: *Parser, t: Token) bool {
        if (self.check(t)) {
            self.advance();
            return true;
        }
        self.errorExpected(t);
        return false;
    }

    /// Report "expected X" error.
    fn errorExpected(self: *Parser, t: Token) void {
        const msg = switch (t) {
            .identifier => "expected identifier",
            .lparen => "expected '('",
            .rparen => "expected ')'",
            .lbrace => "expected '{'",
            .rbrace => "expected '}'",
            .lbracket => "expected '['",
            .rbracket => "expected ']'",
            .semicolon => "expected ';'",
            .colon => "expected ':'",
            .equal => "expected '='",
            .comma => "expected ','",
            else => "unexpected token",
        };
        self.err.errorAt(self.tok.span.start, msg);
    }

    /// Report a syntax error.
    fn syntaxError(self: *Parser, msg: []const u8) void {
        self.err.errorWithCode(self.tok.span.start, .E200, msg);
    }

    /// Get current position.
    fn pos(self: *Parser) Pos {
        return self.tok.span.start;
    }

    // ========================================================================
    // File parsing
    // ========================================================================

    /// Parse a complete file.
    pub fn parseFile(self: *Parser) !void {
        var decls = std.ArrayList(NodeIndex){ .items = &.{}, .capacity = 0 };
        defer decls.deinit(self.allocator);

        while (!self.check(.eof)) {
            if (try self.parseDecl()) |decl_idx| {
                try decls.append(self.allocator, decl_idx);
            } else {
                // Error recovery: skip to next declaration
                self.advance();
            }
        }

        self.ast.file = .{
            .filename = self.scanner.src.filename,
            .decls = try self.allocator.dupe(NodeIndex, decls.items),
            .span = Span.init(Pos.zero, self.tok.span.end),
        };
    }

    // ========================================================================
    // Declaration parsing
    // ========================================================================

    /// Parse a declaration.
    fn parseDecl(self: *Parser) !?NodeIndex {
        return switch (self.tok.tok) {
            .kw_fn => try self.parseFnDecl(),
            .kw_var, .kw_let => try self.parseVarDecl(),
            .kw_const => try self.parseConstDecl(),
            .kw_struct => try self.parseStructDecl(),
            // Note: enum parsing disabled until kw_enum is added to token.zig
            else => {
                self.syntaxError("expected declaration");
                return null;
            },
        };
    }

    /// Parse function declaration: fn name(params) type { body }
    fn parseFnDecl(self: *Parser) !?NodeIndex {
        const start = self.pos();
        self.advance(); // consume 'fn'

        // Function name
        if (!self.check(.identifier)) {
            self.err.errorWithCode(self.pos(), .E203, "expected function name");
            return null;
        }
        const name = self.tok.text;
        self.advance();

        // Parameters
        if (!self.expect(.lparen)) return null;
        const params = try self.parseFieldList(.rparen);
        if (!self.expect(.rparen)) return null;

        // Return type (optional)
        var return_type: ?NodeIndex = null;
        if (!self.check(.lbrace) and !self.check(.eof)) {
            return_type = try self.parseType();
        }

        // Body (optional for forward declarations)
        var body: ?NodeIndex = null;
        if (self.check(.lbrace)) {
            body = try self.parseBlock();
        }

        return try self.ast.addNode(.{
            .decl = .{
                .fn_decl = .{
                    .name = name,
                    .params = params,
                    .return_type = return_type,
                    .body = body,
                    .span = Span.init(start, self.tok.span.start),
                },
            },
        });
    }

    /// Parse var/let declaration: var name: type = value
    fn parseVarDecl(self: *Parser) !?NodeIndex {
        const start = self.pos();
        self.advance(); // consume 'var' or 'let'

        if (!self.check(.identifier)) {
            self.err.errorWithCode(self.pos(), .E203, "expected variable name");
            return null;
        }
        const name = self.tok.text;
        self.advance();

        // Type annotation (optional)
        var type_expr: ?NodeIndex = null;
        if (self.match(.colon)) {
            type_expr = try self.parseType();
        }

        // Initializer (optional)
        var value: ?NodeIndex = null;
        if (self.match(.equal)) {
            value = try self.parseExpr();
        }

        return try self.ast.addNode(.{
            .decl = .{
                .var_decl = .{
                    .name = name,
                    .type_expr = type_expr,
                    .value = value,
                    .span = Span.init(start, self.tok.span.start),
                },
            },
        });
    }

    /// Parse const declaration: const name: type = value
    fn parseConstDecl(self: *Parser) !?NodeIndex {
        const start = self.pos();
        self.advance(); // consume 'const'

        if (!self.check(.identifier)) {
            self.err.errorWithCode(self.pos(), .E203, "expected constant name");
            return null;
        }
        const name = self.tok.text;
        self.advance();

        // Type annotation (optional)
        var type_expr: ?NodeIndex = null;
        if (self.match(.colon)) {
            type_expr = try self.parseType();
        }

        // Initializer (required for const)
        if (!self.expect(.equal)) return null;
        const value = try self.parseExpr() orelse {
            self.err.errorWithCode(self.pos(), .E201, "expected expression");
            return null;
        };

        return try self.ast.addNode(.{
            .decl = .{
                .const_decl = .{
                    .name = name,
                    .type_expr = type_expr,
                    .value = value,
                    .span = Span.init(start, self.tok.span.start),
                },
            },
        });
    }

    /// Parse struct declaration: struct Name { fields }
    fn parseStructDecl(self: *Parser) !?NodeIndex {
        const start = self.pos();
        self.advance(); // consume 'struct'

        if (!self.check(.identifier)) {
            self.err.errorWithCode(self.pos(), .E203, "expected struct name");
            return null;
        }
        const name = self.tok.text;
        self.advance();

        if (!self.expect(.lbrace)) return null;
        const fields = try self.parseFieldList(.rbrace);
        if (!self.expect(.rbrace)) return null;

        return try self.ast.addNode(.{
            .decl = .{
                .struct_decl = .{
                    .name = name,
                    .fields = fields,
                    .span = Span.init(start, self.tok.span.start),
                },
            },
        });
    }

    /// Parse enum declaration: enum Name { variants }
    fn parseEnumDecl(self: *Parser) !?NodeIndex {
        const start = self.pos();
        self.advance(); // consume 'enum'

        if (!self.check(.identifier)) {
            self.err.errorWithCode(self.pos(), .E203, "expected enum name");
            return null;
        }
        const name = self.tok.text;
        self.advance();

        if (!self.expect(.lbrace)) return null;

        var variants = std.ArrayList(ast.EnumVariant){ .items = &.{}, .capacity = 0 };
        defer variants.deinit(self.allocator);

        while (!self.check(.rbrace) and !self.check(.eof)) {
            if (!self.check(.identifier)) {
                self.syntaxError("expected variant name");
                break;
            }
            const variant_name = self.tok.text;
            const variant_start = self.pos();
            self.advance();

            var value: ?NodeIndex = null;
            if (self.match(.equal)) {
                value = try self.parseExpr();
            }

            try variants.append(self.allocator, .{
                .name = variant_name,
                .value = value,
                .span = Span.init(variant_start, self.tok.span.start),
            });

            if (!self.match(.comma)) break;
        }

        if (!self.expect(.rbrace)) return null;

        return try self.ast.addNode(.{
            .decl = .{
                .enum_decl = .{
                    .name = name,
                    .variants = try self.allocator.dupe(ast.EnumVariant, variants.items),
                    .span = Span.init(start, self.tok.span.start),
                },
            },
        });
    }

    /// Parse field list (for struct fields and function parameters).
    fn parseFieldList(self: *Parser, end: Token) ![]const ast.Field {
        var fields = std.ArrayList(ast.Field){ .items = &.{}, .capacity = 0 };
        defer fields.deinit(self.allocator);

        while (!self.check(end) and !self.check(.eof)) {
            if (!self.check(.identifier)) break;

            const field_name = self.tok.text;
            const field_start = self.pos();
            self.advance();

            if (!self.expect(.colon)) break;

            const type_idx = try self.parseType() orelse break;

            try fields.append(self.allocator, .{
                .name = field_name,
                .type_expr = type_idx,
                .span = Span.init(field_start, self.tok.span.start),
            });

            if (!self.match(.comma)) break;
        }

        return try self.allocator.dupe(ast.Field, fields.items);
    }

    // ========================================================================
    // Type parsing
    // ========================================================================

    /// Parse a type expression.
    fn parseType(self: *Parser) !?NodeIndex {
        const start = self.pos();

        // Optional type: ?T
        if (self.match(.question)) {
            const inner = try self.parseType() orelse return null;
            return try self.ast.addNode(.{
                .expr = .{
                    .type_expr = .{
                        .kind = .{ .optional = inner },
                        .span = Span.init(start, self.tok.span.start),
                    },
                },
            });
        }

        // Pointer type: *T
        if (self.match(.star)) {
            const inner = try self.parseType() orelse return null;
            return try self.ast.addNode(.{
                .expr = .{
                    .type_expr = .{
                        .kind = .{ .pointer = inner },
                        .span = Span.init(start, self.tok.span.start),
                    },
                },
            });
        }

        // Slice type: []T or Array type: [N]T
        if (self.match(.lbracket)) {
            if (self.match(.rbracket)) {
                // Slice: []T
                const elem = try self.parseType() orelse return null;
                return try self.ast.addNode(.{
                    .expr = .{
                        .type_expr = .{
                            .kind = .{ .slice = elem },
                            .span = Span.init(start, self.tok.span.start),
                        },
                    },
                });
            } else {
                // Array: [N]T
                const size = try self.parseExpr() orelse return null;
                if (!self.expect(.rbracket)) return null;
                const elem = try self.parseType() orelse return null;
                return try self.ast.addNode(.{
                    .expr = .{
                        .type_expr = .{
                            .kind = .{ .array = .{ .size = size, .elem = elem } },
                            .span = Span.init(start, self.tok.span.start),
                        },
                    },
                });
            }
        }

        // Named type: identifier or type keyword
        if (self.check(.identifier) or isTypeKeyword(self.tok.tok)) {
            const name = if (self.check(.identifier)) self.tok.text else self.tok.tok.toString();
            self.advance();
            return try self.ast.addNode(.{
                .expr = .{
                    .type_expr = .{
                        .kind = .{ .named = name },
                        .span = Span.init(start, self.tok.span.start),
                    },
                },
            });
        }

        self.err.errorWithCode(self.pos(), .E202, "expected type");
        return null;
    }

    // ========================================================================
    // Expression parsing (precedence climbing)
    // ========================================================================

    /// Parse an expression.
    pub fn parseExpr(self: *Parser) ParseError!?NodeIndex {
        return self.parseBinaryExpr(0);
    }

    /// Parse binary expression with precedence climbing.
    fn parseBinaryExpr(self: *Parser, min_prec: u8) ParseError!?NodeIndex {
        var left = try self.parseUnaryExpr() orelse return null;

        while (true) {
            const op = self.tok.tok;
            const prec = token.binaryPrecedence(op);

            if (prec == .none or @intFromEnum(prec) <= min_prec) break;

            const op_start = self.pos();
            self.advance();

            const right = try self.parseBinaryExpr(@intFromEnum(prec)) orelse {
                self.err.errorWithCode(self.pos(), .E201, "expected expression");
                return null;
            };

            left = try self.ast.addNode(.{
                .expr = .{
                    .binary = .{
                        .op = op,
                        .left = left,
                        .right = right,
                        .span = Span.init(op_start, self.tok.span.start),
                    },
                },
            });
        }

        return left;
    }

    /// Parse unary expression.
    fn parseUnaryExpr(self: *Parser) ParseError!?NodeIndex {
        const start = self.pos();

        // Unary operators: -, !, not
        if (self.tok.tok == .minus or self.tok.tok == .bang or self.tok.tok == .kw_not) {
            const op = self.tok.tok;
            self.advance();
            const operand = try self.parseUnaryExpr() orelse return null;
            return try self.ast.addNode(.{
                .expr = .{
                    .unary = .{
                        .op = op,
                        .operand = operand,
                        .span = Span.init(start, self.tok.span.start),
                    },
                },
            });
        }

        return self.parsePrimaryExpr();
    }

    /// Parse primary expression (operand + postfix).
    fn parsePrimaryExpr(self: *Parser) ParseError!?NodeIndex {
        var expr = try self.parseOperand() orelse return null;

        // Postfix operators: ., [], ()
        while (true) {
            if (self.match(.dot)) {
                // Field access: expr.field
                if (!self.check(.identifier)) {
                    self.err.errorWithCode(self.pos(), .E203, "expected field name");
                    return null;
                }
                const field = self.tok.text;
                const field_end = self.tok.span.end;
                self.advance();

                const expr_span = self.ast.getNode(expr).span();
                expr = try self.ast.addNode(.{
                    .expr = .{
                        .field_access = .{
                            .base = expr,
                            .field = field,
                            .span = Span.init(expr_span.start, field_end),
                        },
                    },
                });
            } else if (self.match(.lbracket)) {
                // Index: expr[index] or Slice: expr[start:end]
                const expr_span = self.ast.getNode(expr).span();

                // Check for slice with no start: expr[:end] or expr[:]
                if (self.match(.colon)) {
                    // Slice from beginning
                    var slice_end: NodeIndex = ast.null_node;
                    if (!self.check(.rbracket)) {
                        slice_end = try self.parseExpr() orelse return null;
                    }
                    const end = self.tok.span.end;
                    if (!self.expect(.rbracket)) return null;

                    expr = try self.ast.addNode(.{
                        .expr = .{
                            .slice_expr = .{
                                .base = expr,
                                .start = ast.null_node,
                                .end = slice_end,
                                .span = Span.init(expr_span.start, end),
                            },
                        },
                    });
                } else {
                    // Parse start expression
                    const start_or_index = try self.parseExpr() orelse return null;

                    if (self.match(.colon)) {
                        // Slice: expr[start:end] or expr[start:]
                        var slice_end: NodeIndex = ast.null_node;
                        if (!self.check(.rbracket)) {
                            slice_end = try self.parseExpr() orelse return null;
                        }
                        const end = self.tok.span.end;
                        if (!self.expect(.rbracket)) return null;

                        expr = try self.ast.addNode(.{
                            .expr = .{
                                .slice_expr = .{
                                    .base = expr,
                                    .start = start_or_index,
                                    .end = slice_end,
                                    .span = Span.init(expr_span.start, end),
                                },
                            },
                        });
                    } else {
                        // Index: expr[index]
                        const end = self.tok.span.end;
                        if (!self.expect(.rbracket)) return null;

                        expr = try self.ast.addNode(.{
                            .expr = .{
                                .index = .{
                                    .base = expr,
                                    .index = start_or_index,
                                    .span = Span.init(expr_span.start, end),
                                },
                            },
                        });
                    }
                }
            } else if (self.match(.lparen)) {
                // Call: expr(args)
                var args = std.ArrayList(NodeIndex){ .items = &.{}, .capacity = 0 };
                defer args.deinit(self.allocator);

                while (!self.check(.rparen) and !self.check(.eof)) {
                    const arg = try self.parseExpr() orelse break;
                    try args.append(self.allocator, arg);
                    if (!self.match(.comma)) break;
                }

                const end = self.tok.span.end;
                if (!self.expect(.rparen)) return null;

                const expr_span = self.ast.getNode(expr).span();
                expr = try self.ast.addNode(.{
                    .expr = .{
                        .call = .{
                            .callee = expr,
                            .args = try self.allocator.dupe(NodeIndex, args.items),
                            .span = Span.init(expr_span.start, end),
                        },
                    },
                });
            } else if (self.check(.lbrace)) {
                // Struct literal: Type{ .field = value, ... }
                // Only valid after an identifier (type name) AND when content starts with '.'
                // If not an identifier, don't consume the '{' - it may be a block start
                const node = self.ast.getNode(expr);
                if (node != .expr or node.expr != .identifier) {
                    // Not a struct literal - leave '{' for caller (e.g., if/while block)
                    break;
                }
                // Peek ahead: struct literals must start with '.field' inside braces
                // If next after '{' is not '.', this is likely a block, not struct literal
                if (!self.peekCheck(.dot)) {
                    break;
                }
                self.advance(); // consume '{'
                const type_name = node.expr.identifier.name;

                var fields = std.ArrayList(ast.FieldInit){ .items = &.{}, .capacity = 0 };
                defer fields.deinit(self.allocator);

                while (!self.check(.rbrace) and !self.check(.eof)) {
                    // Parse .field = value
                    if (!self.expect(.dot)) return null;
                    if (!self.check(.identifier)) {
                        self.err.errorWithCode(self.pos(), .E203, "expected field name");
                        return null;
                    }
                    const field_name = self.tok.text;
                    const field_start = self.tok.span.start;
                    self.advance();

                    if (!self.expect(.equal)) return null;

                    const value = try self.parseExpr() orelse return null;
                    const field_end = self.ast.getNode(value).span().end;

                    try fields.append(self.allocator, .{
                        .name = field_name,
                        .value = value,
                        .span = Span.init(field_start, field_end),
                    });

                    if (!self.match(.comma)) break;
                }

                const end = self.tok.span.end;
                if (!self.expect(.rbrace)) return null;

                const expr_span = self.ast.getNode(expr).span();
                expr = try self.ast.addNode(.{
                    .expr = .{
                        .struct_init = .{
                            .type_name = type_name,
                            .fields = try self.allocator.dupe(ast.FieldInit, fields.items),
                            .span = Span.init(expr_span.start, end),
                        },
                    },
                });
            } else {
                break;
            }
        }

        return expr;
    }

    /// Parse operand (literals, identifiers, parenthesized expressions).
    fn parseOperand(self: *Parser) ParseError!?NodeIndex {
        const start = self.pos();

        switch (self.tok.tok) {
            .identifier => {
                const name = self.tok.text;
                self.advance();
                return try self.ast.addNode(.{
                    .expr = .{
                        .identifier = .{
                            .name = name,
                            .span = Span.init(start, self.tok.span.start),
                        },
                    },
                });
            },
            .int_literal => {
                const value = self.tok.text;
                self.advance();
                return try self.ast.addNode(.{
                    .expr = .{
                        .literal = .{
                            .kind = .int,
                            .value = value,
                            .span = Span.init(start, self.tok.span.start),
                        },
                    },
                });
            },
            .float_literal => {
                const value = self.tok.text;
                self.advance();
                return try self.ast.addNode(.{
                    .expr = .{
                        .literal = .{
                            .kind = .float,
                            .value = value,
                            .span = Span.init(start, self.tok.span.start),
                        },
                    },
                });
            },
            .string_literal => {
                const value = self.tok.text;
                self.advance();
                return try self.ast.addNode(.{
                    .expr = .{
                        .literal = .{
                            .kind = .string,
                            .value = value,
                            .span = Span.init(start, self.tok.span.start),
                        },
                    },
                });
            },
            .char_literal => {
                const value = self.tok.text;
                self.advance();
                return try self.ast.addNode(.{
                    .expr = .{
                        .literal = .{
                            .kind = .char,
                            .value = value,
                            .span = Span.init(start, self.tok.span.start),
                        },
                    },
                });
            },
            .kw_true => {
                self.advance();
                return try self.ast.addNode(.{
                    .expr = .{
                        .literal = .{
                            .kind = .true_lit,
                            .value = "true",
                            .span = Span.init(start, self.tok.span.start),
                        },
                    },
                });
            },
            .kw_false => {
                self.advance();
                return try self.ast.addNode(.{
                    .expr = .{
                        .literal = .{
                            .kind = .false_lit,
                            .value = "false",
                            .span = Span.init(start, self.tok.span.start),
                        },
                    },
                });
            },
            .kw_null => {
                self.advance();
                return try self.ast.addNode(.{
                    .expr = .{
                        .literal = .{
                            .kind = .null_lit,
                            .value = "null",
                            .span = Span.init(start, self.tok.span.start),
                        },
                    },
                });
            },
            .lparen => {
                self.advance();
                const inner = try self.parseExpr() orelse return null;
                const end = self.tok.span.end;
                if (!self.expect(.rparen)) return null;
                return try self.ast.addNode(.{
                    .expr = .{
                        .paren = .{
                            .inner = inner,
                            .span = Span.init(start, end),
                        },
                    },
                });
            },
            .kw_if => {
                return self.parseIfExpr();
            },
            .kw_switch => {
                return self.parseSwitchExpr();
            },
            .lbrace => {
                return self.parseBlock();
            },
            .lbracket => {
                // Array literal: [elem1, elem2, ...]
                self.advance(); // consume '['

                var elements = std.ArrayList(NodeIndex){ .items = &.{}, .capacity = 0 };
                defer elements.deinit(self.allocator);

                // Parse comma-separated elements
                while (!self.check(.rbracket) and !self.check(.eof)) {
                    const elem = try self.parseExpr() orelse break;
                    try elements.append(self.allocator, elem);
                    if (!self.match(.comma)) break;
                }

                const end = self.tok.span.end;
                if (!self.expect(.rbracket)) return null;

                return try self.ast.addNode(.{
                    .expr = .{
                        .array_literal = .{
                            .elements = try self.allocator.dupe(NodeIndex, elements.items),
                            .span = Span.init(start, end),
                        },
                    },
                });
            },
            else => {
                self.err.errorWithCode(self.pos(), .E201, "expected expression");
                return null;
            },
        }
    }

    /// Parse if expression: if cond { then } else { else }
    fn parseIfExpr(self: *Parser) ParseError!?NodeIndex {
        const start = self.pos();
        self.advance(); // consume 'if'

        const condition = try self.parseExpr() orelse return null;

        if (!self.check(.lbrace)) {
            self.err.errorWithCode(self.pos(), .E204, "expected '{' after if condition");
            return null;
        }
        const then_branch = try self.parseBlock() orelse return null;

        var else_branch: ?NodeIndex = null;
        if (self.match(.kw_else)) {
            if (self.check(.kw_if)) {
                else_branch = try self.parseIfExpr();
            } else if (self.check(.lbrace)) {
                else_branch = try self.parseBlock();
            } else {
                self.syntaxError("expected '{' or 'if' after 'else'");
                return null;
            }
        }

        return try self.ast.addNode(.{
            .expr = .{
                .if_expr = .{
                    .condition = condition,
                    .then_branch = then_branch,
                    .else_branch = else_branch,
                    .span = Span.init(start, self.tok.span.start),
                },
            },
        });
    }

    /// Parse switch expression: switch expr { cases }
    fn parseSwitchExpr(self: *Parser) ParseError!?NodeIndex {
        const start = self.pos();
        self.advance(); // consume 'switch'

        // Parse subject expression - just use parseOperand to avoid struct init ambiguity
        // For more complex expressions like a.b.c, we'd need lookahead or a different approach
        const subject = try self.parseOperand() orelse return null;

        // Expect opening brace
        if (!self.expect(.lbrace)) return null;

        var cases = std.ArrayList(ast.SwitchCase){ .items = &.{}, .capacity = 0 };
        defer cases.deinit(self.allocator);
        var else_body: ?NodeIndex = null;

        // Parse cases
        while (!self.check(.rbrace) and !self.check(.eof)) {
            const case_start = self.pos();

            // Check for else case
            if (self.match(.kw_else)) {
                if (!self.expect(.fat_arrow)) return null;
                else_body = try self.parseExpr() orelse return null;
                _ = self.match(.comma); // optional trailing comma
                continue;
            }

            // Parse case values (comma-separated)
            var values = std.ArrayList(NodeIndex){ .items = &.{}, .capacity = 0 };
            defer values.deinit(self.allocator);

            // Parse first value
            const first_val = try self.parseExpr() orelse return null;
            try values.append(self.allocator, first_val);

            // Parse additional comma-separated values
            while (self.check(.comma) and !self.check(.fat_arrow)) {
                self.advance(); // consume comma
                // Check if next is fat_arrow (end of values) or else
                if (self.check(.fat_arrow) or self.check(.kw_else)) break;
                const val = try self.parseExpr() orelse return null;
                try values.append(self.allocator, val);
            }

            // Expect =>
            if (!self.expect(.fat_arrow)) return null;

            // Parse body expression
            const body = try self.parseExpr() orelse return null;

            try cases.append(self.allocator, .{
                .values = try self.allocator.dupe(NodeIndex, values.items),
                .body = body,
                .span = Span.init(case_start, self.tok.span.end),
            });

            // Optional trailing comma
            _ = self.match(.comma);
        }

        const end = self.tok.span.end;
        if (!self.expect(.rbrace)) return null;

        return try self.ast.addNode(.{
            .expr = .{
                .switch_expr = .{
                    .subject = subject,
                    .cases = try self.allocator.dupe(ast.SwitchCase, cases.items),
                    .else_body = else_body,
                    .span = Span.init(start, end),
                },
            },
        });
    }

    // ========================================================================
    // Statement parsing
    // ========================================================================

    /// Parse a block: { statements }
    fn parseBlock(self: *Parser) ParseError!?NodeIndex {
        const start = self.pos();
        if (!self.expect(.lbrace)) return null;

        var stmts = std.ArrayList(NodeIndex){ .items = &.{}, .capacity = 0 };
        defer stmts.deinit(self.allocator);

        while (!self.check(.rbrace) and !self.check(.eof)) {
            if (try self.parseStmt()) |stmt_idx| {
                try stmts.append(self.allocator, stmt_idx);
            } else {
                // Error recovery: skip token
                self.advance();
            }
        }

        const end = self.tok.span.end;
        if (!self.expect(.rbrace)) return null;

        return try self.ast.addNode(.{
            .expr = .{
                .block = .{
                    .stmts = try self.allocator.dupe(NodeIndex, stmts.items),
                    .expr = null_node,
                    .span = Span.init(start, end),
                },
            },
        });
    }

    /// Parse a statement.
    fn parseStmt(self: *Parser) ParseError!?NodeIndex {
        const start = self.pos();

        switch (self.tok.tok) {
            .kw_return => {
                self.advance();
                var value: ?NodeIndex = null;
                if (!self.check(.rbrace) and !self.check(.semicolon)) {
                    value = try self.parseExpr();
                }
                _ = self.match(.semicolon);
                return try self.ast.addNode(.{
                    .stmt = .{
                        .return_stmt = .{
                            .value = value,
                            .span = Span.init(start, self.tok.span.start),
                        },
                    },
                });
            },
            .kw_var, .kw_let => {
                return self.parseVarStmt(false);
            },
            .kw_const => {
                return self.parseVarStmt(true);
            },
            .kw_if => {
                return self.parseIfStmt();
            },
            .kw_while => {
                return self.parseWhileStmt();
            },
            .kw_for => {
                return self.parseForStmt();
            },
            .kw_break => {
                self.advance();
                _ = self.match(.semicolon);
                return try self.ast.addNode(.{
                    .stmt = .{
                        .break_stmt = .{
                            .span = Span.init(start, self.tok.span.start),
                        },
                    },
                });
            },
            .kw_continue => {
                self.advance();
                _ = self.match(.semicolon);
                return try self.ast.addNode(.{
                    .stmt = .{
                        .continue_stmt = .{
                            .span = Span.init(start, self.tok.span.start),
                        },
                    },
                });
            },
            else => {
                // Expression statement or assignment
                const expr = try self.parseExpr() orelse return null;

                // Check for assignment
                if (self.tok.tok == .equal or isCompoundAssign(self.tok.tok)) {
                    const op: ?Token = if (self.tok.tok == .equal) null else self.tok.tok;
                    self.advance();
                    const value = try self.parseExpr() orelse return null;
                    _ = self.match(.semicolon);
                    return try self.ast.addNode(.{
                        .stmt = .{
                            .assign_stmt = .{
                                .target = expr,
                                .op = op,
                                .value = value,
                                .span = Span.init(start, self.tok.span.start),
                            },
                        },
                    });
                }

                _ = self.match(.semicolon);
                return try self.ast.addNode(.{
                    .stmt = .{
                        .expr_stmt = .{
                            .expr = expr,
                            .span = Span.init(start, self.tok.span.start),
                        },
                    },
                });
            },
        }
    }

    /// Parse var/let/const statement.
    fn parseVarStmt(self: *Parser, is_const: bool) ParseError!?NodeIndex {
        const start = self.pos();
        self.advance(); // consume var/let/const

        if (!self.check(.identifier)) {
            self.err.errorWithCode(self.pos(), .E203, "expected variable name");
            return null;
        }
        const name = self.tok.text;
        self.advance();

        var type_expr: ?NodeIndex = null;
        if (self.match(.colon)) {
            type_expr = try self.parseType();
        }

        var value: ?NodeIndex = null;
        if (self.match(.equal)) {
            value = try self.parseExpr();
        }

        _ = self.match(.semicolon);

        return try self.ast.addNode(.{
            .stmt = .{
                .var_stmt = .{
                    .name = name,
                    .type_expr = type_expr,
                    .value = value,
                    .is_const = is_const,
                    .span = Span.init(start, self.tok.span.start),
                },
            },
        });
    }

    /// Parse if statement.
    fn parseIfStmt(self: *Parser) ParseError!?NodeIndex {
        const start = self.pos();
        self.advance(); // consume 'if'

        const condition = try self.parseExpr() orelse return null;

        if (!self.check(.lbrace)) {
            self.err.errorWithCode(self.pos(), .E204, "expected '{' after if condition");
            return null;
        }
        const then_branch = try self.parseBlockStmt() orelse return null;

        var else_branch: ?NodeIndex = null;
        if (self.match(.kw_else)) {
            if (self.check(.kw_if)) {
                else_branch = try self.parseIfStmt();
            } else if (self.check(.lbrace)) {
                else_branch = try self.parseBlockStmt();
            } else {
                self.syntaxError("expected '{' or 'if' after 'else'");
                return null;
            }
        }

        return try self.ast.addNode(.{
            .stmt = .{
                .if_stmt = .{
                    .condition = condition,
                    .then_branch = then_branch,
                    .else_branch = else_branch,
                    .span = Span.init(start, self.tok.span.start),
                },
            },
        });
    }

    /// Parse while statement.
    fn parseWhileStmt(self: *Parser) ParseError!?NodeIndex {
        const start = self.pos();
        self.advance(); // consume 'while'

        const condition = try self.parseExpr() orelse return null;

        if (!self.check(.lbrace)) {
            self.err.errorWithCode(self.pos(), .E204, "expected '{' after while condition");
            return null;
        }
        const body = try self.parseBlockStmt() orelse return null;

        return try self.ast.addNode(.{
            .stmt = .{
                .while_stmt = .{
                    .condition = condition,
                    .body = body,
                    .span = Span.init(start, self.tok.span.start),
                },
            },
        });
    }

    /// Parse for statement: for x in iter { body }
    fn parseForStmt(self: *Parser) ParseError!?NodeIndex {
        const start = self.pos();
        self.advance(); // consume 'for'

        if (!self.check(.identifier)) {
            self.err.errorWithCode(self.pos(), .E203, "expected loop variable");
            return null;
        }
        const binding = self.tok.text;
        self.advance();

        if (!self.expect(.kw_in)) {
            self.syntaxError("expected 'in' in for loop");
            return null;
        }

        const iterable = try self.parseExpr() orelse return null;

        if (!self.check(.lbrace)) {
            self.err.errorWithCode(self.pos(), .E204, "expected '{' after for clause");
            return null;
        }
        const body = try self.parseBlockStmt() orelse return null;

        return try self.ast.addNode(.{
            .stmt = .{
                .for_stmt = .{
                    .binding = binding,
                    .iterable = iterable,
                    .body = body,
                    .span = Span.init(start, self.tok.span.start),
                },
            },
        });
    }

    /// Parse block as statement.
    fn parseBlockStmt(self: *Parser) ParseError!?NodeIndex {
        const start = self.pos();
        if (!self.expect(.lbrace)) return null;

        var stmts = std.ArrayList(NodeIndex){ .items = &.{}, .capacity = 0 };
        defer stmts.deinit(self.allocator);

        while (!self.check(.rbrace) and !self.check(.eof)) {
            if (try self.parseStmt()) |stmt_idx| {
                try stmts.append(self.allocator, stmt_idx);
            } else {
                self.advance();
            }
        }

        const end = self.tok.span.end;
        if (!self.expect(.rbrace)) return null;

        return try self.ast.addNode(.{
            .stmt = .{
                .block_stmt = .{
                    .stmts = try self.allocator.dupe(NodeIndex, stmts.items),
                    .span = Span.init(start, end),
                },
            },
        });
    }
};

/// Check if token is a type keyword (int, string, etc.)
fn isTypeKeyword(t: Token) bool {
    return switch (t) {
        .kw_int, .kw_float, .kw_bool, .kw_string, .kw_byte => true,
        .kw_decimal, .kw_alpha => true,
        .kw_i8, .kw_i16, .kw_i32, .kw_i64 => true,
        .kw_u8, .kw_u16, .kw_u32, .kw_u64 => true,
        .kw_f32, .kw_f64 => true,
        else => false,
    };
}

/// Check if token is a compound assignment operator.
fn isCompoundAssign(t: Token) bool {
    return switch (t) {
        .plus_equal, .minus_equal, .star_equal, .slash_equal, .percent_equal => true,
        .ampersand_equal, .pipe_equal, .caret_equal => true,
        else => false,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parser simple function" {
    const content = "fn main() { return 42 }";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var src = Source.init(alloc, "test.cot", content);
    var err_reporter = ErrorReporter.init(&src, null);
    var scan = Scanner.initWithErrors(&src, &err_reporter);
    var tree = Ast.init(alloc);

    var parser = Parser.init(alloc, &scan, &tree, &err_reporter);
    try parser.parseFile();

    try std.testing.expect(tree.file != null);
    try std.testing.expectEqual(@as(usize, 1), tree.file.?.decls.len);

    const decl = tree.getDecl(tree.file.?.decls[0]);
    try std.testing.expect(decl != null);
    try std.testing.expect(decl.? == .fn_decl);
    try std.testing.expectEqualStrings("main", decl.?.fn_decl.name);
}

test "parser variable declaration" {
    const content = "var x: int = 42";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var src = Source.init(alloc, "test.cot", content);
    var err_reporter = ErrorReporter.init(&src, null);
    var scan = Scanner.initWithErrors(&src, &err_reporter);
    var tree = Ast.init(alloc);

    var parser = Parser.init(alloc, &scan, &tree, &err_reporter);
    try parser.parseFile();

    try std.testing.expect(tree.file != null);
    try std.testing.expectEqual(@as(usize, 1), tree.file.?.decls.len);

    const decl = tree.getDecl(tree.file.?.decls[0]);
    try std.testing.expect(decl != null);
    try std.testing.expect(decl.? == .var_decl);
    try std.testing.expectEqualStrings("x", decl.?.var_decl.name);
}

test "parser binary expression" {
    const content = "var x = 1 + 2 * 3";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var src = Source.init(alloc, "test.cot", content);
    var err_reporter = ErrorReporter.init(&src, null);
    var scan = Scanner.initWithErrors(&src, &err_reporter);
    var tree = Ast.init(alloc);

    var parser = Parser.init(alloc, &scan, &tree, &err_reporter);
    try parser.parseFile();

    try std.testing.expect(tree.file != null);
    // Should parse as: 1 + (2 * 3) due to precedence
    const decl = tree.getDecl(tree.file.?.decls[0]);
    try std.testing.expect(decl != null);
    try std.testing.expect(decl.? == .var_decl);

    // The value should be a binary expression
    const value_idx = decl.?.var_decl.value.?;
    const value = tree.getExpr(value_idx);
    try std.testing.expect(value != null);
    try std.testing.expect(value.? == .binary);
    try std.testing.expectEqual(Token.plus, value.?.binary.op);
}

test "parser if statement" {
    const content = "fn test() i64 { if (1 == 1) { return 1; } else { return 2; } }";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var src = Source.init(alloc, "test.cot", content);
    var err_reporter = ErrorReporter.init(&src, null);
    var scan = Scanner.initWithErrors(&src, &err_reporter);
    var tree = Ast.init(alloc);

    var parser = Parser.init(alloc, &scan, &tree, &err_reporter);
    try parser.parseFile();

    try std.testing.expect(tree.file != null);
    try std.testing.expect(!err_reporter.hasErrors());
    try std.testing.expect(tree.file.?.decls.len > 0);
}

test "parser while loop" {
    const content = "fn test() i64 { var i: i64 = 0; while (i < 10) { i = i + 1; } return i; }";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var src = Source.init(alloc, "test.cot", content);
    var err_reporter = ErrorReporter.init(&src, null);
    var scan = Scanner.initWithErrors(&src, &err_reporter);
    var tree = Ast.init(alloc);

    var parser = Parser.init(alloc, &scan, &tree, &err_reporter);
    try parser.parseFile();

    try std.testing.expect(tree.file != null);
    try std.testing.expect(!err_reporter.hasErrors());
    try std.testing.expect(tree.file.?.decls.len > 0);
}

test "parser struct declaration" {
    const content = "struct Point { x: int, y: int }";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var src = Source.init(alloc, "test.cot", content);
    var err_reporter = ErrorReporter.init(&src, null);
    var scan = Scanner.initWithErrors(&src, &err_reporter);
    var tree = Ast.init(alloc);

    var parser = Parser.init(alloc, &scan, &tree, &err_reporter);
    try parser.parseFile();

    try std.testing.expect(tree.file != null);
    try std.testing.expect(!err_reporter.hasErrors());
    try std.testing.expect(tree.file.?.decls.len > 0);
    const decl = tree.getDecl(tree.file.?.decls[0]);
    try std.testing.expect(decl != null);
    try std.testing.expect(decl.? == .struct_decl);
    try std.testing.expectEqualStrings("Point", decl.?.struct_decl.name);
    try std.testing.expectEqual(@as(usize, 2), decl.?.struct_decl.fields.len);
}

test "parser error recovery" {
    const content = "fn () { }"; // missing function name
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var src = Source.init(alloc, "test.cot", content);
    var err_reporter = ErrorReporter.init(&src, null);
    var scan = Scanner.initWithErrors(&src, &err_reporter);
    var tree = Ast.init(alloc);

    var parser = Parser.init(alloc, &scan, &tree, &err_reporter);
    try parser.parseFile();

    // Should have reported an error
    try std.testing.expect(err_reporter.hasErrors());
}

test "parser switch expression" {
    const content = "fn test() i64 { var x: i64 = 2; return switch x { 1 => 10, 2 => 20, else => 0, }; }";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var src = Source.init(alloc, "test.cot", content);
    var err_reporter = ErrorReporter.init(&src, null);
    var scan = Scanner.initWithErrors(&src, &err_reporter);
    var tree = Ast.init(alloc);

    var parser = Parser.init(alloc, &scan, &tree, &err_reporter);
    try parser.parseFile();

    try std.testing.expect(tree.file != null);
    try std.testing.expect(!err_reporter.hasErrors());
    try std.testing.expect(tree.file.?.decls.len > 0);

    // Verify the function has a return statement with a switch expression
    const decl = tree.getDecl(tree.file.?.decls[0]);
    try std.testing.expect(decl != null);
    try std.testing.expect(decl.? == .fn_decl);
}

test "parser switch with multiple values per case" {
    const content = "fn test() i64 { var x: i64 = 2; return switch x { 1, 2, 3 => 10, 4, 5 => 20, else => 0, }; }";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var src = Source.init(alloc, "test.cot", content);
    var err_reporter = ErrorReporter.init(&src, null);
    var scan = Scanner.initWithErrors(&src, &err_reporter);
    var tree = Ast.init(alloc);

    var parser = Parser.init(alloc, &scan, &tree, &err_reporter);
    try parser.parseFile();

    try std.testing.expect(tree.file != null);
    try std.testing.expect(!err_reporter.hasErrors());
}

test "parser slice expression" {
    const content = "fn test() i64 { var arr = [10, 20, 30]; var s = arr[1:3]; return 0; }";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var src = Source.init(alloc, "test.cot", content);
    var err_reporter = ErrorReporter.init(&src, null);
    var scan = Scanner.initWithErrors(&src, &err_reporter);
    var tree = Ast.init(alloc);

    var parser = Parser.init(alloc, &scan, &tree, &err_reporter);
    try parser.parseFile();

    try std.testing.expect(tree.file != null);
    try std.testing.expect(!err_reporter.hasErrors());
}
