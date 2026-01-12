# Stage 2: Parsing (Syntactic Analysis)

**Files:** `src/parser.zig`, `src/ast.zig`

**Purpose:** Build a tree structure from tokens

---

## What is Parsing?

The scanner gave us a flat list of tokens:

```
[fn] [main] [(] [)] [{] [return] [42] [}]
```

But this doesn't show the **structure** of the code. The parser builds a tree called an **Abstract Syntax Tree (AST)** that shows how tokens relate to each other:

```
FnDecl
  ├── name: "main"
  ├── params: []
  ├── return_type: null
  └── body: Block
        └── ReturnStmt
              └── value: Literal(42)
```

Think of it like diagramming a sentence in English:

```
"The cat sat on the mat"

Sentence
├── Subject: "The cat"
│   ├── Article: "The"
│   └── Noun: "cat"
├── Verb: "sat"
└── PrepPhrase: "on the mat"
    ├── Prep: "on"
    └── Object: "the mat"
```

---

## Why Do We Need a Tree?

Consider this expression: `1 + 2 * 3`

The tokens are: `[1] [+] [2] [*] [3]`

But what does it mean? Two possibilities:

1. `(1 + 2) * 3 = 9`
2. `1 + (2 * 3) = 7`

The parser knows that `*` binds tighter than `+` (has higher precedence), so it builds:

```
      +
     / \
    1   *
       / \
      2   3
```

This tree clearly shows: do `2 * 3` first, then add `1`.

---

## The Parser Struct

```zig
pub const Parser = struct {
    scanner: *Scanner,         // Where we get tokens from
    tok: TokenInfo,            // Current token
    ast: *Ast,                 // The tree we're building
    err: *ErrorReporter,       // Where to report errors
    allocator: std.mem.Allocator,  // For allocating tree nodes
};
```

### Key Fields

**`scanner: *Scanner`** - Pointer to the scanner. We call `scanner.next()` to get tokens.

**`tok: TokenInfo`** - The current token we're looking at. Contains:
- `tok`: The token type (`.kw_fn`, `.identifier`, etc.)
- `span`: Where in the source it came from
- `text`: For identifiers/literals, the actual text

**`ast: *Ast`** - The tree we're building. We add nodes to it as we parse.

**`allocator`** - Memory allocator. The tree needs to store nodes, and that requires allocating memory.

---

## How Recursive Descent Works

The parser uses a technique called **recursive descent**. The idea:

1. Each grammar construct has a function that parses it
2. Functions call each other recursively to parse nested structures
3. We "descend" into the grammar

```
parseFile()
  └── parseDecl()        "What kind of declaration?"
        └── parseFnDecl()    "It's a function!"
              ├── parse name
              ├── parseFieldList() for params
              └── parseBlock()     "Parse the body"
                    └── parseStmt()
                          └── parseExpr()
                                └── parseLiteral()
```

### Example: Parsing `fn main() { return 42 }`

```
1. parseFile() is called
2. Current token: 'fn'
3. parseFile() calls parseDecl()
4. parseDecl() sees 'fn', calls parseFnDecl()
5. parseFnDecl():
   - Consumes 'fn'
   - Current token: 'main' (identifier) - save as name
   - Consume 'main'
   - Expect '(' - consume it
   - parseFieldList() - no params, returns []
   - Expect ')' - consume it
   - No return type before '{'
   - parseBlock():
     - Expect '{' - consume it
     - parseStmt():
       - Current token: 'return'
       - Consume 'return'
       - parseExpr():
         - Current token: '42' (int literal)
         - Return Literal node
       - Return ReturnStmt node
     - Current token: ';' - consume it
     - Current token: '}' - stop loop
     - Expect '}' - consume it
     - Return Block node
   - Return FnDecl node
6. parseFile() adds FnDecl to file.decls
7. Current token: EOF - stop loop
8. Return complete AST
```

---

## Token Handling Functions

### advance() - Get next token

```zig
fn advance(self: *Parser) void {
    self.tok = self.scanner.next();
}
```

Simple: ask the scanner for the next token.

### check() - Is current token X?

```zig
fn check(self: *Parser, t: Token) bool {
    return self.tok.tok == t;
}
```

Doesn't consume the token, just checks.

### match() - Consume if matches

```zig
fn match(self: *Parser, t: Token) bool {
    if (self.check(t)) {
        self.advance();
        return true;
    }
    return false;
}
```

If it matches, consume and return true. Otherwise, don't consume and return false.

### expect() - Must match or error

```zig
fn expect(self: *Parser, t: Token) bool {
    if (self.check(t)) {
        self.advance();
        return true;
    }
    self.errorExpected(t);
    return false;
}
```

Like match, but reports an error if it doesn't match.

---

## Parsing Declarations

A declaration is a top-level construct: function, variable, struct, etc.

```zig
fn parseDecl(self: *Parser) !?NodeIndex {
    return switch (self.tok.tok) {
        .kw_fn => try self.parseFnDecl(),
        .kw_var, .kw_let => try self.parseVarDecl(),
        .kw_const => try self.parseConstDecl(),
        .kw_struct => try self.parseStructDecl(),
        .kw_enum => try self.parseEnumDecl(),
        .kw_union => try self.parseUnionDecl(),
        .kw_type => try self.parseTypeAlias(),
        else => {
            self.syntaxError("expected declaration");
            return null;
        },
    };
}
```

Each keyword leads to a specific parsing function.

### Parsing a Function

```zig
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

    // Parameters: (a: i64, b: i64)
    if (!self.expect(.lparen)) return null;
    const params = try self.parseFieldList(.rparen);
    if (!self.expect(.rparen)) return null;

    // Return type (optional)
    var return_type: ?NodeIndex = null;
    if (!self.check(.lbrace) and !self.check(.eof)) {
        return_type = try self.parseType();
    }

    // Body
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
```

### Parsing a Struct

```zig
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
```

---

## Parsing Expressions: Precedence Climbing

Expressions are tricky because of operator precedence. We use **precedence climbing**:

```zig
pub fn parseExpr(self: *Parser) ParseError!?NodeIndex {
    return self.parseBinaryExpr(0);  // Start at precedence 0
}

fn parseBinaryExpr(self: *Parser, min_prec: u8) ParseError!?NodeIndex {
    // First, parse the left operand
    var left = try self.parseUnaryExpr() orelse return null;

    // Then, keep parsing binary operators
    while (true) {
        const op = self.tok.tok;
        const prec = token.binaryPrecedence(op);

        // Stop if operator has lower precedence than our minimum
        if (prec == .none or @intFromEnum(prec) <= min_prec) break;

        const op_start = self.pos();
        self.advance();  // Consume operator

        // Parse right side with HIGHER precedence requirement
        const right = try self.parseBinaryExpr(@intFromEnum(prec)) orelse {
            self.err.errorWithCode(self.pos(), .E201, "expected expression");
            return null;
        };

        // Build binary node
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
```

### How Precedence Climbing Works

For `1 + 2 * 3`:

```
1. parseBinaryExpr(0)
   - Parse left: Literal(1)
   - See '+' (precedence 5)
   - 5 > 0, so continue
   - Consume '+'
   - Recursively call parseBinaryExpr(5)
     - Parse left: Literal(2)
     - See '*' (precedence 6)
     - 6 > 5, so continue
     - Consume '*'
     - Recursively call parseBinaryExpr(6)
       - Parse left: Literal(3)
       - See EOF (precedence 0)
       - 0 <= 6, so stop
       - Return Literal(3)
     - Build: Binary(*, 2, 3)
     - See EOF (precedence 0)
     - 0 <= 5, so stop
     - Return Binary(*, 2, 3)
   - Build: Binary(+, 1, Binary(*, 2, 3))
   - See EOF (precedence 0)
   - 0 <= 0, so stop
   - Return final tree
```

Result:
```
    +
   / \
  1   *
     / \
    2   3
```

---

## Parsing Statements

Statements are things that do something but don't produce a value.

```zig
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
                    .break_stmt = .{ .span = Span.init(start, self.tok.span.start) },
                },
            });
        },
        else => {
            // Expression statement or assignment
            const expr = try self.parseExpr() orelse return null;

            // Check for assignment
            if (self.tok.tok == .equal or isCompoundAssign(self.tok.tok)) {
                const op = if (self.tok.tok == .equal) null else self.tok.tok;
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
                    .expr_stmt = .{ .expr = expr, ... },
                },
            });
        },
    }
}
```

### If Statement

```zig
fn parseIfStmt(self: *Parser) ParseError!?NodeIndex {
    const start = self.pos();
    self.advance(); // consume 'if'

    const condition = try self.parseExpr() orelse return null;

    // Then branch (block or single statement)
    const then_branch = if (self.check(.lbrace))
        try self.parseBlockStmt() orelse return null
    else
        try self.parseStmt() orelse return null;

    // Optional else branch
    var else_branch: ?NodeIndex = null;
    if (self.match(.kw_else)) {
        if (self.check(.kw_if)) {
            else_branch = try self.parseIfStmt();  // else if
        } else if (self.check(.lbrace)) {
            else_branch = try self.parseBlockStmt();
        } else {
            else_branch = try self.parseStmt();  // single statement
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
```

---

## Parsing Types

Types can be:
- Named: `i64`, `string`, `MyStruct`
- Pointer: `*i64`
- Optional: `?i64`
- Slice: `[]i64`
- Array: `[10]i64`
- Generic: `Map<string, i64>`, `List<i64>`

```zig
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

    // Slice or Array: []T or [N]T
    if (self.match(.lbracket)) {
        if (self.match(.rbracket)) {
            // Slice: []T
            const elem = try self.parseType() orelse return null;
            return try self.ast.addNode(.{
                .expr = .{
                    .type_expr = .{
                        .kind = .{ .slice = elem },
                        ...
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
                        ...
                    },
                },
            });
        }
    }

    // Named type (possibly generic)
    if (self.check(.identifier) or isTypeKeyword(self.tok.tok)) {
        const name = if (self.check(.identifier)) self.tok.text else self.tok.tok.toString();
        self.advance();

        // Check for generic: Map<K, V> or List<T>
        if (self.match(.less)) {
            if (std.mem.eql(u8, name, "Map")) {
                const key_type = try self.parseType() orelse return null;
                if (!self.expect(.comma)) return null;
                const value_type = try self.parseType() orelse return null;
                if (!self.expect(.greater)) return null;
                return try self.ast.addNode(.{
                    .expr = .{
                        .type_expr = .{
                            .kind = .{ .map = .{ .key = key_type, .value = value_type } },
                            ...
                        },
                    },
                });
            }
            // Similar for List<T>
        }

        return try self.ast.addNode(.{
            .expr = .{
                .type_expr = .{
                    .kind = .{ .named = name },
                    ...
                },
            },
        });
    }

    self.err.errorWithCode(self.pos(), .E202, "expected type");
    return null;
}
```

---

## Special Cases: Switch Expressions

Switch expressions are parsed specially because they have complex structure:

```cot
switch value {
    1, 2, 3 => "small"
    .ok |payload| => payload * 2
    else => "default"
}
```

```zig
fn parseSwitchExpr(self: *Parser) ParseError!?NodeIndex {
    const start = self.pos();
    self.advance(); // consume 'switch'

    const subject = try self.parseOperand() orelse return null;

    if (!self.expect(.lbrace)) return null;

    var cases = std.ArrayList(ast.SwitchCase){ .items = &.{}, .capacity = 0 };
    var else_body: ?NodeIndex = null;

    while (!self.check(.rbrace) and !self.check(.eof)) {
        // Check for else case
        if (self.match(.kw_else)) {
            if (!self.expect(.fat_arrow)) return null;
            else_body = try self.parseExpr() orelse return null;
            _ = self.match(.comma);
            continue;
        }

        // Parse case values
        var values = std.ArrayList(NodeIndex){ ... };
        const first_val = try self.parsePrimaryExpr() orelse return null;
        try values.append(self.allocator, first_val);

        // Additional comma-separated values
        while (self.check(.comma) and !self.check(.fat_arrow)) {
            self.advance();
            if (self.check(.fat_arrow) or self.check(.kw_else)) break;
            const val = try self.parsePrimaryExpr() orelse return null;
            try values.append(self.allocator, val);
        }

        // Optional payload capture: |val|
        var capture: ?[]const u8 = null;
        if (self.match(.pipe)) {
            if (self.check(.identifier)) {
                capture = self.tok.text;
                self.advance();
            }
            if (!self.expect(.pipe)) return null;
        }

        // Expect =>
        if (!self.expect(.fat_arrow)) return null;

        // Parse body
        const body = try self.parseExpr() orelse return null;

        try cases.append(self.allocator, .{
            .values = try self.allocator.dupe(NodeIndex, values.items),
            .body = body,
            .capture = capture,
            ...
        });

        _ = self.match(.comma);
    }

    if (!self.expect(.rbrace)) return null;

    return try self.ast.addNode(.{
        .expr = .{
            .switch_expr = .{
                .subject = subject,
                .cases = try self.allocator.dupe(ast.SwitchCase, cases.items),
                .else_body = else_body,
                ...
            },
        },
    });
}
```

---

## Error Handling and Recovery

When the parser encounters invalid syntax, it:

1. Reports an error with location
2. Tries to recover and continue parsing

```zig
fn errorExpected(self: *Parser, t: Token) void {
    const msg = switch (t) {
        .identifier => "expected identifier",
        .lparen => "expected '('",
        .rparen => "expected ')'",
        .lbrace => "expected '{'",
        .rbrace => "expected '}'",
        .semicolon => "expected ';'",
        else => "unexpected token",
    };
    self.err.errorAt(self.tok.span.start, msg);
}
```

Error recovery in `parseFile()`:

```zig
while (!self.check(.eof)) {
    if (try self.parseDecl()) |decl_idx| {
        try decls.append(self.allocator, decl_idx);
    } else {
        // Error recovery: skip to next declaration
        self.advance();
    }
}
```

If parsing a declaration fails, we skip the current token and try again. This allows reporting multiple errors.

---

## The AST Node Types

The parser creates various node types (defined in `ast.zig`):

### Declarations

```zig
pub const Decl = union(enum) {
    fn_decl: struct {
        name: []const u8,
        params: []const Field,
        return_type: ?NodeIndex,
        body: ?NodeIndex,
        span: Span,
    },
    var_decl: struct {
        name: []const u8,
        type_expr: ?NodeIndex,
        value: ?NodeIndex,
        span: Span,
    },
    struct_decl: struct {
        name: []const u8,
        fields: []const Field,
        span: Span,
    },
    enum_decl: struct {
        name: []const u8,
        backing_type: ?NodeIndex,
        variants: []const EnumVariant,
        span: Span,
    },
    // ... more
};
```

### Expressions

```zig
pub const Expr = union(enum) {
    literal: struct {
        kind: LiteralKind,
        value: []const u8,
        span: Span,
    },
    identifier: struct {
        name: []const u8,
        span: Span,
    },
    binary: struct {
        op: Token,
        left: NodeIndex,
        right: NodeIndex,
        span: Span,
    },
    unary: struct {
        op: Token,
        operand: NodeIndex,
        span: Span,
    },
    call: struct {
        callee: NodeIndex,
        args: []const NodeIndex,
        span: Span,
    },
    // ... many more
};
```

### Statements

```zig
pub const Stmt = union(enum) {
    return_stmt: struct {
        value: ?NodeIndex,
        span: Span,
    },
    if_stmt: struct {
        condition: NodeIndex,
        then_branch: NodeIndex,
        else_branch: ?NodeIndex,
        span: Span,
    },
    while_stmt: struct {
        condition: NodeIndex,
        body: NodeIndex,
        span: Span,
    },
    for_stmt: struct {
        binding: []const u8,
        iterable: NodeIndex,
        body: NodeIndex,
        span: Span,
    },
    // ... more
};
```

---

## Complete Example: Parsing Real Code

Let's trace parsing:

```cot
fn add(a: i64, b: i64) i64 {
    return a + b
}
```

```
1. parseFile() starts
2. Token: 'fn' -> parseDecl() -> parseFnDecl()
3. parseFnDecl():
   - Consume 'fn'
   - Name: "add"
   - Consume '('
   - parseFieldList():
     - Field 1: name="a", type=named("i64")
     - Consume ','
     - Field 2: name="b", type=named("i64")
   - Consume ')'
   - parseType(): named("i64") -> return_type
   - parseBlock():
     - Consume '{'
     - parseStmt():
       - Token: 'return'
       - Consume 'return'
       - parseExpr() -> parseBinaryExpr(0):
         - parseUnaryExpr() -> parseOperand():
           - identifier("a")
         - Token: '+' (prec 5)
         - Consume '+'
         - parseBinaryExpr(5):
           - parseOperand(): identifier("b")
           - Token: ';' (prec 0)
           - Stop
         - Build: Binary(+, a, b)
       - Build: ReturnStmt(Binary(+, a, b))
     - Consume ';'
     - Token: '}'
     - Consume '}'
   - Build: Block([ReturnStmt])
   - Build: FnDecl(add, [a:i64, b:i64], i64, Block)
4. Token: EOF -> stop
```

Result AST:
```
File
└── FnDecl
    ├── name: "add"
    ├── params:
    │   ├── Field(a, i64)
    │   └── Field(b, i64)
    ├── return_type: Named("i64")
    └── body: Block
          └── ReturnStmt
                └── Binary(+)
                      ├── Identifier("a")
                      └── Identifier("b")
```

---

## Key Takeaways

1. **Recursive descent** maps grammar rules to functions that call each other.

2. **Precedence climbing** handles operator precedence by requiring higher precedence for nested operators.

3. **The AST captures structure** that was implicit in the token stream.

4. **Error recovery** allows reporting multiple errors instead of stopping at the first one.

5. **NodeIndex** references nodes in the tree, allowing the tree to be stored in a contiguous array.

---

## Next Steps

The parser built a tree, but it hasn't checked whether the code makes sense. The next stage, **type checking**, will verify that:
- Variables are declared before use
- Types are compatible in operations
- Functions are called with the right arguments

See: [12_TYPE_CHECKING.md](12_TYPE_CHECKING.md)
