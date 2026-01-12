# Stage 1: Scanning (Lexical Analysis)

**Files:** `src/scanner.zig`, `src/token.zig`, `src/source.zig`

**Purpose:** Break source code into tokens (meaningful chunks)

---

## What is Scanning?

When you write code like `fn main() { return 42; }`, the computer sees it as a long string of characters:

```
f n   m a i n ( )   {   r e t u r n   4 2 ;   }
```

The scanner's job is to group these characters into **tokens** - the smallest meaningful units of the language:

```
[fn] [main] [(] [)] [{] [return] [42] [;] [}]
```

Think of it like reading English: you don't read letter-by-letter, you recognize whole words and punctuation.

---

## The Token Type

A token represents a single "word" or "symbol" in your code. In `src/token.zig`:

```zig
/// Token represents a lexical token in the cot language.
pub const Token = enum(u8) {
    // Special tokens
    eof,           // End of file
    invalid,       // Something we don't recognize

    // Literals and identifiers
    identifier,    // variable names, function names
    int_literal,   // 123, 0xFF
    float_literal, // 3.14, 1e10
    string_literal,// "hello"
    char_literal,  // 'a'

    // Operators
    plus,          // +
    minus,         // -
    star,          // *
    equal_equal,   // ==
    // ... many more

    // Keywords
    kw_fn,         // fn
    kw_var,        // var
    kw_return,     // return
    // ... many more
};
```

### Why an enum?

In Zig (and Cot), an enum is a type with a fixed set of possible values. Each token can only be ONE of these options. The computer stores it as a single byte (`u8`), but we write meaningful names like `kw_fn` instead of magic numbers.

```
Token Value:       .kw_fn     .identifier    .int_literal
Stored as byte:      77           15              16
Human reads:       "fn"        "main"           "42"
```

---

## The Scanner Struct

The scanner holds its state as it moves through the source code:

```zig
pub const Scanner = struct {
    src: *Source,          // The source code we're scanning
    pos: Pos,              // Where we are in the source
    ch: ?u8,               // Current character (or null if at end)
    err: ?*ErrorReporter,  // Optional error reporter

    // For interpolated strings like "Hello ${name}!"
    in_interp_string: bool,
    interp_brace_depth: u32,
};
```

### Understanding the Fields

**`src: *Source`** - A pointer to the source code. The `*` means pointer - it's a memory address where the source lives, not a copy of it.

**`pos: Pos`** - Current position. Tracks:
- `offset`: byte position in the file (0, 1, 2, ...)
- `line`: line number (1, 2, 3, ...)
- `col`: column number (1, 2, 3, ...)

**`ch: ?u8`** - The current character. The `?` makes it optional - it can be a character OR null (if we've reached the end of the file). `u8` means an 8-bit unsigned integer, which is how computers store ASCII characters.

---

## How Scanning Works: The `next()` Function

The main function is `next()` which returns the next token:

```zig
pub fn next(self: *Scanner) TokenInfo {
    // 1. Skip whitespace and comments
    self.skipWhitespaceAndComments();

    const start = self.pos;  // Remember where we started

    // 2. Check for end of file
    if (self.ch == null) {
        return .{
            .tok = .eof,
            .span = Span.fromPos(start),
            .text = "",
        };
    }

    const c = self.ch.?;  // Get the character (.? unwraps the optional)

    // 3. Identify what kind of token this starts
    if (isAlpha(c) or c == '_') {
        return self.scanIdentifier(start);  // word like "main" or "fn"
    }
    if (isDigit(c)) {
        return self.scanNumber(start);      // number like "42" or "3.14"
    }
    if (c == '"') {
        return self.scanString(start);      // string like "hello"
    }
    if (c == '\'') {
        return self.scanChar(start);        // char like 'a'
    }

    // 4. Must be an operator or delimiter
    return self.scanOperator(start);
}
```

### The Decision Tree

```
                    Current Character
                           |
            +--------------+---------------+
            |              |               |
         letter         digit            other
         or '_'                           |
            |              |        +-----+-----+
            v              v        |     |     |
         scanIdentifier  scanNumber  "    '    operator
                                     |     |     |
                                     v     v     v
                                  string  char  scanOperator
```

---

## Scanning Identifiers and Keywords

An identifier is a name like `main`, `foo`, or `myVariable`. Keywords are special reserved names like `fn`, `return`, `if`.

```zig
fn scanIdentifier(self: *Scanner, start: Pos) TokenInfo {
    // Keep advancing while we see letters, digits, or underscore
    while (self.ch) |c| {
        if (isAlphaNumeric(c) or c == '_') {
            self.advance();
        } else {
            break;
        }
    }

    // Extract the text we scanned
    const text = self.src.content[start.offset..self.pos.offset];

    // Check if it's a keyword
    if (token.keywords.get(text)) |kw| {
        return .{
            .tok = kw,           // It's a keyword like .kw_fn
            .span = Span.init(start, self.pos),
            .text = "",          // Keywords don't need text
        };
    }

    // Not a keyword, it's a regular identifier
    return .{
        .tok = .identifier,
        .span = Span.init(start, self.pos),
        .text = text,            // Keep the name for later
    };
}
```

### The Keyword Lookup

Keywords are checked using a compile-time hash map:

```zig
pub const keywords = std.StaticStringMap(Token).initComptime(.{
    .{ "fn", .kw_fn },
    .{ "var", .kw_var },
    .{ "return", .kw_return },
    .{ "if", .kw_if },
    .{ "else", .kw_else },
    // ... more keywords
});
```

This map is built at **compile time** (when the Zig compiler runs), so keyword lookup is extremely fast at runtime - just a hash table lookup.

---

## Scanning Numbers

Numbers can be:
- Decimal: `42`, `1_000_000` (underscores for readability)
- Hexadecimal: `0xFF`, `0x1A2B`
- Octal: `0o755`
- Binary: `0b1010`
- Float: `3.14`, `1e10`

```zig
fn scanNumber(self: *Scanner, start: Pos) TokenInfo {
    var is_float = false;

    // Check for prefix (0x, 0o, 0b)
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

    // Fractional part?
    if (self.ch == '.' and self.peek(1) != '.') {
        is_float = true;
        self.advance();
        self.scanDecimalDigits();
    }

    // Exponent?
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
```

### Why check `self.peek(1) != '.'`?

The scanner needs to distinguish between:
- `3.14` - a float literal (has fractional part)
- `0..10` - a range expression (two dots)

When we see a `.` after digits, we peek ahead one character. If the next char is also `.`, it's a range, not a float.

---

## Scanning Operators

Operators can be one or two characters:

| Single | Double | Meaning |
|--------|--------|---------|
| `+` | `+=` | add, add-assign |
| `-` | `-=`, `->` | subtract, subtract-assign, arrow |
| `=` | `==`, `=>` | assign, equal, fat arrow |
| `<` | `<=`, `<<` | less, less-equal, shift left |
| `.` | `..`, `.?` | dot, range, optional unwrap |

```zig
fn scanOperator(self: *Scanner, start: Pos) TokenInfo {
    const c = self.ch.?;
    self.advance();  // Consume first character

    const tok: Token = switch (c) {
        '(' => .lparen,
        ')' => .rparen,
        '{' => .lbrace,
        '}' => .rbrace,
        // ... simple single-char operators

        '+' => if (self.ch == '=') blk: {
            self.advance();      // Consume second char
            break :blk .plus_equal;
        } else .plus,

        '.' => if (self.ch == '.') blk: {
            self.advance();
            break :blk .dot_dot;  // Range operator
        } else if (self.ch == '?') blk: {
            self.advance();
            break :blk .dot_question;  // Optional unwrap
        } else .dot,

        else => .invalid,
    };

    return .{ .tok = tok, .span = Span.init(start, self.pos), .text = "" };
}
```

### Understanding `blk: { ... break :blk value; }`

This is a Zig-specific pattern called a **labeled block**. It lets you compute a value across multiple statements:

```zig
// This won't work:
'+' => if (self.ch == '=') {
    self.advance();    // Can't return from here...
    .plus_equal        // Syntax error!
} else .plus,

// This works - labeled block:
'+' => if (self.ch == '=') blk: {
    self.advance();
    break :blk .plus_equal;  // Break out of block with this value
} else .plus,
```

The `blk:` labels the block, and `break :blk value` exits the block and uses `value` as its result.

---

## String Interpolation

Cot supports string interpolation like `"Hello ${name}!"`. The scanner needs to handle this specially:

```cot
var msg = "Hello ${name}!";
```

This produces these tokens:
1. `string_interp_start` - `"Hello ${`
2. `identifier` - `name`
3. `string_interp_end` - `}!"`

For nested interpolation like `"a ${b + "${c}"}d"`:
1. `string_interp_start` - `"a ${`
2. `identifier` - `b`
3. `plus` - `+`
4. `string_interp_start` - `"${`
5. `identifier` - `c`
6. `string_interp_end` - `}"`
7. `string_interp_end` - `}d"`

The scanner tracks `interp_brace_depth` to know when we're back to string content:

```zig
if (c == '}' and self.in_interp_string) {
    self.interp_brace_depth -= 1;
    if (self.interp_brace_depth == 0) {
        // End of interpolated expression - continue scanning string
        return self.scanStringContinuation(start);
    }
    // Still in nested braces
    return .{ .tok = .rbrace, ... };
}
```

---

## Skipping Whitespace and Comments

Before each token, we skip:
- Spaces, tabs, newlines
- Line comments: `// comment until end of line`
- Block comments: `/* comment spanning multiple lines */`

```zig
fn skipWhitespaceAndComments(self: *Scanner) void {
    while (self.ch) |c| {
        if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
            self.advance();
        } else if (c == '/') {
            if (self.peek(1) == '/') {
                self.skipLineComment();
            } else if (self.peek(1) == '*') {
                self.skipBlockComment();
            } else {
                break;  // Just a division operator
            }
        } else {
            break;  // Found a real token
        }
    }
}
```

---

## Helper Functions

### advance() - Move to next character

```zig
fn advance(self: *Scanner) void {
    self.pos = self.pos.advance(1);
    self.ch = self.src.at(self.pos);
}
```

### peek(n) - Look ahead without advancing

```zig
fn peek(self: *Scanner, n: u32) ?u8 {
    return self.src.at(self.pos.advance(n));
}
```

### Character classification

```zig
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
```

---

## Token Precedence

When parsing expressions like `1 + 2 * 3`, we need to know which operators bind tighter. This is called **precedence**:

```zig
pub const Precedence = enum(u8) {
    none = 0,
    coalesce = 1,   // ?? (null coalescing, lowest)
    or_prec = 2,    // or
    and_prec = 3,   // and
    compare = 4,    // == != < <= > >=
    add = 5,        // + - | ^
    mul = 6,        // * / % & << >>
    unary = 7,      // not ! - ~ & * (highest)
};
```

Higher number = tighter binding. So `*` binds tighter than `+`:
- `1 + 2 * 3` = `1 + (2 * 3)` = 7

The precedence lookup:

```zig
pub fn binaryPrecedence(tok: Token) Precedence {
    return switch (tok) {
        .question_question => .coalesce,
        .kw_or => .or_prec,
        .kw_and => .and_prec,
        .equal_equal, .bang_equal, .less, .less_equal, .greater, .greater_equal => .compare,
        .plus, .minus, .pipe, .caret => .add,
        .star, .slash, .percent, .ampersand, .less_less, .greater_greater => .mul,
        else => .none,
    };
}
```

---

## Complete Example: Scanning Real Code

Let's trace through scanning `fn add(a: i64, b: i64) i64 { return a + b; }`:

| Position | Character | Action | Token |
|----------|-----------|--------|-------|
| 0 | `f` | Start identifier | - |
| 1 | `n` | Continue identifier | - |
| 2 | ` ` | End identifier, keyword lookup | `kw_fn` |
| 3 | `a` | Start identifier | - |
| 4 | `d` | Continue identifier | - |
| 5 | `d` | Continue identifier | - |
| 6 | `(` | End identifier | `identifier("add")` |
| 6 | `(` | Single char | `lparen` |
| 7 | `a` | Start identifier | - |
| 8 | `:` | End identifier | `identifier("a")` |
| 8 | `:` | Single char | `colon` |
| 10 | `i` | Start identifier | - |
| 13 | `,` | End, keyword lookup | `kw_i64` |
| 13 | `,` | Single char | `comma` |
| ... | ... | ... | ... |

Final token stream:
```
[kw_fn] [identifier:"add"] [lparen] [identifier:"a"] [colon] [kw_i64] [comma]
[identifier:"b"] [colon] [kw_i64] [rparen] [kw_i64] [lbrace] [kw_return]
[identifier:"a"] [plus] [identifier:"b"] [semicolon] [rbrace] [eof]
```

---

## Error Handling

When the scanner encounters invalid input, it reports errors:

```zig
fn errorAt(self: *Scanner, pos: Pos, code: ErrorCode, msg: []const u8) void {
    if (self.err) |reporter| {
        reporter.errorWithCode(pos, code, msg);
    }
}
```

Error codes:
- `E100` - String literal not terminated
- `E101` - Character literal not terminated
- `E104` - Unexpected character

Example error:
```
test.cot:3:15: error E100: string literal not terminated
    var s = "hello
            ^
```

---

## Key Takeaways

1. **Scanning is simple:** Just pattern matching on characters, grouping them into tokens.

2. **Keywords vs identifiers:** Both look like words, but keywords are reserved and get special token types.

3. **Lookahead is important:** Sometimes we need to peek at the next character to decide what token we have (like `.` vs `..`).

4. **Position tracking:** Every token remembers where it came from for error messages.

5. **State management:** String interpolation requires tracking state (are we inside a string? how deep in braces?).

---

## Next Steps

The scanner produces a stream of tokens. The next stage, **parsing**, will take these tokens and build a tree structure showing how they relate to each other.

See: [11_PARSING.md](11_PARSING.md)
