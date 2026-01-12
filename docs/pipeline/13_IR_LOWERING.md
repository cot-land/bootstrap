# Stage 4: IR Lowering

**Files:** `src/lower.zig`, `src/ir.zig`

**Purpose:** Transform the AST into simpler, lower-level operations

---

## What is IR Lowering?

The AST represents code as the programmer wrote it. But there's a lot of "sugar" - convenient syntax that hides complexity:

```cot
for item in array {    // Sugar: hides counter, bounds check, indexing
    total += item;     // Sugar: hides x = x + item
}
```

IR lowering **desugars** this into simple, explicit operations:

```
// IR (pseudo-code)
i = 0
loop_start:
    if i >= len(array) goto loop_end
    item = array[i]
    temp = load total
    temp2 = add temp, item
    store total, temp2
    i = i + 1
    goto loop_start
loop_end:
```

The IR is closer to what the CPU will actually do.

---

## Why Lowering?

The AST has many node types (for-in, while, +=, struct access, method calls). The IR has few, simple operations:

| AST | IR |
|-----|-----|
| `for x in arr { }` | counter, compare, branch, index, jump |
| `a += b` | load a, add, store |
| `obj.method(x)` | call method(obj, x) |
| `Point{.x=1, .y=2}` | store field at offset 0, store field at offset 8 |

Fewer operations means:
- Easier to optimize (pattern matching on simple ops)
- Easier to convert to machine code (each op maps to instructions)
- Easier to reason about (explicit control flow)

---

## IR Operations

Operations are defined in `src/ir.zig`:

```zig
pub const Op = enum(u8) {
    // Constants
    const_int,    // Integer constant. aux = value
    const_float,  // Float constant
    const_bool,   // Boolean constant. aux = 0 or 1
    const_slice,  // String literal. aux = string index

    // Variables
    local,        // Load local variable. aux = local index
    global,       // Load global variable. aux_str = name
    param,        // Load parameter. aux = param index

    // Arithmetic
    add, sub, mul, div, mod,  // Binary ops
    neg,                       // Unary negate

    // Comparison
    eq, ne, lt, le, gt, ge,   // Result is bool

    // Logical
    @"and", @"or", not,       // Boolean ops

    // Bitwise
    bit_and, bit_or, bit_xor, bit_not, shl, shr,

    // Memory
    load,        // Load from address
    store,       // Store to address. args[0] = dest, args[1] = value
    addr_local,  // Get address of local variable
    addr_field,  // Get field address. aux = offset
    addr_index,  // Get array element address

    // Struct/Array
    field,       // Get struct field. aux = field index
    index,       // Get array element. args[0] = array, args[1] = index

    // Control Flow
    call,        // Function call. args[0] = callee, rest = arguments
    ret,         // Return. args[0] = value (optional)
    jump,        // Unconditional jump. aux = target block
    branch,      // Conditional. args[0] = cond, aux = true block
    phi,         // SSA phi node (covered in next stage)

    // Misc
    nop,         // No operation
};
```

---

## The IR Node

Each IR node represents one operation:

```zig
pub const Node = struct {
    op: Op,                    // The operation
    type_idx: TypeIndex,       // Result type
    args_storage: [4]NodeIndex, // Operand indices (inline)
    args_len: u8,              // Number of operands
    aux: i64,                  // Auxiliary data (constant value, offset, etc.)
    aux_str: []const u8,       // Auxiliary string (names)
    span: Span,                // Source location
    block: BlockIndex,         // Which basic block this belongs to
};
```

Example: `add x, y` becomes:

```zig
Node{
    .op = .add,
    .type_idx = TypeRegistry.INT,
    .args_storage = { node_x, node_y, 0, 0 },
    .args_len = 2,
    .aux = 0,
    .aux_str = "",
    .span = ...,
    .block = 0,
}
```

---

## Basic Blocks

A **basic block** is a sequence of operations with:
- **Single entry** - execution always starts at the first instruction
- **Single exit** - execution always leaves at the last instruction (jump, branch, return)

```zig
pub const Block = struct {
    index: BlockIndex,         // Block number
    preds: []const BlockIndex, // Which blocks jump here
    succs: []const BlockIndex, // Which blocks this jumps to
    nodes: []const NodeIndex,  // Operations in order
    label: []const u8,         // Name for debugging
};
```

Example:

```
Block 0 (entry):
    x = const 1
    y = const 2
    cond = lt x, y
    branch cond, Block1, Block2

Block 1 (then):
    result = const 100
    jump Block3

Block 2 (else):
    result = const 200
    jump Block3

Block 3 (merge):
    ret result
```

---

## The Lowerer

The lowerer walks the AST and emits IR:

```zig
pub const Lowerer = struct {
    allocator: Allocator,
    tree: *const Ast,           // AST to lower
    type_reg: *TypeRegistry,    // Type information
    builder: ir.Builder,        // Builds IR
    checker: *const Checker,    // Type checker results

    // Current function being built
    current_func: ?*ir.FuncBuilder,

    // For break/continue handling
    loop_stack: ArrayList(LoopContext),

    // String literals (for read-only data section)
    string_literals: ArrayList([]const u8),

    const LoopContext = struct {
        cond_block: u32,  // Where to jump for continue
        exit_block: u32,  // Where to jump for break
    };
};
```

---

## Lowering Expressions

Each expression type has a lowering function:

### Literals

```zig
fn lowerLiteral(self: *Lowerer, lit: ast.Literal) !NodeIndex {
    const fb = self.current_func orelse return 0;
    const span = Span.fromPos(Pos.zero);

    return switch (lit.kind) {
        .int => {
            const value = std.fmt.parseInt(i64, lit.value, 10) catch 0;
            return fb.emitConstInt(value, TypeRegistry.INT, span);
        },
        .float => {
            const value = std.fmt.parseFloat(f64, lit.value) catch 0.0;
            return fb.emitConstFloat(value, TypeRegistry.FLOAT, span);
        },
        .true_lit => fb.emitConstBool(true, span),
        .false_lit => fb.emitConstBool(false, span),
        .string => {
            // Add to string table, emit const_slice
            const str_idx = try self.addStringLiteral(lit.value);
            return fb.emitConstSlice(str_idx, TypeRegistry.STRING, span);
        },
        // ...
    };
}
```

### Binary Operations

```zig
fn lowerBinary(self: *Lowerer, bin: ast.Binary) !NodeIndex {
    const fb = self.current_func orelse return 0;

    // Lower operands first
    const left = try self.lowerExpr(bin.left);
    const right = try self.lowerExpr(bin.right);

    // Map AST operator to IR op
    const ir_op = switch (bin.op) {
        .plus => ir.Op.add,
        .minus => ir.Op.sub,
        .star => ir.Op.mul,
        .slash => ir.Op.div,
        .percent => ir.Op.mod,
        .equal_equal => ir.Op.eq,
        .bang_equal => ir.Op.ne,
        .less => ir.Op.lt,
        .less_equal => ir.Op.le,
        .greater => ir.Op.gt,
        .greater_equal => ir.Op.ge,
        .kw_and => ir.Op.@"and",
        .kw_or => ir.Op.@"or",
        // ...
    };

    const result_type = self.getExprType(bin);
    return fb.emitBinary(ir_op, left, right, result_type, span);
}
```

### Function Calls

```zig
fn lowerCall(self: *Lowerer, call: ast.Call) !NodeIndex {
    const fb = self.current_func orelse return 0;

    // Get function name
    const callee_name = self.getFunctionName(call.callee);

    // Lower arguments
    var args = ArrayList(NodeIndex){...};
    for (call.args) |arg_idx| {
        const arg = try self.lowerExpr(arg_idx);
        try args.append(arg);
    }

    // Emit call node
    const return_type = self.getFunctionReturnType(callee_name);
    const callee_node = try fb.emit(
        ir.Node.init(.global, return_type, span).withAuxStr(callee_name)
    );
    return fb.emitCall(callee_node, args.items, return_type, span);
}
```

### Identifiers

```zig
fn lowerIdentifier(self: *Lowerer, ident: ast.Identifier) !NodeIndex {
    const fb = self.current_func orelse return 0;
    const name = ident.name;

    // Check for local variable
    if (fb.lookupLocal(name)) |local_idx| {
        const local = fb.locals.items[local_idx];
        return fb.emitLocalLoad(local_idx, local.type_idx, span);
    }

    // Check for global
    // ...

    return error.UndefinedVariable;
}
```

---

## Lowering Statements

### Return Statement

```zig
fn lowerReturnStmt(self: *Lowerer, rs: ast.ReturnStmt) !void {
    const fb = self.current_func orelse return;

    if (rs.value) |value_idx| {
        const value = try self.lowerExpr(value_idx);
        _ = try fb.emitReturn(value, span);
    } else {
        _ = try fb.emitReturn(null, span);
    }
}
```

### Variable Declaration

```zig
fn lowerVarStmt(self: *Lowerer, vs: ast.VarStmt) !void {
    const fb = self.current_func orelse return;

    // Determine type
    var type_idx = TypeRegistry.VOID;
    if (vs.type_expr) |te| {
        type_idx = self.resolveTypeExpr(te);
    } else if (vs.value) |val| {
        type_idx = self.inferTypeFromExpr(val);
    }

    // Create local variable
    const size = self.type_reg.sizeOf(type_idx);
    const local_idx = try fb.addLocalWithSize(vs.name, type_idx, !vs.is_const, size);

    // Initialize if value provided
    if (vs.value) |value_idx| {
        const value = try self.lowerExpr(value_idx);
        const store = ir.Node.init(.store, type_idx, span)
            .withArgs(&.{ @intCast(local_idx), value });
        _ = try fb.emit(store);
    }
}
```

### Assignment

```zig
fn lowerAssignStmt(self: *Lowerer, as: ast.AssignStmt) !void {
    const fb = self.current_func orelse return;

    // Handle compound assignment (+=, -=, etc.)
    var value_node: NodeIndex = undefined;
    if (as.op) |compound_op| {
        // Desugar: a += b -> a = a + b
        const current = try self.lowerExpr(as.target);
        const increment = try self.lowerExpr(as.value);
        const ir_op = self.compoundOpToIrOp(compound_op);
        value_node = try fb.emitBinary(ir_op, current, increment, type_idx, span);
    } else {
        value_node = try self.lowerExpr(as.value);
    }

    // Store to target
    const target = try self.getLValue(as.target);
    const store = ir.Node.init(.store, type_idx, span)
        .withArgs(&.{ target, value_node });
    _ = try fb.emit(store);
}
```

---

## Lowering Control Flow

### If Statement

```zig
fn lowerIfStmt(self: *Lowerer, is: ast.IfStmt) !void {
    const fb = self.current_func orelse return;

    // Create blocks
    const then_block = try fb.newBlock("then");
    const else_block = if (is.else_branch != null)
        try fb.newBlock("else")
    else
        null;
    const merge_block = try fb.newBlock("merge");

    // Emit condition and branch
    const cond = try self.lowerExpr(is.condition);
    _ = try fb.emitBranch(cond, then_block, else_block orelse merge_block, span);

    // Lower then branch
    fb.setBlock(then_block);
    try self.lowerStmt(is.then_branch);
    if (!self.blockTerminated()) {
        _ = try fb.emitJump(merge_block, span);
    }

    // Lower else branch if present
    if (is.else_branch) |else_idx| {
        fb.setBlock(else_block.?);
        try self.lowerStmt(else_idx);
        if (!self.blockTerminated()) {
            _ = try fb.emitJump(merge_block, span);
        }
    }

    // Continue in merge block
    fb.setBlock(merge_block);
}
```

Generated IR:
```
Block 0 (entry):
    cond = ...
    branch cond, Block1, Block2

Block 1 (then):
    ... then code ...
    jump Block3

Block 2 (else):
    ... else code ...
    jump Block3

Block 3 (merge):
    ... continue ...
```

### While Loop

```zig
fn lowerWhileStmt(self: *Lowerer, ws: ast.WhileStmt) !void {
    const fb = self.current_func orelse return;

    // Create blocks
    const cond_block = try fb.newBlock("while.cond");
    const body_block = try fb.newBlock("while.body");
    const exit_block = try fb.newBlock("while.exit");

    // Push loop context (for break/continue)
    try self.loop_stack.append(.{
        .cond_block = cond_block,
        .exit_block = exit_block,
    });

    // Jump to condition check
    _ = try fb.emitJump(cond_block, span);

    // Condition block
    fb.setBlock(cond_block);
    const cond = try self.lowerExpr(ws.condition);
    _ = try fb.emitBranch(cond, body_block, exit_block, span);

    // Body block
    fb.setBlock(body_block);
    try self.lowerStmt(ws.body);
    _ = try fb.emitJump(cond_block, span);  // Loop back

    // Exit block
    fb.setBlock(exit_block);

    // Pop loop context
    _ = self.loop_stack.pop();
}
```

Generated IR:
```
Block 0 (entry):
    jump Block1

Block 1 (while.cond):
    cond = ...
    branch cond, Block2, Block3

Block 2 (while.body):
    ... body ...
    jump Block1

Block 3 (while.exit):
    ... continue ...
```

### For-In Loop

For loops are desugared into while loops:

```cot
for item in array {
    print(item);
}
```

Becomes:

```zig
fn lowerForStmt(self: *Lowerer, fs: ast.ForStmt) !void {
    const fb = self.current_func orelse return;

    // Get array length
    const array_len = try self.emitArrayLen(fs.iterable);

    // Create counter: var __i = 0
    const counter_idx = try fb.addLocalWithSize("__for_i", TypeRegistry.INT, true, 8);
    const zero = try fb.emitConstInt(0, TypeRegistry.INT, span);
    _ = try fb.emit(ir.Node.init(.store, TypeRegistry.INT, span)
        .withArgs(&.{ @intCast(counter_idx), zero }));

    // Create blocks
    const cond_block = try fb.newBlock("for.cond");
    const body_block = try fb.newBlock("for.body");
    const incr_block = try fb.newBlock("for.incr");
    const exit_block = try fb.newBlock("for.exit");

    // Push loop context
    try self.loop_stack.append(.{
        .cond_block = incr_block,  // continue goes to increment
        .exit_block = exit_block,
    });

    _ = try fb.emitJump(cond_block, span);

    // Condition: __i < len
    fb.setBlock(cond_block);
    const i_val = try fb.emitLocalLoad(counter_idx, TypeRegistry.INT, span);
    const cmp = try fb.emitBinary(.lt, i_val, array_len, TypeRegistry.BOOL, span);
    _ = try fb.emitBranch(cmp, body_block, exit_block, span);

    // Body: item = array[__i]; ... user code ...
    fb.setBlock(body_block);
    const item_val = try self.emitArrayIndex(fs.iterable, i_val);
    const item_idx = try fb.addLocalWithSize(fs.binding, item_type, false, 8);
    _ = try fb.emit(ir.Node.init(.store, item_type, span)
        .withArgs(&.{ @intCast(item_idx), item_val }));
    try self.lowerStmt(fs.body);
    _ = try fb.emitJump(incr_block, span);

    // Increment: __i = __i + 1
    fb.setBlock(incr_block);
    const i_load = try fb.emitLocalLoad(counter_idx, TypeRegistry.INT, span);
    const one = try fb.emitConstInt(1, TypeRegistry.INT, span);
    const i_next = try fb.emitBinary(.add, i_load, one, TypeRegistry.INT, span);
    _ = try fb.emit(ir.Node.init(.store, TypeRegistry.INT, span)
        .withArgs(&.{ @intCast(counter_idx), i_next }));
    _ = try fb.emitJump(cond_block, span);

    // Exit
    fb.setBlock(exit_block);
    _ = self.loop_stack.pop();
}
```

### Break and Continue

```zig
fn lowerBreakStmt(self: *Lowerer, _: ast.BreakStmt) !void {
    const fb = self.current_func orelse return;

    // Jump to exit block of innermost loop
    const ctx = self.loop_stack.items[self.loop_stack.items.len - 1];
    _ = try fb.emitJump(ctx.exit_block, span);
}

fn lowerContinueStmt(self: *Lowerer, _: ast.ContinueStmt) !void {
    const fb = self.current_func orelse return;

    // Jump to condition block (or increment for for-loops)
    const ctx = self.loop_stack.items[self.loop_stack.items.len - 1];
    _ = try fb.emitJump(ctx.cond_block, span);
}
```

---

## Lowering Structs

### Struct Initialization

```cot
var p = Point{ .x = 10, .y = 20 };
```

Becomes a series of field stores:

```zig
fn lowerStructInit(self: *Lowerer, si: ast.StructInit, local_idx: usize) !void {
    const fb = self.current_func orelse return;

    // Get struct type
    const struct_type = self.type_reg.lookupByName(si.type_name);
    const st = struct_type.struct_type;

    // Store each field at its offset
    for (si.fields) |field_init| {
        // Find field offset
        var field_offset: u32 = 0;
        var field_type: TypeIndex = TypeRegistry.VOID;
        for (st.fields) |f| {
            if (std.mem.eql(u8, f.name, field_init.name)) {
                field_offset = f.offset;
                field_type = f.type_idx;
                break;
            }
        }

        // Lower field value
        const value = try self.lowerExpr(field_init.value);

        // Emit store with offset
        const store = ir.Node.init(.store, field_type, span)
            .withArgs(&.{ @intCast(local_idx), value })
            .withAux(@intCast(field_offset));
        _ = try fb.emit(store);
    }
}
```

### Field Access

```cot
p.x
```

Becomes:

```zig
fn lowerFieldAccess(self: *Lowerer, fa: ast.FieldAccess) !NodeIndex {
    const fb = self.current_func orelse return 0;

    // Get base address
    const base = try self.lowerExpr(fa.base);
    const base_type = self.getExprType(fa.base);

    // Find field offset
    const st = self.type_reg.get(base_type).struct_type;
    var offset: u32 = 0;
    var field_type: TypeIndex = TypeRegistry.VOID;
    for (st.fields) |f| {
        if (std.mem.eql(u8, f.name, fa.field)) {
            offset = f.offset;
            field_type = f.type_idx;
            break;
        }
    }

    // Emit field load
    return fb.emit(ir.Node.init(.field, field_type, span)
        .withArgs(&.{base})
        .withAux(@intCast(offset)));
}
```

---

## Local Variables and Stack Frame

The FuncBuilder tracks local variables:

```zig
pub const Local = struct {
    name: []const u8,
    type_idx: TypeIndex,
    slot: u32,           // Deprecated
    mutable: bool,
    is_param: bool,
    param_idx: u32,
    size: u32,           // Size in bytes
    offset: i32,         // Stack frame offset (negative from frame pointer)
};
```

When building the function, offsets are computed:

```zig
pub fn build(self: *FuncBuilder) !Func {
    // Compute stack frame layout
    var frame_offset: i32 = 0;
    for (self.locals.items) |*local| {
        // Align to 8 bytes
        frame_offset = roundUp(frame_offset, 8);
        // Assign offset (negative for x86)
        local.offset = -frame_offset - @intCast(local.size);
        frame_offset += @intCast(local.size);
    }

    // Round to 16-byte alignment (ABI requirement)
    const frame_size = roundUp(frame_offset, 16);

    return Func{
        .locals = self.locals.items,
        .frame_size = frame_size,
        // ...
    };
}
```

---

## Complete Example

Let's trace lowering for:

```cot
fn add(a: i64, b: i64) i64 {
    return a + b;
}
```

### Input AST

```
FnDecl
  name: "add"
  params: [a: i64, b: i64]
  return_type: i64
  body: Block
    ReturnStmt
      value: Binary(+)
        left: Identifier("a")
        right: Identifier("b")
```

### Lowering Steps

```
1. lowerFnDecl("add")
   - Start function builder
   - Add param "a" (local 0, type i64, size 8)
   - Add param "b" (local 1, type i64, size 8)

2. lowerBlock(body)
   - lowerStmt(ReturnStmt)

3. lowerReturnStmt
   - lowerExpr(Binary)

4. lowerBinary(+)
   - lowerExpr(Identifier "a")
     - lookupLocal("a") -> 0
     - emit: local(0) -> node 0
   - lowerExpr(Identifier "b")
     - lookupLocal("b") -> 1
     - emit: local(1) -> node 1
   - emit: add(node0, node1) -> node 2

5. Back to lowerReturnStmt
   - emit: ret(node2) -> node 3

6. Build function
   - Compute frame layout
   - Return Func
```

### Output IR

```
func add(a: i64, b: i64) -> i64:
  locals:
    [0] a: i64, param, offset=-8
    [1] b: i64, param, offset=-16
  frame_size: 16

  block 0 (entry):
    %0 = local 0          ; load a
    %1 = local 1          ; load b
    %2 = add %0, %1       ; a + b
    ret %2
```

---

## Key Takeaways

1. **Desugaring** converts high-level constructs to primitive operations.

2. **Basic blocks** group operations with single entry/exit.

3. **Control flow** is explicit (jumps and branches, not for/while).

4. **Local variables** get stack frame offsets computed during lowering.

5. **String literals** are collected for the read-only data section.

6. **Loop stack** enables proper break/continue handling.

---

## Next Steps

The IR uses named locals and explicit blocks. The next stage, **SSA conversion**, transforms this into Static Single Assignment form where each variable is assigned exactly once.

See: [14_SSA.md](14_SSA.md)
