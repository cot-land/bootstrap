# Stage 5: SSA Conversion

**Files:** `src/ssa.zig`

**Purpose:** Transform IR into Static Single Assignment form

---

## What is SSA?

**Static Single Assignment (SSA)** is a property where every variable is assigned exactly once. Consider:

```
// Not SSA - x is assigned multiple times
x = 1
x = x + 1
x = x * 2
return x
```

In SSA form, we rename each assignment:

```
// SSA - each x_N is assigned exactly once
x_1 = 1
x_2 = x_1 + 1
x_3 = x_2 * 2
return x_3
```

This is incredibly useful for optimization because:
- You can see exactly where each value comes from
- You can safely move or reorder operations
- Dead code elimination becomes trivial

---

## The Problem: Conditional Assignments

What about code like this?

```cot
var x: i64;
if condition {
    x = 1;
} else {
    x = 2;
}
return x;
```

After the `if`, which `x` do we use? Both branches assigned to it!

SSA solves this with **phi functions** (written as `phi` or `Phi`):

```
     if condition:           else:
        x_1 = 1               x_2 = 2
         \                     /
          \                   /
           \                 /
            v               v
             merge:
             x_3 = phi(x_1, x_2)
             return x_3
```

A phi function says: "The value is x_1 if we came from the `if` branch, or x_2 if we came from `else`."

---

## SSA Values

In SSA, everything is a **Value** with a unique ID:

```zig
pub const Value = struct {
    id: ValueID,           // Unique identifier
    op: Op,                // The operation
    type_idx: TypeIndex,   // Result type
    block: BlockID,        // Which block contains this

    /// Inline storage for arguments (first 3)
    args_storage: [3]ValueID = .{ null_value, null_value, null_value },
    args_len: u8 = 0,

    /// Use count for dead code elimination
    uses: u32 = 0,

    /// Auxiliary data
    aux_int: i64 = 0,
    aux_str: []const u8 = "",
};
```

Key insight: Values **reference other values by ID**, not by name. This creates a dependency graph:

```
%1 = const_int 1
%2 = const_int 2
%3 = add %1, %2     // Depends on %1 and %2
%4 = mul %3, %3     // Depends on %3 (twice)
```

---

## SSA Operations

SSA has its own set of operations, similar to IR but with SSA-specific ones:

```zig
pub const Op = enum(u8) {
    // Constants
    const_int,
    const_float,
    const_bool,
    const_nil,
    const_slice,   // String literal

    // SSA-specific
    phi,           // Phi function for merging
    copy,          // Register allocation helper

    // Arithmetic
    add, sub, mul, div, mod, neg,

    // Comparison
    eq, ne, lt, le, gt, ge,

    // Logical
    @"and", @"or", not,

    // Conditional select (ternary without branches)
    select,        // args[0]=cond, args[1]=then, args[2]=else

    // Memory
    load, store, addr, alloc,

    // Struct/array
    field, ptr_field, index,
    slice_make, slice_index,

    // Control flow (block terminators)
    ret,           // Return from function
    jump,          // Unconditional jump
    branch,        // Conditional branch
    @"unreachable",
};
```

---

## SSA Blocks

Blocks in SSA track their **control flow edges**:

```zig
pub const BlockKind = enum(u8) {
    plain,    // Single successor (unconditional)
    @"if",    // Two successors (conditional)
    ret,      // Return from function
    exit,     // Unreachable
};

pub const Block = struct {
    id: BlockID,
    kind: BlockKind,

    /// Successor edges (where this block can jump to)
    succs_storage: [2]Edge,  // Inline for common case
    succs_len: u8,

    /// Predecessor edges (what blocks can jump here)
    preds_storage: [4]Edge,  // Inline for common case
    preds_len: u8,

    /// Values in this block (in order)
    values: ArrayList(ValueID),

    /// Control value (condition for if blocks)
    control: ValueID,
};
```

The `Edge` type enables bidirectional navigation:

```zig
pub const Edge = struct {
    block: BlockID,      // Target block
    reverse_idx: u32,    // Index in target's reverse list
};
```

This allows O(1) operations when modifying the CFG (control flow graph).

---

## The SSA Function

An SSA function contains all the SSA data:

```zig
pub const Func = struct {
    name: []const u8,
    return_type: TypeIndex,

    /// All values (indexed by ValueID)
    values: ArrayList(Value),

    /// All blocks (indexed by BlockID)
    blocks: ArrayList(Block),

    /// Entry block
    entry: BlockID,

    /// Local variable info (for stack allocation)
    locals: []const LocalInfo,

    /// Total stack frame size
    frame_size: u32,

    /// ID allocators for dense indexing
    value_ids: IdAlloc,
    block_ids: IdAlloc,
};
```

---

## Converting IR to SSA

The conversion process:

### Step 1: Create Entry Block

```zig
pub fn convert(ir_func: *const ir.Func, allocator: Allocator) !Func {
    var ssa_func = Func.init(allocator, ir_func.name, ir_func.return_type);

    // Create entry block
    const entry_block = try ssa_func.newBlock();
    ssa_func.entry = entry_block;

    // ...
}
```

### Step 2: Map IR Locals to SSA Values

For each local variable, we track the current SSA value:

```zig
var current_def: std.StringHashMap(ValueID) = .{};

// Parameters become initial definitions
for (ir_func.params) |param| {
    const arg_val = try ssa_func.newValue(.arg, param.type_idx, entry_block);
    arg_val.aux_int = @intCast(param.param_idx);
    try current_def.put(param.name, arg_val.id);
}
```

### Step 3: Convert IR Nodes to SSA Values

Each IR node becomes one or more SSA values:

```zig
fn convertNode(self: *Converter, ir_node: ir.Node, block: BlockID) !ValueID {
    switch (ir_node.op) {
        .const_int => {
            const val = try self.func.newValue(.const_int, ir_node.type_idx, block);
            val.aux_int = ir_node.aux;
            return val.id;
        },
        .local => {
            // Look up current SSA value for this local
            const local_name = self.ir_func.locals[ir_node.aux].name;
            return self.current_def.get(local_name) orelse null_value;
        },
        .store => {
            // Create new SSA value for this local
            const local_name = self.ir_func.locals[ir_node.args()[0]].name;
            const value = ir_node.args()[1];
            try self.current_def.put(local_name, value);
            return null_value;  // Stores don't produce values
        },
        .add => {
            const left = ir_node.args()[0];
            const right = ir_node.args()[1];
            const val = try self.func.newValue(.add, ir_node.type_idx, block);
            try val.setArgs(&.{ left, right }, self.allocator);
            return val.id;
        },
        // ... more cases
    }
}
```

### Step 4: Handle Control Flow

When converting branches, we need to:
1. Create new blocks
2. Set up successor/predecessor edges
3. Add phi functions at merge points

```zig
fn convertBranch(self: *Converter, ir_node: ir.Node, block_id: BlockID) !void {
    const cond = try self.convertValue(ir_node.args()[0]);
    const true_target = @intCast(ir_node.aux);
    const false_target = ... ; // From aux_str

    var block = &self.func.blocks.items[block_id];
    block.kind = .@"if";
    block.setControl(cond);
    _ = block.addSucc(true_target);
    _ = block.addSucc(false_target);
}
```

### Step 5: Insert Phi Functions

At merge points (blocks with multiple predecessors), we insert phi functions:

```zig
fn insertPhis(self: *Converter, block_id: BlockID) !void {
    const block = &self.func.blocks.items[block_id];

    if (block.numPreds() < 2) return;  // No merge, no phi needed

    // For each variable that has different values on different paths
    for (self.variables) |var_name| {
        var incoming: [4]ValueID = undefined;
        var num_incoming: u8 = 0;

        for (block.preds()) |pred_edge| {
            const pred_def = self.getDefAtEndOf(pred_edge.block, var_name);
            incoming[num_incoming] = pred_def;
            num_incoming += 1;
        }

        // Only need phi if values differ
        if (needsPhi(incoming[0..num_incoming])) {
            const phi_val = try self.func.newValue(.phi, var_type, block_id);
            try phi_val.setArgs(incoming[0..num_incoming], self.allocator);
            try self.current_def.put(var_name, phi_val.id);
        }
    }
}
```

---

## Use Counting for Dead Code Elimination

Each value tracks how many times it's used:

```zig
fn addUse(self: *Func, value_id: ValueID) void {
    self.values.items[value_id].uses += 1;
}

fn removeUse(self: *Func, value_id: ValueID) void {
    const val = &self.values.items[value_id];
    val.uses -= 1;
    if (val.uses == 0 and !val.op.hasSideEffects()) {
        // This value is dead, can be eliminated
        self.markDead(value_id);
    }
}
```

Dead code elimination becomes simple:
1. Walk all values
2. If uses == 0 and no side effects, remove it
3. Decrement use counts of its arguments
4. Repeat until nothing changes

---

## Example: SSA Conversion

Original IR:

```
func add(a, b):
  block0:
    %0 = local 0       ; a
    %1 = local 1       ; b
    %2 = add %0, %1
    ret %2
```

SSA:

```
func add(a, b):
  entry (block 0):
    %0 = arg 0         ; a (uses: 1)
    %1 = arg 1         ; b (uses: 1)
    %2 = add %0, %1    ; (uses: 1)
    ret %2
```

With a conditional:

Original IR:

```
func max(a, b):
  block0:
    %0 = local 0       ; a
    %1 = local 1       ; b
    %2 = gt %0, %1
    branch %2, block1, block2

  block1:
    %3 = local 0       ; load a
    ret %3

  block2:
    %4 = local 1       ; load b
    ret %4
```

SSA (simplified):

```
func max(a, b):
  block0:
    %0 = arg 0         ; a
    %1 = arg 1         ; b
    %2 = gt %0, %1
    branch %2 -> block1, block2

  block1:
    ret %0             ; return a directly

  block2:
    ret %1             ; return b directly
```

With a phi:

```
func abs(x):
  block0:
    %0 = arg 0
    %1 = const_int 0
    %2 = lt %0, %1     ; x < 0?
    branch %2 -> block1, block2

  block1:
    %3 = neg %0        ; -x
    jump -> block3

  block2:
    jump -> block3

  block3:
    %4 = phi(%3, %0)   ; result is -x from block1, or x from block2
    ret %4
```

---

## SSA Properties

### Dominance

A block A **dominates** block B if every path from entry to B goes through A.

This is important for:
- Knowing where values are available
- Placing phi functions correctly
- Loop optimizations

### Use-Def Chains

Every use of a value points directly to its definition:

```
%3 = add %1, %2
         ^   ^
         |   |
         |   +-- Definition of %2
         +------ Definition of %1
```

This makes dependency analysis trivial.

---

## The Select Operation

For simple conditionals, SSA has a `select` operation that avoids branches:

```
// Instead of:
branch cond -> then_block, else_block
then_block: %1 = const 1; jump merge
else_block: %2 = const 2; jump merge
merge: %3 = phi(%1, %2)

// Use select:
%1 = const 1
%2 = const 2
%3 = select cond, %1, %2  // If cond then %1 else %2
```

This maps directly to conditional move instructions on modern CPUs.

---

## Location Tracking

For register allocation, values can have locations:

```zig
pub const Location = union(enum) {
    reg: u8,     // In a register
    stack: i32,  // On the stack (offset from frame pointer)
    none: void,  // Doesn't need a location
};
```

The register allocator fills these in after SSA is constructed.

---

## Key Takeaways

1. **Every value assigned once** makes optimization easier.

2. **Phi functions** handle merge points where different paths assign different values.

3. **Use counting** enables trivial dead code elimination.

4. **Dense IDs** make values and blocks cache-friendly arrays.

5. **Bidirectional edges** enable O(1) CFG modifications.

6. **Select** can replace simple conditional branches.

---

## Next Steps

The SSA form is ready for code generation. The next stage, **codegen**, will:
1. Allocate registers for values
2. Emit machine instructions for each operation
3. Handle calling conventions

See: [15_CODEGEN.md](15_CODEGEN.md)
