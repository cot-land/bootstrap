# Cot 0.2 Development Guidelines

## BUG TRACKING PROCESS - MANDATORY

**When you encounter a bug during bootstrap development, follow this process:**

1. **Discover** - Identify the bug through testing or code analysis
2. **Document** - Add to `BUGLIST.md` with location, description, and impact
3. **Test** - Create a test case in `tests/` that exposes the bug
4. **Fix** - Implement the fix
5. **Verify** - Run the test to confirm the fix works
6. **Complete** - Mark the bug as FIXED in `BUGLIST.md`

This is the ONLY way to achieve a stable self-hosting compiler. See `BUGLIST.md` for the current bug list and template.

---

## CODEGEN ARCHITECTURE - MANDATORY READING

**Before implementing new SSA operations or debugging codegen bugs, you MUST read `CODEGEN.md`.**

The codegen uses an **MCValue-based architecture** where every value's location is tracked explicitly. This is different from naive approaches that guess register contents.

### Quick Reference (read CODEGEN.md for details)

**To add a new operation:**
```zig
fn genMyOp(self: *CodeGen, value: *ssa.Value) !void {
    const args = value.args();

    // 1. Get operand locations (NEVER assume registers)
    const left_mcv = self.getValue(args[0]);
    const right_mcv = self.getValue(args[1]);

    // 2. Handle register clobbering (if right is in x0/rax, save it first!)
    if (right_mcv == .register and right_mcv.register == .x0) {
        try movRegReg(.x9, .x0);  // Save right to scratch
        try self.loadToReg(.x0, left_mcv);
        // ... use x9 for right
    } else {
        try self.loadToReg(.x0, left_mcv);
        try self.loadToReg(.x9, right_mcv);
    }

    // 3. Emit instruction
    try someInstruction(self.buf, .x0, .x9);

    // 4. Record result location
    self.reg_manager.markUsed(.x0, value.id);
    try self.setResult(value.id, .{ .register = .x0 });
}
```

**Key functions:**
- `getValue(id)` - Returns MCValue showing where a value currently lives
- `loadToReg(dest, mcv)` - Loads any MCValue into a register
- `setResult(id, mcv)` - Records where an operation's result is stored
- `spillReg(reg)` - Saves register to stack when we need it for something else

**Common bugs:**
- Loading left operand clobbers right (if both target same register)
- Forgetting to call `setResult()` after an operation
- Using wrong function names for runtime calls (check runtime/*.zig for correct names)

---

## DOCUMENTATION MAINTENANCE - KEEP UPDATED

**After completing features or fixing tests, update these tracking documents:**

### STATUS.md - Current Implementation Status
- Update test counts when tests pass/fail
- Mark features as "Done" when implemented
- Add notes about partial implementations

### ROADMAP.md - Self-Hosting Roadmap
- Move completed items to STATUS.md
- Update priority levels as blockers change
- Track .cot file readiness

**When to update:**
- After implementing a new feature → update STATUS.md
- After completing a roadmap item → move from ROADMAP.md to STATUS.md
- After fixing test failures → update test counts in STATUS.md
- After discovering new blockers → add to ROADMAP.md

---

## TROUBLESHOOTING - READ THIS FIRST

When debugging compiler issues, **DO NOT read through source code to trace execution**. Instead, use these debug flags to observe what's actually happening:

### Debug Flags (use these immediately when something goes wrong)

```bash
# See what IR is generated (ops, locals, control flow)
./zig-out/bin/cot file.cot --debug-ir -o out

# See what SSA looks like (values, blocks, args)
./zig-out/bin/cot file.cot --debug-ssa -o out

# See what instructions are emitted (bytes per op)
./zig-out/bin/cot file.cot --debug-codegen -o out

# See the actual machine code (runs objdump automatically)
./zig-out/bin/cot file.cot --disasm -o out

# Combine flags for full visibility
./zig-out/bin/cot file.cot --debug-ir --debug-ssa --debug-codegen --disasm -o out
```

### When a compiled program crashes or returns wrong value

1. **First**: Run with `--disasm` to see the actual machine code
2. **Use lldb** to see where it crashes: `lldb -o "run" -o "bt" -o "quit" ./program`
3. **Check the SSA** with `--debug-ssa` to see if values are correct
4. **Check the IR** with `--debug-ir` to see if lowering is correct

### Example debugging session

```bash
# Program returns 0 instead of expected 10
./zig-out/bin/cot tests/test_return.cot --disasm -o test
# Look at disassembly - is the value being loaded correctly?
# Is the epilogue restoring the stack before ret?

# If crash (exit 139 = segfault)
lldb -o "run" -o "bt" -o "quit" ./test
# Shows where crash happens - dyld means loader issue, _main means our code
```

### DO NOT

- Spend time reading source code to trace execution flow
- Add temporary debug prints (they get removed and next session has to re-add them)
- Guess at what might be wrong based on code reading

### DO

- Use the debug flags to observe actual behavior
- Use lldb/objdump to see what's really happening
- Trust the output over your interpretation of the code

### Note for self-hosted .cot compiler

When implementing the .cot compiler, replicate these same debug flags:
- `--debug-ir` - Dump IR after lowering
- `--debug-ssa` - Dump SSA after conversion
- `--debug-codegen` - Show codegen operations
- `--disasm` - Run objdump on output

This pattern is essential for maintainability. The Zig implementation is temporary scaffolding.

---

## Zig 0.15 API Reference

This project uses Zig 0.15.2. Key API differences from older tutorials:

### ⚠️ ArrayList - CRITICAL (read this first!)

**STOP! ArrayList in Zig 0.15 does NOT have .init()!**

```zig
// ❌ WRONG - This will NOT compile in 0.15:
var list = std.ArrayList(u32).init(allocator);
list.append(item);
list.deinit();

// ✅ CORRECT - Zig 0.15 unmanaged ArrayList:
var list = std.ArrayList(u32){ .items = &.{}, .capacity = 0 };
try list.append(allocator, item);  // allocator on EVERY call
list.deinit(allocator);            // allocator on deinit too
```

**Every ArrayList method needs the allocator passed in:**
- `list.append(allocator, item)` not `list.append(item)`
- `list.deinit(allocator)` not `list.deinit()`
- Initialize with `{ .items = &.{}, .capacity = 0 }` not `.init(allocator)`

---

### Build System
```zig
// CORRECT for 0.15:
const exe = b.addExecutable(.{
    .name = "cot",
    .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    }),
});

// WRONG (old API):
// .root_source_file = b.path("src/main.zig"),  // was top-level, now nested
```

### Printing
```zig
// CORRECT for 0.15:
std.debug.print("hello\n", .{});

// WRONG (old API):
// const stdout = std.io.getStdOut().writer();  // getStdOut doesn't exist
```

### Memory Allocation
```zig
// CORRECT for 0.15:
const allocator = std.heap.page_allocator;
// or for arena:
var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
defer arena.deinit();
const alloc = arena.allocator();
```

### Testing
```zig
// CORRECT for 0.15:
test "name" {
    try std.testing.expect(condition);
    try std.testing.expectEqual(expected, actual);
}
```

---

## Development Pattern

**One file at a time. Explain before moving on.**

For each new file:
1. Update todo list to mark file as in_progress
2. Reference the equivalent Go source file
3. Write the Zig implementation
4. Run tests and fix any issues
5. Update main.zig to import the new module
6. Update IMPLEMENTATION.md status
7. Summarize what the file does and how it maps to Go
8. Wait for approval before proceeding to next file

This pattern ensures:
- John can follow along and verify each step
- Zig 0.15 API issues are caught immediately
- No runaway code generation (the 0.1 problem)
- Clear documentation of Go → Zig mapping

---

## Design Philosophy

Cot's design draws from multiple proven languages:

- **~90% Zig syntax** - The core language syntax and semantics
- **Swift/Kotlin ergonomics** - `??` null coalescing, `?.` optional chaining, modern optional handling
- **Rust features** - `impl` blocks and traits for polymorphism (post-bootstrap)
- **Go compiler/runtime design** - Pipeline architecture, IR patterns, algorithms
- **ARC memory management** - Automatic reference counting instead of Go's GC
- **C# safe mode** - `@mode safe` hides pointers for business software developers

This combination provides systems-level performance with a gradual learning curve. Business developers can work in safe mode (familiar Java/C# semantics), while systems programmers have full pointer access when needed.

## Core Philosophy

**Surgical precision over speed.**

Cot 0.1 failed because we added too much too fast - 200k lines in 2 weeks across parallel sessions. Bugs compounded, verification became impossible, and the codebase became unmanageable.

## Two Distinct Concerns

**Language features** - Minimal. Only what's needed to self-host.

**Compiler architecture** - Follow Go's proven design from day one. Don't invent our own architecture; that's where bugs come from.

The Go compiler has decades of refinement. We use its pipeline structure, IR patterns, and algorithms as our foundation. We just compile fewer language constructs through that solid pipeline.

## Rules

1. **One feature at a time.** Complete and verify before moving on.

2. **Minimal diff.** Every change should be the smallest possible to achieve the goal. No "while we're here" additions.

3. **No speculative language features.** Only add what's needed for the current milestone. Self-hosting first, everything else later.

4. **Reference, don't invent.** Use Go, Zig, Roc, or Kotlin source code as the blueprint. Claude implements patterns from real compilers, not novel designs.

5. **Verify before proceeding.** Each addition must be tested and working before the next begins.

6. **Single source of truth.** All sessions reference the same spec. No divergent implementations.

## Extensive Testing - CRITICAL

**Testing is the foundation of stability.** Extensive tests are the key to bug-free Zig code.

### Requirements

1. **Every function needs tests.** Don't write code without corresponding tests.

2. **Test edge cases.** Empty inputs, null values, boundary conditions, error paths.

3. **Test failure modes.** If a function can fail, test that it fails correctly.

4. **Integration tests.** Test end-to-end flows, not just unit functions.

5. **Regression tests.** When fixing a bug, add a test that would have caught it.

### Test Structure

```zig
// Unit test for specific function
test "parser handles empty input" {
    // Setup
    var parser = Parser.init(allocator, "");
    defer parser.deinit();

    // Action
    const result = parser.parse();

    // Assert
    try std.testing.expectEqual(result.errors.len, 1);
}

// Integration test for end-to-end flow
test "compile simple return statement" {
    const source = "fn main() { return 42; }";
    const result = try compile(allocator, source);
    try std.testing.expect(result.success);
}
```

### Why This Matters

Cot 0.1 failed because bugs compounded faster than we could fix them. Extensive testing:
- Catches bugs early before they cascade
- Enables confident refactoring
- Documents expected behavior
- Proves the code works

The same test discipline will be required in cot when we self-host.

### Testing Workflow - ALWAYS FOLLOW THIS ORDER

Before any commit or after any code changes, **always run tests in this order**:

```bash
# 1. FIRST: Run Zig embedded tests (catches compilation and unit test errors)
zig build test

# 2. THEN: Build and run comprehensive test (fast validation)
zig build
./run_tests.sh                    # ARM64 - runs comprehensive test by default
```

### x86_64 Testing (PAUSED during bootstrap)

**Note:** x86_64 cross-platform testing is paused during the bootstrap phase to speed up development. The x86_64 codegen was helpful for catching bugs and validating the architecture, but running Docker tests for every change slows down iteration. We'll re-enable thorough x86_64 testing after bootstrap is complete.

```bash
# OPTIONAL: Run x86_64 tests when needed (not required during bootstrap)
zig build -Dtarget=x86_64-linux-gnu
docker run --rm --platform linux/amd64 -v $(pwd):/cot -w /cot cot-zig:0.15.2 ./run_tests_x86_64.sh
```

### Comprehensive Test (Fast Validation)

The `tests/test_comprehensive.cot` file exercises ALL language features in a single test:
- Arithmetic, compound assignment, comparisons
- Boolean operations, control flow (if/while/for)
- Arrays, slices, strings
- Structs, enums, unions with switch
- Functions, maps, lists, type aliases

**This is the default test mode.** If comprehensive passes, all features work correctly.

```bash
# Default: Run comprehensive test only (fast ~2 seconds)
./run_tests.sh

# If comprehensive fails or you want to isolate issues:
./run_tests.sh --all              # Runs all 65+ individual tests
```

The comprehensive test returns specific error codes (1-52) to identify which feature failed.
If it fails, individual tests run automatically to help isolate the issue.

**Why this order matters:**
1. `zig build test` catches:
   - Syntax errors in Zig code
   - Type errors and API misuse
   - Unit test failures in parser, checker, lowerer, codegen
   - Exhaustive switch violations (missing cases for new ops/expressions)

2. Comprehensive test validates all features work together

**Current test counts:**
- 135+ Zig embedded tests (unit tests in source files)
- 1 comprehensive test + 65+ individual isolation tests

### Exhaustive Switches for New Features

When adding a new AST expression type, IR op, or SSA op, the exhaustive switch tests will **fail to compile**, reminding you to handle the new case everywhere:

- `check.zig`: "AST expr coverage - exhaustive" test
- `driver.zig`: "IR op coverage - exhaustive" test
- `driver.zig`: "SSA op coverage - exhaustive" test

This ensures new features are implemented across all compilation stages.

---

## Cross-Platform Testing (x86_64 on ARM64 Mac)

The cot compiler uses native target detection. To test x86_64 codegen on an ARM64 Mac:

### One-time setup: Build the Docker image
```bash
docker build --platform linux/amd64 -t cot-zig:0.15.2 -f Dockerfile.zig .
```

### Step 1: Build cot for x86_64 Linux
```bash
zig build -Dtarget=x86_64-linux-gnu
```

### Step 2: Compile and link in Docker
Use the `cot-zig:0.15.2` Docker image (has zig pre-installed for consistent linking):
```bash
# Compile .cot file + link with zig cc in Docker
docker run --platform linux/amd64 -v $(pwd):/cot -w /cot cot-zig:0.15.2 \
  sh -c "./zig-out/bin/cot tests/test_return.cot -o ignored 2>&1; \
         zig cc -o test test_return.o && ./test; echo Exit: \$?"
```

**IMPORTANT**:
- The `-o` option specifies the executable name but cot outputs .o files to the current working directory (uses input basename + .o)
- Must use `zig cc` (not bare `ld`) because `main` returns a value - C runtime's `_start` calls `exit(main())`
- Using bare `ld -e main` causes segfault because `ret` from main has nowhere to return to
- Test files are located in the `tests/` directory
- When compiling `tests/foo.cot`, the .o file is output as `./foo.o` (in cwd, not in tests/)

### Verified working test commands
```bash
# ARM64 (native macOS) - cot now uses zig cc for linking
zig build && ./zig-out/bin/cot tests/test_return.cot -o test 2>/dev/null && \
  ./test; echo "Exit: $?"

# x86_64 (Docker) - uses zig image for consistent linking
zig build -Dtarget=x86_64-linux-gnu
docker run --platform linux/amd64 -v $(pwd):/cot -w /cot cot-zig:0.15.2 \
  sh -c "./zig-out/bin/cot tests/test_return.cot -o ignored 2>&1; \
         zig cc -o test test_return.o && ./test; echo Exit: \$?"

# Run full x86_64 test suite in Docker
docker run --platform linux/amd64 -v $(pwd):/cot -w /cot cot-zig:0.15.2 ./run_tests_x86_64.sh

# Quick helper script (builds x86_64 + runs all Docker tests)
./docker_test.sh          # Run all x86_64 tests
./docker_test.sh test_foo # Run single test
```

### Quick x86_64 Test Workflow (OPTIONAL during bootstrap)

When implementing new features or fixing bugs after bootstrap is complete:

```bash
# 1. Build and run native tests
zig build && ./run_tests.sh

# 2. OPTIONAL: Build for x86_64 and run Docker tests
zig build -Dtarget=x86_64-linux-gnu && \
  docker run --platform linux/amd64 -v $(pwd):/cot -w /cot cot-zig:0.15.2 ./run_tests_x86_64.sh
```

**Note:** x86_64 testing is optional during bootstrap. After bootstrap, re-enable it to catch platform-specific codegen bugs.

---

## Register Safety for New Features

When adding operations that call runtime functions or produce multi-register results:

### Rules for Avoiding Register Clobbering

1. **Document register contracts** for each operation:
   - What registers does it expect inputs in?
   - What registers does it produce outputs in?
   - What registers does it clobber (caller-saved)?

2. **Handle nested expressions explicitly**. When an operation's input comes from another operation of the same type (e.g., nested str_concat), the result may already be in registers. Check for this case and move to argument registers if needed.

3. **Test nested expressions**. Always add tests like:
   - `var a = op1(op1(x, y), z)` - nested same operation
   - `var a = op2(op1(x, y))` - chained different operations

### Example: str_concat

```
x86_64:
- Inputs: rdi=ptr1, rsi=len1, rdx=ptr2, rcx=len2
- Outputs: rax=ptr, rdx=len
- When first arg is str_concat result: rax->rdi, rdx->rsi before loading arg2

AArch64:
- Inputs: x0=ptr1, x1=len1, x2=ptr2, x3=len2
- Outputs: x0=ptr, x1=len
- When first arg is str_concat result: already in x0/x1, no move needed
```

### Future Improvement: Proper Register Allocation

The current naive codegen assumes values are in specific registers. For more complex expressions, implement:
1. Linear scan register allocation
2. Spill slots for when registers exhausted
3. Live range analysis

---

## TODO: Go-Inspired Type Safety (High Priority)

The following improvements are needed to match Go's compiler robustness. These should be implemented before self-hosting to prevent cascading bugs.

### 1. Type-Aware Codegen

**Problem**: Current codegen checks alignment (`@mod(offset, 8) == 0`) to decide instruction width, which fails silently for small types at unaligned offsets.

**Go's approach**: Every SSA value has a type, and codegen uses type.Size() to select the appropriate load/store instruction (byte, half-word, word, double-word).

**Fix needed**:
- Always check `type_reg.sizeOf(value.type_idx)` in load/store codegen
- Use `ldrb`/`strb` for 1-byte types, `ldrh`/`strh` for 2-byte types, etc.
- Never silently skip operations due to alignment - either emit the right instruction or error

### 2. Proper Frame Layout Alignment

**Problem**: Our x86-centric frame layout assigns arbitrary negative offsets, causing ARM64 loads/stores to fail when locals aren't 8-byte aligned.

**Go's approach**: Stack slots are allocated with alignment appropriate to their type (1-byte aligned for u8, 8-byte aligned for int, etc.), with padding as needed.

**Fix needed**:
- Modify `FrameLayout` to align each local appropriately
- Or: ensure all locals are 8-byte aligned (wastes space but simpler)
- Track alignment in `Local` struct: `alignment: u32`

### 3. Type Coverage Tests

**Problem**: We lacked tests for small types (u8 enums) stored from function call results. The bug only surfaced when testing scanner_boot.cot.

**Go's approach**: Comprehensive tests for every type size in every context:
- Parameters (u8, u16, u32, u64, structs by value, structs by pointer)
- Return values (same variations)
- Struct fields (at various offsets)
- Array elements
- Nested combinations

**Tests to add**:
```bash
tests/test_u8_return.cot      # Function returning u8
tests/test_u8_param.cot       # Function with u8 parameter
tests/test_u8_struct_field.cot # Struct with u8 field at various offsets
tests/test_u16_*.cot          # Same for u16
tests/test_struct_return_*.cot # Struct returns of various sizes (8, 16, 17, 32 bytes)
```

### 4. Struct Return Calling Convention

**Problem**: Struct returns don't populate x0/rax. The IR emits `ret args=[0xFFFFFFFF]` as a sentinel but codegen ignores it.

**Go's approach**:
- Structs ≤ 16 bytes (ARM64) or ≤ 16 bytes (x86_64): returned in registers
- Larger structs: hidden pointer parameter (x8 on ARM64, first param on x86_64)

**Fix needed**:
- Detect struct return in lowering, allocate temp space
- For small structs: pack fields into x0/x1 (or rax/rdx)
- For large structs: implement hidden pointer convention

---

## Architecture Reference

See `go-inspired-architecture-improvements.md` for the compiler design we're following. The pipeline phases, IR representation, and optimization passes should match Go's approach - implemented in Zig, processing cot syntax.

## Current Goal

Bootstrap a minimal self-hosting compiler using Go's proven compiler architecture. Minimal language features, solid engineering foundation.

## When in Doubt

Ask John. Pause and clarify rather than guessing and building the wrong thing.
