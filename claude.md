# Cot 0.2 Development Guidelines

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

# 2. THEN: Build the compiler and run native tests
zig build
./run_tests.sh                    # ARM64 macOS native tests

# 3. FINALLY: ALWAYS run x86_64 tests in Docker (catches platform-specific bugs)
zig build -Dtarget=x86_64-linux-gnu
docker run --platform linux/amd64 -v $(pwd):/cot -w /cot cot-zig:0.15.2 ./run_tests_x86_64.sh
```

**IMPORTANT: Always run BOTH native AND x86_64 tests.** The x86_64 tests catch platform-specific codegen bugs that won't appear on ARM64. Never skip the Docker tests.

**Why this order matters:**
1. `zig build test` catches:
   - Syntax errors in Zig code
   - Type errors and API misuse
   - Unit test failures in parser, checker, lowerer, codegen
   - Exhaustive switch violations (missing cases for new ops/expressions)

2. Native binary tests verify ARM64 codegen works

3. x86_64 Docker tests verify cross-platform codegen (critical for self-hosting)

**Current test counts:**
- 135+ Zig embedded tests (unit tests in source files)
- 39 binary tests (.cot test files)

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
```

---

## Architecture Reference

See `go-inspired-architecture-improvements.md` for the compiler design we're following. The pipeline phases, IR representation, and optimization passes should match Go's approach - implemented in Zig, processing cot syntax.

## Current Goal

Bootstrap a minimal self-hosting compiler using Go's proven compiler architecture. Minimal language features, solid engineering foundation.

## When in Doubt

Ask John. Pause and clarify rather than guessing and building the wrong thing.
