# Cot Compiler Documentation

Welcome to the Cot compiler documentation! This documentation is designed to teach you everything from compiler basics to the specific implementation details of Cot.

## Quick Start

If you're new to compilers, start here:

1. **[00_OVERVIEW.md](00_OVERVIEW.md)** - What is a compiler? How does code become executable?
2. **[02_ZIG_PRIMER.md](02_ZIG_PRIMER.md)** - Understanding Zig concepts used in the implementation

## The Compilation Pipeline

Deep dives into each stage of compilation:

| Stage | Document | What You'll Learn |
|-------|----------|-------------------|
| 1 | [Scanning](pipeline/10_SCANNING.md) | How source code becomes tokens |
| 2 | [Parsing](pipeline/11_PARSING.md) | How tokens become a syntax tree |
| 3 | [Type Checking](pipeline/12_TYPE_CHECKING.md) | How we verify code is correct |
| 4 | [IR Lowering](pipeline/13_IR_LOWERING.md) | How we simplify the syntax tree |
| 5 | [SSA Conversion](pipeline/14_SSA.md) | How we prepare for optimization |
| 6 | [Code Generation](pipeline/15_CODEGEN.md) | How we emit machine instructions |
| 7 | [Linking](pipeline/16_LINKING.md) | How we create an executable |

## CPU Fundamentals

Understanding the target machine:

| Topic | Document | What You'll Learn |
|-------|----------|-------------------|
| Basics | [CPU Basics](cpu/20_CPU_BASICS.md) | Registers, instructions, the fetch-decode-execute cycle |
| Stack | [Stack Frames](cpu/21_STACK_FRAMES.md) | How function calls work at the machine level |
| Calling | [Calling Conventions](cpu/22_CALLING_CONVENTIONS.md) | How functions pass arguments and return values |

## Worked Example

See the entire compilation process in action:

- **[30_WORKED_EXAMPLE.md](30_WORKED_EXAMPLE.md)** - Trace `return 42` through every stage

## Reference

Quick lookups for developers:

- **[Module Index](reference/40_MODULE_INDEX.md)** - Key functions and structs in each module

## Directory Structure

```
docs/
├── README.md                 # This file
├── 00_OVERVIEW.md           # High-level compiler overview
├── 02_ZIG_PRIMER.md         # Zig language concepts
├── 30_WORKED_EXAMPLE.md     # Complete compilation trace
├── pipeline/                # Compilation stages
│   ├── 10_SCANNING.md
│   ├── 11_PARSING.md
│   ├── 12_TYPE_CHECKING.md
│   ├── 13_IR_LOWERING.md
│   ├── 14_SSA.md
│   ├── 15_CODEGEN.md
│   └── 16_LINKING.md
├── cpu/                     # CPU fundamentals
│   ├── 20_CPU_BASICS.md
│   ├── 21_STACK_FRAMES.md
│   └── 22_CALLING_CONVENTIONS.md
└── reference/               # Quick reference
    └── 40_MODULE_INDEX.md
```

## Learning Paths

### "I want to understand compilers from scratch"

1. Start with [00_OVERVIEW.md](00_OVERVIEW.md)
2. Read the pipeline docs in order (10 through 16)
3. Try the [worked example](30_WORKED_EXAMPLE.md)

### "I want to understand the Zig implementation"

1. Read [02_ZIG_PRIMER.md](02_ZIG_PRIMER.md)
2. Look at the pipeline docs alongside the source code
3. Use the [Module Index](reference/40_MODULE_INDEX.md) for quick lookups

### "I want to understand how code runs on the CPU"

1. Start with [CPU Basics](cpu/20_CPU_BASICS.md)
2. Read about [Stack Frames](cpu/21_STACK_FRAMES.md)
3. Then [Code Generation](pipeline/15_CODEGEN.md)

### "I want to contribute to Cot"

1. Skim all docs to understand the architecture
2. Find the stage you want to work on
3. Read that stage's doc and source code together
4. Look at existing tests for examples

## Debug Flags

When working with the compiler, these flags show intermediate stages:

```bash
./zig-out/bin/cot file.cot --debug-ir      # Show IR
./zig-out/bin/cot file.cot --debug-ssa     # Show SSA
./zig-out/bin/cot file.cot --debug-codegen # Show instructions
./zig-out/bin/cot file.cot --disasm        # Disassemble output
```

## Related Files

- `CLAUDE.md` - Development guidelines and debugging tips
- `STATUS.md` - Current implementation status
- `ROADMAP.md` - Self-hosting roadmap
- `src/*.cot` - Cot wireframes (future self-hosted version)
- `src/*.zig` - Zig implementation (current bootstrap)
