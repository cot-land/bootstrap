# Go-Inspired Architecture Improvements for Cot Compiler

A systematic comparison of the Cot compiler (Zig, ~/cotlang/cot/src) with the Go compiler (~/learning/go/src/cmd/compile), documenting every architectural improvement that could benefit the Cot language.

## Executive Summary

After thorough analysis of both codebases:
- **Go Compiler**: 50 internal packages, 7-phase pipeline, sophisticated SSA with 50+ optimization passes
- **Cot Compiler**: 217 files (64K LOC), 8-phase pipeline, basic optimizations

This document identifies **35+ architectural improvements** organized by compiler phase.

---

## Table of Contents

1. [Overall Pipeline Architecture](#1-overall-pipeline-architecture)
2. [Parsing and AST](#2-parsing-and-ast)
3. [Type System](#3-type-system)
4. [IR Representation](#4-ir-representation)
5. [SSA Form and Control Flow](#5-ssa-form-and-control-flow)
6. [Optimization Passes](#6-optimization-passes)
7. [Inlining System](#7-inlining-system)
8. [Escape Analysis](#8-escape-analysis)
9. [Register Allocation](#9-register-allocation)
10. [Code Generation](#10-code-generation)
11. [Debugging and Tooling](#11-debugging-and-tooling)
12. [Concurrency and Performance](#12-concurrency-and-performance)

---

## 1. Overall Pipeline Architecture

### Current Cot Pipeline
```
Source → Lexer → Parser → Comptime → IR Lower → Type Check → Optimize → Bytecode Emit → VM
```

### Go's Pipeline
```
Source → Parse → Type Check (types2) → IR Construction → Middle-end Opts → Walk → SSA → Codegen
```

### Improvements

#### 1.1 Unified IR for Import/Export
**Go Pattern**: `internal/noder/` provides "Unified IR" - a serialized representation for:
- Efficient inlining across packages
- Generic instantiation
- Fast import/export of compiled code

**Cot Improvement**:
- Create a serialized IR format for `.clb` library files
- Enable cross-module inlining decisions
- Store pre-computed type information

**Files to modify**: `src/ir/ir.zig`, new `src/ir/unified.zig`

#### 1.2 Separate Type Checking Phase
**Go Pattern**: Type checking happens in `types2` BEFORE IR construction
- Clean separation of concerns
- Type errors reported before expensive lowering
- Type information available for IR construction

**Cot Current**: Type checking happens AFTER IR lowering in `compiler/type_checker.zig`

**Cot Improvement**:
- Move type checking to occur on AST before lowering
- Pass fully-typed AST to IR lowering phase
- Reduces wasted work on type-error files

**Files to modify**: `src/compiler/type_checker.zig`, `src/ir/lower.zig`

#### 1.3 Walk Phase for Desugaring
**Go Pattern**: `internal/walk/` phase handles:
- Order of evaluation
- Desugaring (switch→if chains, range→for loops)
- Builtin expansion (append, copy, make)
- Runtime call insertion

**Cot Improvement**:
- Add explicit walk phase between AST and IR
- Desugar complex constructs before lowering
- Simplifies IR lowering code

**Files to create**: `src/ir/walk.zig`

---

## 2. Parsing and AST

### Current Cot Strengths
- SoA-based NodeStore (12 bytes/node) - excellent cache locality
- StringInterner for deduplication
- Typed indices (StmtIdx, ExprIdx)
- Pratt parser for expressions

### Improvements

#### 2.1 Parallel Parsing
**Go Pattern**: Parse files concurrently with semaphore limiting open files
```go
// From gc/main.go
for _, f := range files {
    go func() { /* parse file */ }()
}
```

**Cot Improvement**:
- Parse source files in parallel using Zig's thread pool
- Aggregate errors after all parsing completes
- Significant speedup for multi-file projects

**Files to modify**: `src/parser/parser.zig`, `src/main.zig`

#### 2.2 Source Position Compression
**Go Pattern**: Uses `src.XPos` - a compact position type with:
- File/line/column encoded efficiently
- Separate `src.PosTable` for expansion
- 32-bit positions (not full structs)

**Cot Current**: `SourceLoc` is 4 bytes (line:u24, column:u8)

**Cot Improvement**: Already good, but consider:
- Add file index for multi-file support
- Consider `PosTable` pattern for debugging info

#### 2.3 Syntax Tree Pooling
**Go Pattern**: Syntax nodes allocated from pools, returned after use

**Cot Improvement**:
- Add node recycling to NodeStore
- Reuse freed nodes for subsequent allocations
- Reduces allocator pressure

**Files to modify**: `src/ast/node_store.zig`

---

## 3. Type System

### Current Cot
- Type union with 30+ variants
- Basic type checking after IR lowering
- Limited inference

### Go Innovations

#### 3.1 Dual Type System
**Go Pattern**: Two type systems:
- `types2`: Full type checking, generics support, inference
- `types`: Compiler-internal representation for IR

**Cot Improvement**:
- Create separate "checked types" representation
- Frontend types for checking, backend types for codegen
- Enables richer type operations without IR bloat

**Files to create**: `src/types/checked.zig`, `src/types/backend.zig`

#### 3.2 Lazy Type Computation
**Go Pattern**: Type sets computed on-demand, cached:
```go
func (t *Interface) typeSet() *_TypeSet {
    if t.tset != nil { return t.tset }
    t.tset = computeTypeSet(...)
    return t.tset
}
```

**Cot Improvement**:
- Defer expensive type computations
- Cache computed results
- Avoid recomputing for unchanged types

**Files to modify**: `src/ir/ir.zig` (Type definitions)

#### 3.3 Unification-Based Inference
**Go Pattern**: `types2/unify.go` implements:
- Handle-based unification (shared pointers for unified types)
- Two modes: `assign` (covariant) and `exact` (structural)
- Cycle detection and breaking

**Cot Improvement**:
- Implement proper type inference using unification
- Support constraints and type parameter bounds
- Enable "let x = ..." to infer complex types

**Files to create**: `src/compiler/unify.zig`

#### 3.4 Context-Based Deduplication
**Go Pattern**: `types2/context.go`:
- Hash instances by (origin, type_args)
- Prevents unbounded generic instantiation
- Thread-safe with mutex protection

**Cot Improvement**:
- Implement generic type instance caching
- Prevents duplicate instantiations
- Reduces memory for generic-heavy code

**Files to create**: `src/compiler/type_context.zig`

#### 3.5 Delayed Actions Queue
**Go Pattern**: FIFO queue for deferred type operations:
```go
type action struct {
    version goVersion
    f       func()
    desc    *actionDesc
}
```
Used for: circular type resolution, interface computation, validation

**Cot Improvement**:
- Add delayed action system to type checker
- Handle forward references elegantly
- Support recursive type definitions

**Files to modify**: `src/compiler/type_checker.zig`

---

## 4. IR Representation

### Current Cot IR
- Instruction union with 100+ variants
- Basic blocks with Value references
- Simple CFG structure

### Go Innovations

#### 4.1 Bidirectional CFG Edges
**Go Pattern**: `ssa/block.go`:
```go
type Edge struct {
    b *Block  // target block
    i int     // index in target's Preds/Succs
}
```
Enables O(1) CFG mutation

**Cot Improvement**:
- Store bidirectional edge indices
- Enable efficient predecessor/successor removal
- Critical for optimization passes

**Files to modify**: `src/ir/ir.zig` (Block definition)

#### 4.2 Use Count Tracking
**Go Pattern**: Every Value tracks use count:
- Incremented on AddArg
- Decremented on removal
- `Uses == 0` indicates dead code

**Cot Improvement**:
- Add use counting to IR values
- Enable incremental dead code detection
- Eliminate need for full DCE passes

**Files to modify**: `src/ir/ir.zig` (Value definition)

#### 4.3 Memory Value Representation
**Go Pattern**: `memory` type represents global memory state:
- Memory-accessing ops depend on memory value
- Ensures correct ordering of memory operations
- Enables safe reordering of non-memory ops

**Cot Improvement**:
- Explicit memory SSA values
- Track memory dependencies properly
- Enable more aggressive optimization

**Files to modify**: `src/ir/ir.zig`, `src/ir/lower.zig`

#### 4.4 Auxiliary Data Pattern
**Go Pattern**: Values have `Aux` and `AuxInt` fields:
- `AuxInt`: int64 for constants, shifts, etc.
- `Aux`: interface{} for symbols, call targets

**Cot Improvement**:
- Standardize auxiliary data representation
- Reduces instruction variant explosion
- Cleaner pattern matching in optimizations

---

## 5. SSA Form and Control Flow

### Current Cot
- Has phi nodes (recently added)
- Basic CFG structure
- Limited SSA-based analysis

### Go Innovations

#### 5.1 Sparse Dominator Tree
**Go Pattern**: `ssa/sparsetree.go`:
- Lengauer-Tarjan for dominators
- O(1) LCA (Lowest Common Ancestor) queries
- Sparse tree for efficient dominance checks

**Cot Improvement**:
- Implement proper dominator tree
- Add sparse tree for efficient queries
- Foundation for many optimizations

**Files to create**: `src/ir/dom.zig`, `src/ir/sparse_tree.zig`

#### 5.2 Loop Detection and Analysis
**Go Pattern**: `ssa/loopbce.go`:
- Induction variable detection
- Loop bounds analysis
- Loop-invariant code motion

**Cot Improvement**:
- Add loop detection pass
- Identify induction variables
- Enable loop-specific optimizations

**Files to create**: `src/ir/loop.zig`

#### 5.3 Critical Edge Splitting
**Go Pattern**: Before register allocation, split critical edges:
- Block with >1 pred AND >1 succ gets intermediate block
- Enables proper phi placement

**Cot Improvement**:
- Add critical edge splitting pass
- Run before register allocation
- Simplifies regalloc implementation

**Files to create**: `src/ir/critical.zig`

#### 5.4 Block Scheduling
**Go Pattern**: `ssa/schedule.go`:
- Priority-based value ordering within blocks
- Respects memory dependencies
- Minimizes register pressure

**Cot Improvement**:
- Add value scheduling within blocks
- Optimize for register usage
- Reduce spills

**Files to create**: `src/ir/schedule.zig`

---

## 6. Optimization Passes

### Current Cot
- Constant folding
- Dead code elimination
- Tail call optimization
- Basic inlining

### Go's 50+ Passes

#### 6.1 Rewrite Rule System
**Go Pattern**: Code-generated optimization rules:
- `_gen/*.rules` files define patterns
- Generated into `rewriteXXX.go` files
- Pattern matching with conditions

**Cot Improvement**:
- Create declarative rewrite rule language
- Generate optimizers from rules
- Easier to add new optimizations

**Files to create**: `rules/generic.rules`, `src/ir/rewrite_gen.zig`

#### 6.2 Common Subexpression Elimination
**Go Pattern**: `ssa/cse.go`:
- Partition refinement algorithm
- O(n log n) per iteration
- Handles commutative operations

**Cot Current**: No CSE implementation

**Cot Improvement**:
- Implement partition-based CSE
- Handle commutative ops
- Significant performance gains

**Files to create**: `src/ir/cse.zig`

#### 6.3 Copy Elimination
**Go Pattern**: `ssa/copyelim.go`:
- Transitive copy chain following
- Cycle detection (tortoise-hare)
- Path compression

**Cot Improvement**:
- Add copy elimination pass
- Run early in optimization pipeline
- Reduces register pressure

**Files to create**: `src/ir/copyelim.zig`

#### 6.4 Prove Pass (Bounds Check Elimination)
**Go Pattern**: `ssa/prove.go`:
- Tracks relations (lt, eq, gt) between values
- Maintains signed/unsigned min/max ranges
- Proves bounds checks unnecessary

**Cot Improvement**:
- Implement range tracking
- Eliminate redundant bounds checks
- Major performance win for array code

**Files to create**: `src/ir/prove.zig`

#### 6.5 Nil Check Elimination
**Go Pattern**: `ssa/nilcheck.go`:
- Walk dominator tree tracking non-nil values
- Inherited facts from OpAddr, OpAddPtr, etc.
- Phi nodes: non-nil if all args non-nil

**Cot Improvement**:
- Track known non-null pointers
- Eliminate redundant null checks
- Important for optional types

**Files to create**: `src/ir/nilcheck.zig`

#### 6.6 Dead Store Elimination
**Go Pattern**: `ssa/deadstore.go`:
- Track shadowed memory ranges
- Eliminate stores overwritten before read
- Works within basic blocks

**Cot Improvement**:
- Implement shadow range tracking
- Eliminate dead stores
- Reduce memory traffic

**Files to create**: `src/ir/deadstore.zig`

#### 6.7 Phi Optimization
**Go Pattern**: `ssa/phiopt.go`:
- Pattern: `if a { x = true } else { x = false }`
- Transform to `x = a`
- Convert to And/Or/Not operations

**Cot Improvement**:
- Add phi optimization pass
- Simplify boolean control flow
- Reduce branch overhead

**Files to modify**: `src/ir/optimize.zig`

#### 6.8 Fixed-Point Iteration Framework
**Go Pattern**: `ssa/rewrite.go`:
```go
func applyRewrite(f *Func, rb, rv func) {
    for {
        change := false
        for _, b := range f.Blocks {
            if rb(b) { change = true }
            for _, v := range b.Values {
                if rv(v) { change = true }
            }
        }
        if !change { break }
    }
}
```

**Cot Improvement**:
- Standardize optimization iteration
- Cycle detection (limit iterations)
- Clear convergence handling

**Files to modify**: `src/ir/optimize.zig`

---

## 7. Inlining System

### Current Cot
- Basic inlining in `optimize.zig`
- No cost model
- No cross-module inlining

### Go Innovations

#### 7.1 Budget-Based Cost Model
**Go Pattern**: `inline/inl.go`:
```
inlineMaxBudget = 80 nodes
inlineExtraCallCost = 57
inlineParamCallCost = 17
inlineExtraThrowCost = 80
```

**Cot Improvement**:
- Implement node budget system
- Assign costs to operations
- Balance code size vs performance

**Files to modify**: `src/ir/optimize.zig` (inline section)

#### 7.2 Two-Pass Inlining
**Go Pattern**:
1. `CanInline()`: Analyze each function for inlinability
2. `InlineCalls()`: Expand calls at call sites

**Cot Improvement**:
- Separate inlinability analysis from expansion
- Cache inlinability decisions
- Enable smarter call-site decisions

#### 7.3 Hairy Visitor Pattern
**Go Pattern**: Walk AST computing "hairiness" (cost):
- Special handling for each node type
- Cost adjustments for optimizable patterns
- Hard blocks (go/defer/recover)

**Cot Improvement**:
- Implement cost visitor
- Special cases for Cot constructs
- Identify inlining blockers

#### 7.4 Heuristics-Based Scoring
**Go Pattern**: `inline/inlheur/`:
- Context-sensitive adjustments
- Parameter analysis (constants to conditions)
- Return value flow analysis
- PGO integration

**Cot Improvement**:
- Add heuristic scoring system
- Adjust for call context
- Better inlining decisions

**Files to create**: `src/ir/inline_heur.zig`

#### 7.5 Closure Inlining
**Go Pattern**:
- Closures called once get 2x budget
- `inlineClosureCalledOnceCost = 800`
- Single-call closures almost always inline

**Cot Improvement**:
- Track closure call sites
- Generous budget for single-use closures
- Important for functional patterns

---

## 8. Escape Analysis

### Current Cot
- Basic escape analysis in `src/compiler/escape_analysis.zig`
- Limited interprocedural analysis

### Go Innovations

#### 8.1 Graph-Based Algorithm
**Go Pattern**: `escape/escape.go`:
- Build directed weighted graph
- Vertices = allocations (locations)
- Edges = assignments with dereference counts
- Bellman-Ford to find minimal paths

**Cot Improvement**:
- Implement graph-based analysis
- Track dereference depths
- More precise escape decisions

**Files to modify**: `src/compiler/escape_analysis.zig`

#### 8.2 Parameter Leak Tagging
**Go Pattern**: `escape/leaks.go`:
```
leakHeap = 0     // Flows to heap
leakMutator = 1  // Mutated
leakCallee = 2   // Flows to callee
leakResult0+ = 3+ // Flows to result N
```

**Cot Improvement**:
- Tag parameters with leak information
- Store in function signatures
- Enable interprocedural analysis

#### 8.3 Closure Capture Decision
**Go Pattern**:
```
if !addrtaken && !reassigned && size <= 128:
    capture by value
else:
    capture by reference (heap allocate)
```

**Cot Improvement**:
- Implement capture mode analysis
- Prefer by-value for small, immutable captures
- Reduce closure allocations

---

## 9. Register Allocation

### Current Cot
- Basic register allocation in `src/ir/regalloc.zig`
- 16 virtual registers (r0-r15)
- Simple spilling

### Go Innovations

#### 9.1 Linear Scan with Lookahead
**Go Pattern**: `ssa/regalloc.go`:
- Process function as one long block
- Allocate just before use
- Spill based on farthest next use

**Cot Improvement**:
- Implement lookahead-based spilling
- Choose spill victim by next-use distance
- Reduce spill overhead

**Files to modify**: `src/ir/regalloc.zig`

#### 9.2 Use Chain Tracking
**Go Pattern**:
```go
type use struct {
    dist int32   // distance from start
    pos  src.XPos
    next *use    // linked list
}
```

**Cot Improvement**:
- Build use chains for each value
- Track exact positions of uses
- Enable optimal spill decisions

#### 9.3 Merge Point Handling
**Go Pattern**: Insert fixup code at merge points:
- Ensure consistent register state
- Handle phi-like situations
- Critical edges already split

**Cot Improvement**:
- Add merge point fixup
- Handle CFG joins correctly
- Proper phi resolution

#### 9.4 Callee-Saved Register Optimization
**Go Pattern**: Track callee-saved registers:
- Avoid saving registers not modified
- Track which registers need restoration
- Efficient function prologues

**Cot Current**: Fixed callee-saved set (r8-r13)

**Cot Improvement**:
- Analyze actual register usage
- Save only modified registers
- Smaller stack frames

---

## 10. Code Generation

### Current Cot
- Direct bytecode emission
- Instruction encoding in `emit_instruction.zig`

### Go Innovations

#### 10.1 Lowering Phases
**Go Pattern**: Two lowering stages:
- `lower`: Generic → architecture-specific
- `lateLower`: Final architecture tweaks

**Cot Improvement** (for native target):
- Separate generic and target-specific lowering
- Enable multiple backends
- Cleaner architecture support

#### 10.2 Instruction Selection via Patterns
**Go Pattern**: Pattern matching for instruction selection:
```
(Add (Const [c]) x) → (ADDQconst x [c])
```

**Cot Improvement**:
- Pattern-based bytecode selection
- Combine operations (load+add, etc.)
- More efficient bytecode

#### 10.3 Peephole Optimization
**Go Pattern**: Architecture-specific peepholes:
- Combine adjacent operations
- Use specialized instructions
- Address mode folding

**Cot Improvement**:
- Add bytecode peephole pass
- Combine instruction sequences
- Reduce instruction count

**Files to create**: `src/ir/peephole.zig`

---

## 11. Debugging and Tooling

### Current Cot
- `cot trace` for execution tracing
- `cot debug` for interactive debugging
- `cot validate` for bytecode validation

### Go Innovations

#### 11.1 SSA HTML Visualization
**Go Pattern**: `GOSSAFUNC=Foo go build` generates `ssa.html`:
- Shows each SSA pass
- Before/after comparison
- Value highlighting

**Cot Improvement**:
- Add HTML IR visualization
- Show optimization passes
- Debug optimization issues

**Files to create**: `src/ir/html_dump.zig`

#### 11.2 Pass Statistics
**Go Pattern**: Each pass tracks:
- Time spent
- Memory allocated
- Custom statistics

**Cot Improvement**:
- Add pass-level statistics
- Profile optimization impact
- Identify bottlenecks

#### 11.3 Phase Dumping
**Go Pattern**: `-d ssa/prove/debug=1` for per-pass debugging

**Cot Improvement**:
- Add per-pass debug flags
- Dump intermediate states
- Easier optimization debugging

---

## 12. Concurrency and Performance

### Current Cot
- Single-threaded compilation
- Sequential file processing

### Go Innovations

#### 12.1 Parallel File Parsing
**Go Pattern**: Parse files concurrently with work stealing

**Cot Improvement**:
- Parallel parsing with Zig's thread pool
- Aggregate results and errors
- Major speedup for large projects

#### 12.2 Concurrent Function Compilation
**Go Pattern**: Compile functions in parallel:
- Queue functions for compilation
- Worker pool processes queue
- Coordinate on shared state

**Cot Improvement**:
- Parallel function optimization
- Independent SSA passes per function
- Better multi-core utilization

#### 12.3 Cache Allocators
**Go Pattern**: Pool allocators for hot paths:
```go
f.newSparseSet(n)
f.newSparseMap(n)
```

**Cot Improvement**:
- Add arena allocators for passes
- Pool common allocations
- Reduce allocator pressure

#### 12.4 Incremental Compilation
**Go Pattern**: Unified IR enables:
- Skip unchanged files
- Cache optimization results
- Fast rebuilds

**Cot Improvement**:
- Hash source files
- Cache compiled modules
- Only recompile changed files

**Files to create**: `src/framework/incremental.zig`

---

## Priority Ranking

### High Priority (Immediate Impact)

1. **Separate Type Checking Phase** (1.2) - Cleaner architecture, early error detection
2. **CSE Implementation** (6.2) - Major optimization win
3. **Bidirectional CFG Edges** (4.1) - Foundation for many opts
4. **Budget-Based Inlining** (7.1) - Better code size/perf balance
5. **Dominator Tree** (5.1) - Required for many analyses

### Medium Priority (Significant Value)

6. **Prove Pass** (6.4) - Bounds check elimination
7. **Dead Store Elimination** (6.6) - Memory optimization
8. **Graph-Based Escape Analysis** (8.1) - Better stack allocation
9. **Use Count Tracking** (4.2) - Incremental DCE
10. **Rewrite Rule System** (6.1) - Maintainable optimizations

### Lower Priority (Future Enhancements)

11. **Parallel Parsing** (2.1) - Build speed
12. **HTML Visualization** (11.1) - Developer experience
13. **Unified IR** (1.1) - Cross-module optimization
14. **Dual Type System** (3.1) - Advanced generics
15. **Concurrent Compilation** (12.2) - Build speed

---

## Implementation Order

### Phase 1: Infrastructure (Weeks 1-2)
- Bidirectional CFG edges
- Use count tracking
- Dominator tree computation
- Critical edge splitting

### Phase 2: Core Optimizations (Weeks 3-4)
- Common subexpression elimination
- Copy elimination
- Phi optimization
- Fixed-point iteration framework

### Phase 3: Advanced Analysis (Weeks 5-6)
- Prove pass (range analysis)
- Nil check elimination
- Dead store elimination
- Graph-based escape analysis

### Phase 4: Inlining (Weeks 7-8)
- Budget-based cost model
- Two-pass inlining
- Heuristic scoring
- Closure optimization

### Phase 5: Architecture (Weeks 9-10)
- Separate type checking phase
- Walk/desugar phase
- Pass statistics
- HTML visualization

---

## References

- Go compiler source: `~/learning/go/src/cmd/compile/`
- Cot compiler source: `~/cotlang/cot/src/`
- Go SSA README: `internal/ssa/README.md`
- types2 implementation: `internal/types2/`
- Inline heuristics: `internal/inline/inlheur/`
- Escape analysis: `internal/escape/`

---

## Appendix: File Mapping

| Go File | Purpose | Cot Equivalent |
|---------|---------|----------------|
| `ssa/compile.go` | SSA pipeline orchestration | `ir/optimize.zig` |
| `ssa/value.go` | SSA value representation | `ir/ir.zig` |
| `ssa/block.go` | Basic block definition | `ir/ir.zig` |
| `ssa/cse.go` | Common subexpression elimination | (new) `ir/cse.zig` |
| `ssa/deadcode.go` | Dead code elimination | `ir/optimize.zig` |
| `ssa/prove.go` | Bounds check elimination | (new) `ir/prove.zig` |
| `ssa/regalloc.go` | Register allocation | `ir/regalloc.zig` |
| `types2/check.go` | Type checker driver | `compiler/type_checker.zig` |
| `types2/unify.go` | Type unification | (new) `compiler/unify.zig` |
| `inline/inl.go` | Function inlining | `ir/optimize.zig` |
| `escape/escape.go` | Escape analysis | `compiler/escape_analysis.zig` |

---

*Document created: 2026-01-09*
*Based on comprehensive analysis of Go 1.23+ and Cot compilers*
