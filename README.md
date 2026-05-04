# toy-zkVM

A small STARK-style zero-knowledge virtual machine written in Rust.

`toy-zkVM` is an educational implementation of a proving pipeline for a tiny virtual
machine. It includes a custom assembly-like DSL, a register-based VM, execution
trace generation, AIR constraints, Merkle commitments, a Fiat-Shamir transcript,
FRI-style low-degree testing, and an end-to-end prover/verifier flow.

The goal of this project is to understand how the main components of a STARK-style
zkVM fit together from first principles.

---

## What this project demonstrates

This repository implements a minimal zkVM stack end to end:

- a tiny assembly-like DSL
- lexer, parser, and label resolver
- a register-based virtual machine
- execution trace generation over a finite field
- AIR constraints for VM correctness
- quotient/composition evaluation over a shifted low-degree extension domain
- Merkle commitments for trace openings
- Fiat-Shamir transcript for non-interactive challenges
- FRI-style low-degree testing
- proof generation and verification tests

---

## High-level pipeline

```text
Source program
    |
    v
Lexer / Parser / Resolver
    |
    v
VM instructions
    |
    v
VM execution
    |
    v
Execution trace
    |
    v
AIR constraints
    |
    v
Composition / quotient evaluations
    |
    v
Merkle commitments + Fiat-Shamir + FRI
    |
    v
Proof
    |
    v
Verifier
```

At a high level, the prover executes a program, records the VM state at each step,
turns the execution into a trace table, checks the trace against AIR constraints,
commits to low-degree extensions of the trace, and produces a proof that the trace
is consistent with the VM semantics.

The verifier checks Merkle openings, recomputes local constraint evaluations at
queried positions, and verifies the FRI proof.

---


### Main modules

| Module | Purpose |
|---|---|
| `src/dsl` | Lexer, parser, AST, and label resolver for the toy DSL |
| `src/vm` | Instruction set, VM execution, and execution-row generation |
| `src/air` | Generic AIR abstractions and trace-table representation |
| `src/backend` | Merkle tree, Fiat-Shamir transcript, and FRI backend |
| `src/zkvm` | Public parameters, prover, verifier, and VM AIR constraints |
| `src/examples` | Fibonacci examples and demo computations |
| `tests` | End-to-end tests for the DSL, VM, AIR, and proof pipeline |

---

## The toy VM

- four registers: `r0`, `r1`, `r2`, `r3`
- a program counter: `pc`
- a halt flag: `halted`
- a small instruction set
- execution rows that can be converted into an AIR trace

All register values are represented as field elements in the proving system.

---

## Instruction set

| Instruction | Meaning |
|---|---|
| `const rX, c` | Set register `rX := c`, then increment `pc` |
| `mov rX, rY` | Copy `rY` into `rX`, then increment `pc` |
| `add rX, rY` | Set `rX := rX + rY`, then increment `pc` |
| `sub rX, rY` | Set `rX := rX - rY`, then increment `pc` |
| `jmp L` | Jump to label `L` |
| `jnz rX, L` | Jump to label `L` if `rX != 0`; otherwise continue |
| `halt` | Halt execution |

---

## Example DSL program

This program computes a Fibonacci-style loop using the four VM registers.

```asm
const r0, 0
const r1, 1
const r3, 20

loop:
mov r2, r1
add r1, r0
mov r0, r2
const r2, 1
sub r3, r2
jnz r3, loop
halt
```

Informally:

- `r0` stores the previous Fibonacci value
- `r1` stores the current Fibonacci value
- `r2` is temporary storage
- `r3` is the loop counter
- `jnz r3, loop` keeps the loop running while the counter is nonzero

The VM executes this program, records each step, pads the trace to a power-of-two
length, and then proves that the trace satisfies the VM AIR.

---

## What is being proven?

The prover shows that a committed execution trace is valid with respect to the VM
AIR.

In other words, the proof is meant to show:

> “I know a VM execution trace that starts from the expected initial state and follows
> the instruction semantics of this VM until it halts.”

The AIR constraints enforce properties such as:

- correct initial state
- boolean opcode selector columns
- exactly one active instruction per row
- valid register indices
- correct `pc` transitions
- correct `const`, `mov`, `add`, and `sub` semantics
- correct unconditional jump behavior
- correct conditional jump behavior for `jnz`
- correct halt behavior
- correct padding after halt
- preservation of registers that should not change

---

## Execution trace

Each VM step is decoded into an execution row. The trace currently contains the
following columns:

| Column | Meaning |
|---|---|
| `t` | Time-step column |
| `pc` | Program counter |
| `r0`, `r1`, `r2`, `r3` | VM registers |
| `halted` | Halt flag |
| `s_const` | Selector for `const` |
| `s_mov` | Selector for `mov` |
| `s_add` | Selector for `add` |
| `s_sub` | Selector for `sub` |
| `s_jmp` | Selector for `jmp` |
| `s_jnz` | Selector for `jnz` |
| `s_halt` | Selector for `halt` |
| `a` | First operand register index |
| `b` | Second operand register index |
| `imm` | Immediate value |
| `target` | Jump target |
| `jnz_taken` | Whether a conditional jump was taken |
| `jnz_taken_inverse` | Auxiliary inverse used for `jnz` constraints |

The selector columns encode which instruction is active at each step. For a valid
execution row, exactly one opcode selector should be equal to `1`.

---

## AIR constraints

The VM AIR is built from multiple groups of constraints.

### Structural constraints

These enforce basic shape and validity properties:

- opcode selectors are boolean
- `halted` is boolean
- `jnz_taken` is boolean
- opcode selectors are one-hot
- register indices are in `{0, 1, 2, 3}`
- unused operands are zero
- `jnz` auxiliary columns are zero when the row is not a `jnz` row

### Initialization constraints

These enforce that the VM starts from the expected initial state:

- `pc = 0`
- `r0 = r1 = r2 = r3 = 0`
- `halted = 0`

### Transition constraints

These enforce instruction semantics across consecutive rows:

- `const` writes an immediate into a destination register
- `mov` copies from source to destination
- `add` updates the destination register by addition
- `sub` updates the destination register by subtraction
- ordinary instructions increment `pc`
- `jmp` sets `pc` to the target
- `jnz` either jumps or falls through depending on the condition register
- `halt` transitions into the halted state

### Preservation constraints

These ensure that registers not affected by an instruction remain unchanged.

For example, if an instruction writes only to `r0`, then `r1`, `r2`, and `r3`
must be preserved across that transition.

### Halt and padding constraints

After the VM halts, the trace is padded by repeating the halted state until the
trace reaches a power-of-two length. The AIR enforces that the halted state remains
frozen during this padding region.

---

## Cryptographic backend

The backend contains the minimal components needed for a STARK-style proving
flow.

### Merkle commitments

The prover commits to evaluation vectors using Merkle trees. The verifier later
checks Merkle authentication paths for queried positions.

Implementation:

```text
src/backend/merkle.rs
```

### Fiat-Shamir transcript

The transcript turns the protocol non-interactive by deriving verifier challenges
from previously absorbed public data and commitments.

Implementation:

```text
src/backend/transcript.rs
```

### FRI-style low-degree testing

The FRI component is used to test that committed evaluations are consistent with
a low-degree polynomial.

Implementation:

```text
src/backend/fri.rs
```

---

## Prover and verifier

The high-level zkVM API lives in:

```text
src/zkvm
```

The main pieces are:

| File | Purpose |
|---|---|
| `params.rs` | Public parameters for the proof system |
| `prover.rs` | Proof generation |
| `verifier.rs` | Proof verification |
| `constraints.rs` | VM AIR constraints |
| `mod.rs` | Public zkVM exports |

The prover takes:

- a trace table
- an AIR instance
- a transcript
- public parameters

and returns a proof.

The verifier takes:

- the proof
- the same AIR
- a transcript initialized with the same label/seed
- the same public parameters

and either accepts or rejects.


## Getting started

### Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/toy-zkvm.git
cd toy-zkvm
```

### Run all tests

```bash
cargo test
```

### Run the DSL/VM pipeline tests

```bash
cargo test vm_pipeline
```

### Run VM AIR tests

```bash
cargo test vm_air_e2e
```

### Run proof-generation tests

```bash
cargo test vm_fib_proof_e2e
```

### Show proof/verification timings from the Fibonacci proof test

```bash
cargo test prove_and_verify_fibonacci_vm_trace_with_current_air -- --nocapture
```

---

## Current test coverage

The test suite covers several layers of the system.

### DSL and VM pipeline

The pipeline tests check that source programs can be compiled and executed:

- `const` followed by `halt`
- register addition
- register copy with `mov`
- unconditional jumps
- conditional jumps when taken
- conditional jumps when not taken
- missing-label compile errors
- step-limit errors for infinite loops

### VM AIR

The AIR tests check that generated traces satisfy the VM constraints.

### Proof pipeline

The proof tests check that valid VM traces can be proven and verified using the
current STARK-style backend.

Examples include:

- proving a simple `const r0, 7; halt` program
- proving a Fibonacci VM trace

---

## Minimal example from tests

The following is the shape of an end-to-end proof test:

```rust
use ark_bn254::Fr;
use toy_zkvm::{
    backend::{FriOptions, Transcript},
    test_utils::{pick_coset_shift, pick_domain},
    vm::VmAir,
    zkvm::{ZkvmPublicParameters, prove, verify},
};

let source = r#"
    const r0, 7
    halt
"#;

// Helper used in tests:
// source -> compile -> VM execution -> execution trace
let trace = run_program_to_trace(source, 16, 16);

let air = VmAir::<Fr>::default();

let blowup = 16usize;
let lde_size = trace.n() * blowup;
let shift = pick_coset_shift(lde_size);
let trace_domain = pick_domain(trace.n());
let lde_domain = pick_domain(lde_size);

let public_params = ZkvmPublicParameters {
    trace_domain,
    lde_domain,
    shift,
    fri_options: FriOptions {
        max_degree: trace.n() * 2,
        max_remainder_degree: 1,
        query_number: 64,
        shift,
    },
};

let label = b"transcript";
let seed = b"vm_const_halt";

let mut prover_tx = Transcript::new(label, seed);
let proof = prove(&trace, &air, &mut prover_tx, &public_params)
    .expect("proof generation should succeed");

let mut verifier_tx = Transcript::new(label, seed);
verify(&proof, &air, &mut verifier_tx, &public_params)
    .expect("verification should succeed");
```

---

## DSL grammar

The DSL is intentionally small and line-oriented.

```ebnf
program        ::= { line } EOF ;

line           ::= { newline }
                | statement newline
                | statement EOF
                ;

statement      ::= label
                | instruction
                ;

label          ::= identifier ":" ;

instruction    ::= const_instr
                | mov_instr
                | add_instr
                | sub_instr
                | jmp_instr
                | jnz_instr
                | halt_instr
                ;

const_instr    ::= "const" reg "," number ;
mov_instr      ::= "mov"  reg "," reg ;
add_instr      ::= "add"  reg "," reg ;
sub_instr      ::= "sub"  reg "," reg ;

jmp_instr      ::= "jmp" identifier ;
jnz_instr      ::= "jnz" reg "," identifier ;

halt_instr     ::= "halt" ;

reg            ::= "r0" | "r1" | "r2" | "r3" ;
identifier     ::= ident_start { ident_continue } ;
ident_start    ::= "_" | "A".."Z" | "a".."z" ;
ident_continue ::= ident_start | "0".."9" ;

number         ::= digit { digit } ;
digit          ::= "0".."9" ;

newline        ::= "\n" ;
```

---

## Limitations

This repository is intentionally minimal. Current limitations include:

- not production secure
- not audited
- tiny custom instruction set
- no memory model
- no stack
- no syscalls
- no general-purpose Rust/C compilation target
- no optimized prover
- no serious parameter/security analysis
- no zero-knowledge masking/blinding layer
- educational FRI/STARK-style backend only
- proof format and APIs may change

The implementation is best understood as a learning project that exposes the moving
parts of a zkVM, rather than as a deployable cryptographic system.

---

## Future work

Possible directions for improvement:

- add memory constraints
- add a stack model
- add richer instructions
- add public inputs and public outputs
- improve the proof format
- add better examples and benchmarks
- add zero-knowledge blinding
- improve soundness/security parameter documentation
- make the DSL more ergonomic
- add a CLI for proving/verifying programs
- add more negative tests for invalid traces
- compare the design with real zkVM architectures

---

## Status

Work in progress.

The current repository already includes the main components of a toy STARK-style
zkVM pipeline, but the design is still experimental and subject to change.


---

## Acknowledgements

This project was developed as part of my MSc thesis work on the design and
implementation of a toy STARK-based zero-knowledge virtual machine.
