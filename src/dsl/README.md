# DSL (Toy zkVM Assembly)

This folder contains a minimal, assembly-like DSL used to describe programs for the toy zkVM.
The DSL is intentionally small and line-oriented to keep parsing, execution, and AIR constraints simple.

## Lexical rules

- Programs are ASCII-oriented.
- Whitespace (`' '`, `'\t'`, `'\r'`) is ignored.
- Newlines (`'\n'`) terminate statements.
- Comments start with `#` and run until the end of the line.
- Identifiers are `[A-Za-z_][A-Za-z0-9_]*` (labels, registers).
- Registers are `r0`, `r1`, `r2`, `r3`.
- Integers are decimal.

## Grammar (EBNF)

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

## Instruction semantics 

Assume VM state `(pc, r0..r3, halted)`:

- `const rX, c` : set `rX := c`, `pc := pc + 1`
- `mov rX, rY`  : set `rX := rY`, `pc := pc + 1`
- `add rX, rY`  : set `rX := rX + rY`, `pc := pc + 1`
- `sub rX, rY`  : set `rX := rX - rY`, `pc := pc + 1`
- `jmp L`       : set `pc := addr(L)`
- `jnz rX, L`   : if `rX != 0` then `pc := addr(L)` else `pc := pc + 1`
- `halt`        : set `halted := 1` 

All arithmetic is performed over the VM field in the proving system.

## Example

```asm
# Sum 1..n (n in r0), result in r1
const r1, 0
const r2, 1

loop:
add r1, r0
sub r0, r2
jnz r0, loop
halt
```
