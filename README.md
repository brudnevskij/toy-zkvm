# toy-zkvm

Work in progress.

This project is a toy zkVM built from scratch in Rust. It includes a custom DSL, its own frontend pipeline (lexer, parser, resolver), and a VM execution model designed to later connect to an AIR/STARK-style proving system.

The goal is educational and experimental: to understand how a zkVM can be structured end to end, from source code written in a DSL, through execution, and eventually into zero-knowledge proof generation.

This is not intended to be production-ready. The design is still evolving, and parts of the system are incomplete or may change significantly.
