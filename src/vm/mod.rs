mod exec;
mod instructions;
mod trace;

pub use exec::{VmError, VmState, step};
pub use instructions::{Instruction, Pc, Program, Reg};
pub use trace::{ExecutionRow, decode_row};
