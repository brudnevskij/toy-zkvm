mod exec;
mod instructions;

pub use exec::{VmError, VmState, step};
pub use instructions::{Instruction, Pc, Program, Reg};
