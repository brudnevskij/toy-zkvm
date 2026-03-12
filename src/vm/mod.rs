mod air;
mod exec;
mod instructions;
mod trace;

pub use air::VmAir;
pub use exec::{VmError, VmState, run_rows, step};
pub use instructions::{Instruction, Pc, Program, Reg};
pub use trace::{ExecutionRow, TraceColumn, decode_row, rows_to_trace_table};
