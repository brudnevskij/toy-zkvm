use ark_bn254::Fr;
use ark_ff::Zero;
use thiserror::Error;
use toy_zkvm::{
    dsl::{CompileError, compile},
    vm::{ExecutionRow, VmError, VmState, run_rows},
};

#[derive(Error, Debug)]
pub enum PipelineError {
    #[error("compile error: {0}")]
    Compile(#[from] CompileError),

    #[error("vm error: {0}")]
    Vm(#[from] VmError),
}

fn run_program_text(
    source: &str,
    trace_len: usize,
    max_steps: usize,
) -> Result<Vec<ExecutionRow<Fr>>, PipelineError> {
    let program = compile(source)?;

    let initial_state = VmState {
        pc: 0,
        regs: [Fr::zero(); 4],
        halted: false,
    };
    let rows = run_rows(initial_state, &program, trace_len, max_steps)?;
    Ok(rows)
}
