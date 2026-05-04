pub mod air;
pub mod backend;
pub mod dsl;
pub mod examples;
pub mod test_utils;
pub mod vm;
pub mod zkvm;

use crate::{
    air::TraceTable,
    backend::FriOptions,
    dsl::compile,
    test_utils::{pick_coset_shift, pick_domain},
    vm::{VmState, rows_to_trace_table, run_rows},
    zkvm::{ZkvmProof, ZkvmPublicParameters},
};
use ark_bn254::Fr;
use ark_ff::Zero;

pub struct ProveResult {
    pub proof: ZkvmProof<Fr>,
    pub prove_duration: std::time::Duration,
}

pub fn setup_public_params(trace_size: usize) -> ZkvmPublicParameters<Fr> {
    let blowup = 16usize;
    let lde_size = trace_size * blowup;

    let shift = pick_coset_shift(lde_size);
    let trace_domain = pick_domain(trace_size);
    let lde_domain = pick_domain(lde_size);

    ZkvmPublicParameters {
        trace_domain,
        lde_domain,
        shift,
        fri_options: FriOptions {
            max_degree: trace_size * 4,
            max_remainder_degree: 1,
            query_number: 64,
            shift,
        },
    }
}

pub fn run_program_to_trace(source: &str, trace_len: usize, max_steps: usize) -> TraceTable<Fr> {
    let program = compile(source).expect("program should compile");
    let initial_state = VmState {
        pc: 0,
        regs: [Fr::zero(); 4],
        halted: false,
    };

    let rows = run_rows(initial_state, &program, trace_len, max_steps).expect("program should run");

    rows_to_trace_table(&rows)
}
