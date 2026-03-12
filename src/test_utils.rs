use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

use crate::{
    air::TraceTable,
    dsl::compile,
    vm::{VmState, rows_to_trace_table, run_rows},
};

pub fn pick_coset_shift<F: PrimeField>(lde_size: usize) -> F {
    for k in 2u64.. {
        let candidate = F::from(k);

        if candidate.pow([lde_size as u64]) != F::one() {
            return candidate;
        }
    }
    unreachable!()
}

pub fn pick_domain<F: PrimeField>(n: usize) -> Radix2EvaluationDomain<F> {
    Radix2EvaluationDomain::<F>::new(n).expect("expect radix 2 domain")
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
