use ark_bn254::Fr;
use ark_ff::{One, PrimeField, Zero};
use toy_zkvm::{
    air::{Air, RowAccess, TraceTable},
    dsl::compile,
    vm::{VmState, rows_to_trace_table, run_rows},
    zkvm::PreprocessedTraceEvals,
};

pub fn fr(x: u64) -> Fr {
    Fr::from(x)
}

pub struct TestRow<'a, F: PrimeField> {
    trace: &'a TraceTable<F>,
    row_idx: usize,
    preprocessed_evals: &'a PreprocessedTraceEvals<F>,
}

impl<'a, F: PrimeField> RowAccess<F> for TestRow<'a, F> {
    fn current_step_column_value(&self, column: usize) -> F {
        self.trace.columns[column][self.row_idx]
    }

    fn previous_step_column_value(&self, column: usize) -> F {
        assert!(self.row_idx > 0, "previous row requested for row 0");
        self.trace.columns[column][self.row_idx - 1]
    }

    fn idx(&self) -> usize {
        self.row_idx
    }

    fn x(&self) -> F {
        F::zero()
    }

    fn x0(&self) -> F {
        F::zero()
    }

    fn x_last(&self) -> F {
        F::zero()
    }

    fn z_h_inverse(&self) -> F {
        F::one()
    }

    fn first_row_selector(&self) -> F {
        self.preprocessed_evals.first_row_selector[self.row_idx]
    }

    fn last_row_selector(&self) -> F {
        self.preprocessed_evals.last_row_selector[self.row_idx]
    }
}

pub fn generate_preprocessed_selectors(n: usize) -> PreprocessedTraceEvals<Fr> {
    let mut first_row_selector = Vec::with_capacity(n);
    let mut last_row_selector = Vec::with_capacity(n);
    for i in 0..n {
        if i == 0 {
            first_row_selector.push(Fr::one());
            last_row_selector.push(Fr::zero());
        } else if i == n - 1 {
            first_row_selector.push(Fr::zero());
            last_row_selector.push(Fr::one());
        } else {
            first_row_selector.push(Fr::zero());
            last_row_selector.push(Fr::zero());
        }
    }

    PreprocessedTraceEvals {
        first_row_selector,
        last_row_selector,
    }
}

pub fn assert_trace_satisfies_air(trace: &TraceTable<Fr>, air: &dyn Air<Fr>) {
    let preprocessed_evals = &generate_preprocessed_selectors(trace.n());
    for row_idx in 0..trace.n() {
        let row = TestRow {
            trace,
            row_idx,
            preprocessed_evals,
        };

        for i in 0..air.num_constraints() {
            let value = air.eval_constraint(i, &row);
            assert!(
                value.is_zero(),
                "constraint '{}' failed at row {} with value {:?}",
                air.constraint_name(i),
                row_idx,
                value
            );
        }
    }
}

pub fn assert_trace_violates_some_constraint(trace: &TraceTable<Fr>, air: &dyn Air<Fr>) {
    let preprocessed_evals = &generate_preprocessed_selectors(trace.n());
    for row_idx in 0..trace.n() {
        let row = TestRow {
            trace,
            row_idx,
            preprocessed_evals,
        };

        for i in 0..air.num_constraints() {
            let value = air.eval_constraint(i, &row);
            if !value.is_zero() {
                return;
            }
        }
    }

    panic!("expected corrupted trace to violate at least one constraint");
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
