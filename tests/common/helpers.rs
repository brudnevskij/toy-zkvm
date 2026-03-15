use ark_bn254::Fr;
use ark_ff::{One, PrimeField, Zero};
use toy_zkvm::{
    air::{Air, Constraint, RowAccess, TraceTable},
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
        let idx = (self.row_idx + self.trace.n() - 1) % self.trace.n();
        self.trace.columns[column][idx]
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

pub fn print_trace_and_constraint_evals<F: PrimeField>(
    trace: &TraceTable<F>,
    constraints: &[Box<dyn Constraint<F>>],
) {
    assert!(
        !trace.columns.is_empty(),
        "trace must contain at least one column"
    );

    let n_rows = trace.columns[0].len();
    for col in &trace.columns {
        assert_eq!(col.len(), n_rows, "all trace columns must have same length");
    }

    println!("=== TRACE TABLE ===");
    print_trace_table(trace);

    println!();
    println!("=== CONSTRAINT EVALUATIONS BY ROW ===");

    for i in 0..n_rows {
        let prev_i = if i == 0 { 0 } else { i - 1 };

        let row_view = DebugRowView { trace, i, prev_i };

        println!();
        println!("--- row {i} (prev {prev_i}) ---");

        for constraint in constraints {
            let value = constraint.eval(&row_view);
            let ok = value.is_zero();
            println!(
                "[{}] {} = {:?}",
                if ok { "ok" } else { "!!" },
                constraint.name(),
                value
            );
        }
    }
}

pub fn print_trace_table<F: PrimeField>(trace: &TraceTable<F>) {
    assert_eq!(
        trace.columns.len(),
        trace.names.len(),
        "trace.names and trace.columns length mismatch"
    );

    if trace.columns.is_empty() {
        println!("(empty trace)");
        return;
    }

    let n_rows = trace.columns[0].len();

    let mut widths = Vec::with_capacity(trace.columns.len());
    for (name, col) in trace.names.iter().zip(trace.columns.iter()) {
        let mut width = name.len();
        for v in col {
            let s = format!("{v:?}");
            width = width.max(s.len());
        }
        widths.push(width);
    }

    print!("{:>5} |", "#");
    for (name, width) in trace.names.iter().zip(widths.iter()) {
        print!(" {:>width$} |", name, width = *width);
    }
    println!();

    for row in 0..n_rows {
        print!("{:>5} |", row);
        for (col, width) in trace.columns.iter().zip(widths.iter()) {
            let s = format!("{:?}", col[row]);
            print!(" {:>width$} |", s, width = *width);
        }
        println!();
    }
}

/// Minimal row view for debugging constraint evaluation directly on the base trace.
/// This version uses row values from the trace table, not LDE values.
struct DebugRowView<'a, F: PrimeField> {
    trace: &'a TraceTable<F>,
    i: usize,
    prev_i: usize,
}

impl<'a, F: PrimeField> RowAccess<F> for DebugRowView<'a, F> {
    fn current_step_column_value(&self, column: usize) -> F {
        self.trace.columns[column][self.i]
    }

    fn previous_step_column_value(&self, column: usize) -> F {
        self.trace.columns[column][self.prev_i]
    }

    fn idx(&self) -> usize {
        self.i
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
        if self.i == 0 { F::one() } else { F::zero() }
    }

    fn last_row_selector(&self) -> F {
        let last = self.trace.columns[0].len() - 1;
        if self.i == last { F::one() } else { F::zero() }
    }
}
