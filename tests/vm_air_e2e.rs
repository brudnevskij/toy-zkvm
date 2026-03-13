use ark_bn254::Fr;
use ark_ff::{One, PrimeField, Zero};
use toy_zkvm::{
    air::{Air, RowAccess, TraceTable},
    test_utils::run_program_to_trace,
    vm::{TraceColumn, VmAir},
    zkvm::PreprocessedTraceEvals,
};

fn fr(x: u64) -> Fr {
    Fr::from(x)
}

struct TestRow<'a, F: PrimeField> {
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

fn generate_preprocessed_selectors(n: usize) -> PreprocessedTraceEvals<Fr> {
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

fn assert_trace_satisfies_air(trace: &TraceTable<Fr>, air: &dyn Air<Fr>) {
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

fn assert_trace_violates_some_constraint(trace: &TraceTable<Fr>, air: &dyn Air<Fr>) {
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

#[test]
fn fib_trace_satisfies_vm_air() {
    let source = r#"
       const r0, 0
       const r1, 1
       const r3, 10

       loop:
       mov r2, r1
       add r1, r0
       mov r0, r2
       const r2, 1
       sub r3, r2
       jnz r3, loop
       halt
    "#;

    let trace = run_program_to_trace(source, 128, 128);
    let air = VmAir::<Fr>::default();

    assert_trace_satisfies_air(&trace, &air);
}

#[test]
fn const_halt_trace_satisfies_vm_air() {
    let source = r#"
        const r0, 7
        halt
    "#;

    let trace = run_program_to_trace(source, 8, 16);
    let air = VmAir::<Fr>::default();

    assert_trace_satisfies_air(&trace, &air);
}

#[test]
fn corrupted_initial_pc_is_detected() {
    let source = r#"
        const r0, 7
        halt
    "#;

    let mut trace = run_program_to_trace(source, 8, 16);
    trace.columns[TraceColumn::Pc.idx()][0] = fr(123);

    let air = VmAir::<Fr>::default();
    assert_trace_violates_some_constraint(&trace, &air);
}

#[test]
fn corrupted_initial_r0_is_detected() {
    let source = r#"
        const r0, 7
        halt
    "#;

    let mut trace = run_program_to_trace(source, 8, 16);
    trace.columns[TraceColumn::R0.idx()][0] = fr(9);

    let air = VmAir::<Fr>::default();
    assert_trace_violates_some_constraint(&trace, &air);
}

#[test]
fn corrupted_initial_halted_is_detected() {
    let source = r#"
        const r0, 7
        halt
    "#;

    let mut trace = run_program_to_trace(source, 8, 16);
    trace.columns[TraceColumn::Halted.idx()][0] = Fr::one();

    let air = VmAir::<Fr>::default();
    assert_trace_violates_some_constraint(&trace, &air);
}

#[test]
fn corrupted_booleanity_is_detected() {
    let source = r#"
        const r0, 7
        halt
    "#;

    let mut trace = run_program_to_trace(source, 8, 16);
    trace.columns[TraceColumn::Halted.idx()][2] = fr(2);

    let air = VmAir::<Fr>::default();
    assert_trace_violates_some_constraint(&trace, &air);
}

#[test]
fn corrupted_one_hot_opcode_is_detected() {
    let source = r#"
        const r0, 7
        halt
    "#;

    let mut trace = run_program_to_trace(source, 8, 16);
    trace.columns[TraceColumn::SConst.idx()][0] = Fr::one();
    trace.columns[TraceColumn::SHalt.idx()][0] = Fr::one();

    let air = VmAir::<Fr>::default();
    assert_trace_violates_some_constraint(&trace, &air);
}

#[test]
fn corrupted_register_index_a_is_detected() {
    let source = r#"
        const r0, 7
        halt
    "#;

    let mut trace = run_program_to_trace(source, 8, 16);
    trace.columns[TraceColumn::A.idx()][0] = fr(5);

    let air = VmAir::<Fr>::default();
    assert_trace_violates_some_constraint(&trace, &air);
}

#[test]
fn corrupted_unused_operand_for_const_is_detected() {
    let source = r#"
        const r0, 7
        halt
    "#;

    let mut trace = run_program_to_trace(source, 8, 16);
    trace.columns[TraceColumn::B.idx()][0] = fr(9);

    let air = VmAir::<Fr>::default();
    assert_trace_violates_some_constraint(&trace, &air);
}
