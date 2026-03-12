use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use toy_zkvm::{
    air::{Air, RowAccess, TraceTable},
    dsl::compile,
    vm::{VmAir, VmState, rows_to_trace_table, run_rows},
};

fn fr(x: u64) -> Fr {
    Fr::from(x)
}

fn run_program_to_trace(source: &str, trace_len: usize, max_steps: usize) -> TraceTable<Fr> {
    let program = compile(source).expect("program should compile");
    let initial_state = VmState {
        pc: 0,
        regs: [Fr::zero(); 4],
        halted: false,
    };

    let rows = run_rows(initial_state, &program, trace_len, max_steps).expect("program should run");

    rows_to_trace_table(&rows)
}

struct TestRow<'a, F: PrimeField> {
    trace: &'a TraceTable<F>,
    row_idx: usize,
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
}

fn assert_trace_satisfies_air(trace: &TraceTable<Fr>, air: &VmAir<Fr>) {
    for row_idx in 0..trace.n() {
        let row = TestRow { trace, row_idx };

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

fn assert_trace_violates_some_constraint(trace: &TraceTable<Fr>, air: &VmAir<Fr>) {
    for row_idx in 0..trace.n() {
        let row = TestRow { trace, row_idx };

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
fn fib_trace_satisfies_current_vm_air() {
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
    let air = VmAir::<Fr>::new();

    assert_trace_satisfies_air(&trace, &air);
}
