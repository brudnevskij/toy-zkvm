use ark_ff::PrimeField;

use crate::air::RowAccess;
use FibonacciColumns::{SequenceValuesA, SequenceValuesB, TimeStep};

enum FibonacciColumns {
    TimeStep,
    SequenceValuesA, // a_{i-1}
    SequenceValuesB, // a_i
}

impl FibonacciColumns {
    pub const fn idx(self) -> usize {
        match self {
            Self::TimeStep => 0,
            Self::SequenceValuesA => 1,
            Self::SequenceValuesB => 2,
        }
    }
}

const FIBONACCI_SEQUENCE_FINAL_VALUE: u64 = 89;

fn time_step_boundary_constraint<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    let num = row.current_step_column_value(TimeStep.idx()) - F::one();
    let denom = row.x() - row.x0();
    num * denom.inverse().unwrap()
}

fn time_step_transition_constraint<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    let t_cur = row.current_step_column_value(TimeStep.idx());
    let t_previous = row.previous_step_column_value(TimeStep.idx());
    (row.x() - row.x0()) * (t_cur - t_previous - F::one()) * row.z_h_inverse()
}

fn a_transition_constraint<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    let cur_a = row.current_step_column_value(SequenceValuesA.idx());
    let previous_b = row.previous_step_column_value(SequenceValuesB.idx());
    (row.x() - row.x0()) * (cur_a - previous_b) * row.z_h_inverse()
}

fn b_transition_constraint<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    let b_cur = row.current_step_column_value(SequenceValuesB.idx());
    let b_previos = row.previous_step_column_value(SequenceValuesB.idx());
    let a_previous = row.previous_step_column_value(SequenceValuesA.idx());
    (row.x() - row.x0()) * (b_cur - b_previos - a_previous) * row.z_h_inverse()
}

fn final_value_boundary<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    let num = row.current_step_column_value(SequenceValuesB.idx())
        - F::from(FIBONACCI_SEQUENCE_FINAL_VALUE);
    let denom = row.x() - row.x_last();
    num * denom.inverse().unwrap()
}

// optional: implement first boundary values
