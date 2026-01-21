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

// n 64
const FIBONACCI_SEQUENCE_FINAL_VALUE: u128 = 251728825683549488150424261;

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

#[cfg(test)]
mod tests {
    use std::usize;

    use super::*;
    use crate::{
        air::{
            ConstraintFunction, TraceTable,
            air::{ZkvmProveError, ZkvmPublicParameters},
            zkvm_prove, zkvm_verify,
        },
        backend::{FriOptions, FriProofError, Transcript},
        test_utils::{pick_coset_shift, pick_domain},
    };
    use ark_bn254::Fr;
    use ark_ff::{One, Zero};

    fn calculate_fibonacci_seq<F: PrimeField>(n: usize) -> Vec<F> {
        match n {
            0 => vec![],
            1 => vec![F::one()],
            _ => {
                let mut sequence = Vec::with_capacity(n);
                sequence.push(F::one());
                sequence.push(F::one());

                for i in 2..n {
                    let next_value = sequence[i - 1] + sequence[i - 2];
                    sequence.push(next_value);
                }

                sequence
            }
        }
    }

    fn compute_fibonacci_trace(n: usize) -> TraceTable<Fr> {
        let fib_seq_128 = calculate_fibonacci_seq::<Fr>(n);
        let mut a_column = fib_seq_128
            .clone()
            .into_iter()
            .take(n - 1)
            .collect::<Vec<_>>();
        a_column.insert(0, Fr::zero());
        let b_column = fib_seq_128;
        let t_column = (1..=n).map(|i| Fr::from(i as i64)).collect();
        let columns = vec![t_column, a_column, b_column];
        let names = vec!["t", "A", "B"];

        TraceTable::new(columns, names)
    }

    #[test]
    fn prove_fibonacci_sequence() {
        let seed = b"fibonacci-zkvm";
        let mut tx = Transcript::new(b"transcript", seed);

        // public params
        let trace_size = 128;
        let blowup = 16;
        let lde_size = blowup * trace_size;
        let shift = pick_coset_shift(lde_size);
        let trace_domain = pick_domain(trace_size);
        let lde_domain = pick_domain(lde_size);

        let public_params = ZkvmPublicParameters {
            trace_domain,
            lde_domain,
            shift,
            fri_options: FriOptions {
                max_degree: trace_size,
                max_remainder_degree: 1,
                query_number: 64,
                shift,
            },
        };

        let trace_table = compute_fibonacci_trace(trace_size);

        // setting the constraintslet
        let constraints: Vec<ConstraintFunction<Fr>> = vec![
            time_step_boundary_constraint::<Fr>,
            time_step_transition_constraint::<Fr>,
            a_transition_constraint::<Fr>,
            b_transition_constraint::<Fr>,
            final_value_boundary::<Fr>,
        ];

        let proof = zkvm_prove(&trace_table, &mut tx, &constraints, &public_params)
            .expect("prove should succeed");

        let mut tx = Transcript::new(b"transcript", seed);
        zkvm_verify(&proof, &mut tx, &constraints, &public_params)
            .expect("verification should succeed");
    }

    #[test]
    fn prove_incorrect_fibonacci_sequence() {
        let seed = b"fibonacci-zkvm";
        let mut tx = Transcript::new(b"transcript", seed);

        // public params
        let trace_size = 128;
        let blowup = 16;
        let lde_size = blowup * trace_size;
        let shift = pick_coset_shift(lde_size);
        let trace_domain = pick_domain(trace_size);
        let lde_domain = pick_domain(lde_size);

        let public_params = ZkvmPublicParameters {
            trace_domain,
            lde_domain,
            shift,
            fri_options: FriOptions {
                max_degree: trace_size,
                max_remainder_degree: 1,
                query_number: 64,
                shift,
            },
        };

        let fib_seq_128 = calculate_fibonacci_seq::<Fr>(trace_size);

        let mut a_column = fib_seq_128
            .clone()
            .into_iter()
            .take(trace_size - 1)
            .collect::<Vec<_>>();
        a_column.insert(0, Fr::zero());

        let b_column = fib_seq_128;
        let mut t_column: Vec<_> = (1..=trace_size).map(|i| Fr::from(i as i64)).collect();
        // replace one cell with incorrect index
        t_column[trace_size - 1] = Fr::from(0);

        let columns = vec![t_column, a_column, b_column];
        let names = vec!["t", "A", "B"];
        let trace_table = TraceTable::new(columns, names);

        // setting the constraintslet
        let constraints: Vec<ConstraintFunction<Fr>> = vec![
            time_step_boundary_constraint::<Fr>,
            time_step_transition_constraint::<Fr>,
            a_transition_constraint::<Fr>,
            b_transition_constraint::<Fr>,
            final_value_boundary::<Fr>,
        ];

        let res = zkvm_prove(&trace_table, &mut tx, &constraints, &public_params);
        assert!(matches!(
            res,
            Err(ZkvmProveError::Fri(
                FriProofError::FinalPolynomialDegreeExceedMaxRemainderDegree { .. }
            ))
        ));
    }
}
