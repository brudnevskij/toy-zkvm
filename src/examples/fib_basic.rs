use ark_ff::PrimeField;

use crate::air::{Air, Constraint, RowAccess};
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

// n 128
const FIBONACCI_SEQUENCE_FINAL_VALUE: u128 = 251728825683549488150424261;

// ---------------- Constraints  ----------------

struct TimeStepBoundary {
    time_col: usize,
}

impl<F: PrimeField> Constraint<F> for TimeStepBoundary {
    fn name(&self) -> &'static str {
        "time_step_boundary"
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let num = row.current_step_column_value(self.time_col) - F::one();
        let denom = row.x() - row.x0();
        num * denom.inverse().unwrap()
    }
}

struct TimeStepTransition {
    time_col: usize,
}

impl<F: PrimeField> Constraint<F> for TimeStepTransition {
    fn name(&self) -> &'static str {
        "time_step_transition"
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let t_cur = row.current_step_column_value(self.time_col);
        let t_prev = row.previous_step_column_value(self.time_col);
        (row.x() - row.x0()) * (t_cur - t_prev - F::one()) * row.z_h_inverse()
    }
}

struct ATransition {
    a_col: usize,
    b_col: usize,
}

impl<F: PrimeField> Constraint<F> for ATransition {
    fn name(&self) -> &'static str {
        "a_transition"
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let cur_a = row.current_step_column_value(self.a_col);
        let prev_b = row.previous_step_column_value(self.b_col);
        (row.x() - row.x0()) * (cur_a - prev_b) * row.z_h_inverse()
    }
}

struct BTransition {
    a_col: usize,
    b_col: usize,
}

impl<F: PrimeField> Constraint<F> for BTransition {
    fn name(&self) -> &'static str {
        "b_transition"
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let b_cur = row.current_step_column_value(self.b_col);
        let b_prev = row.previous_step_column_value(self.b_col);
        let a_prev = row.previous_step_column_value(self.a_col);
        (row.x() - row.x0()) * (b_cur - b_prev - a_prev) * row.z_h_inverse()
    }
}

struct FinalValueBoundary {
    b_col: usize,
    final_value: u128,
}

impl<F: PrimeField> Constraint<F> for FinalValueBoundary {
    fn name(&self) -> &'static str {
        "final_value_boundary"
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let num = row.current_step_column_value(self.b_col) - F::from(self.final_value);
        let denom = row.x() - row.x_last();
        num * denom.inverse().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        air::{Constraint, TraceTable},
        backend::{FriOptions, FriProofError, Transcript},
        examples::{FibAir, calculate_fibonacci_seq},
        test_utils::{pick_coset_shift, pick_domain},
        zkvm::{ZkvmProveError, ZkvmPublicParameters, prove, verify},
    };
    use ark_bn254::Fr;
    use ark_ff::Zero;

    fn compute_fibonacci_trace(n: usize) -> TraceTable<Fr> {
        let fib_seq = calculate_fibonacci_seq::<Fr>(n);
        let mut a_column = fib_seq.clone().into_iter().take(n - 1).collect::<Vec<_>>();
        a_column.insert(0, Fr::zero());
        let b_column = fib_seq;
        let t_column = (1..=n).map(|i| Fr::from(i as i64)).collect();
        let columns = vec![t_column, a_column, b_column];
        let names = vec!["t".to_string(), "A".to_string(), "B".to_string()];

        TraceTable::new(columns, names)
    }

    fn make_fib_air<F: PrimeField>() -> FibAir<F> {
        let time = FibonacciColumns::TimeStep.idx();
        let a = FibonacciColumns::SequenceValuesA.idx();
        let b = FibonacciColumns::SequenceValuesB.idx();

        FibAir {
            width: 3,
            constraints: vec![
                Box::new(TimeStepBoundary { time_col: time }),
                Box::new(TimeStepTransition { time_col: time }),
                Box::new(ATransition { a_col: a, b_col: b }),
                Box::new(BTransition { a_col: a, b_col: b }),
                Box::new(FinalValueBoundary {
                    b_col: b,
                    final_value: FIBONACCI_SEQUENCE_FINAL_VALUE,
                }),
            ],
        }
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

        let air = make_fib_air();
        let proof =
            prove(&trace_table, &air, &mut tx, &public_params).expect("prove should succeed");

        let mut tx = Transcript::new(b"transcript", seed);
        verify(&proof, &air, &mut tx, &public_params).expect("verification should succeed");
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
        let names = vec!["t".to_string(), "A".to_string(), "B".to_string()];
        let trace_table = TraceTable::new(columns, names);

        let air = make_fib_air();

        let res = prove(&trace_table, &air, &mut tx, &public_params);
        assert!(matches!(
            res,
            Err(ZkvmProveError::Fri(
                FriProofError::FinalPolynomialDegreeExceedMaxRemainderDegree { .. }
            ))
        ));
    }
}
