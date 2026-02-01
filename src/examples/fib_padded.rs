use crate::air::{Constraint, RowAccess};
use FibonacciColumns::{
    InitControl, SequenceValuesA, SequenceValuesB, TerminationControl, TimeStep, TransitionControl,
};
use ark_ff::PrimeField;

enum FibonacciColumns {
    TimeStep,
    SequenceValuesA, // a_{i-1}
    SequenceValuesB, // a_i
    TransitionControl,
    InitControl,
    TerminationControl,
}

impl FibonacciColumns {
    pub const fn idx(self) -> usize {
        match self {
            Self::TimeStep => 0,
            Self::SequenceValuesA => 1,
            Self::SequenceValuesB => 2,
            Self::TransitionControl => 3,
            Self::InitControl => 4,
            Self::TerminationControl => 5,
        }
    }

    pub fn name(self) -> String {
        match self {
            TimeStep => "t".to_string(),
            SequenceValuesA => "A".to_string(),
            SequenceValuesB => "B".to_string(),
            TransitionControl => "transition control".to_string(),
            InitControl => "init control a".to_string(),
            TerminationControl => "termination control".to_string(),
        }
    }
}

// n = 64
const FIBONACCI_SEQUENCE_FINAL_VALUE: u128 = 251728825683549488150424261;
const FIBONACCI_SEQUENCE_INIT_VALUE_A: u128 = 70492524767089125814114;
const FIBONACCI_SEQUENCE_INIT_VALUE_B: u128 = 114059301025943970552219;

// ---------------- Constraints ----------------
struct TimeStepBoundary {
    time_col: usize,
    init_ctrl_col: usize,
}

impl<F: PrimeField> Constraint<F> for TimeStepBoundary {
    fn name(&self) -> &'static str {
        "time_step_boundary"
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let boundary = row.current_step_column_value(self.time_col) - F::one();
        boundary * row.current_step_column_value(self.init_ctrl_col) * row.z_h_inverse()
    }
}

struct TimeStepTransition {
    time_col: usize,
    transition_ctrl_col: usize,
}

impl<F: PrimeField> Constraint<F> for TimeStepTransition {
    fn name(&self) -> &'static str {
        "time_step_transition"
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let transition = row.current_step_column_value(self.time_col)
            - row.previous_step_column_value(self.time_col)
            - F::one();
        transition * row.current_step_column_value(self.transition_ctrl_col) * row.z_h_inverse()
    }
}

struct ATransition {
    a_col: usize,
    b_col: usize,
    transition_ctrl_col: usize,
}

impl<F: PrimeField> Constraint<F> for ATransition {
    fn name(&self) -> &'static str {
        "a_transition"
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let current_a = row.current_step_column_value(self.a_col);
        let previous_b = row.previous_step_column_value(self.b_col);
        let ctrl = row.current_step_column_value(self.transition_ctrl_col);
        (current_a - previous_b) * ctrl * row.z_h_inverse()
    }
}

struct BTransition {
    a_col: usize,
    b_col: usize,
    transition_ctrl_col: usize,
}

impl<F: PrimeField> Constraint<F> for BTransition {
    fn name(&self) -> &'static str {
        "b_transition"
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let current_b = row.current_step_column_value(self.b_col);
        let previous_b = row.previous_step_column_value(self.b_col);
        let previous_a = row.previous_step_column_value(self.a_col);
        let ctrl = row.current_step_column_value(self.transition_ctrl_col);
        (current_b - previous_b - previous_a) * ctrl * row.z_h_inverse()
    }
}

struct TerminationValue {
    b_col: usize,
    termination_ctrl_col: usize,
    final_value: u128,
}

impl<F: PrimeField> Constraint<F> for TerminationValue {
    fn name(&self) -> &'static str {
        "termination_value"
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let current_b = row.current_step_column_value(self.b_col);
        let ctrl = row.current_step_column_value(self.termination_ctrl_col);
        (current_b - F::from(self.final_value)) * ctrl * row.z_h_inverse()
    }
}

struct AInit {
    a_col: usize,
    init_ctrl_col: usize,
    init_value: u128,
}

impl<F: PrimeField> Constraint<F> for AInit {
    fn name(&self) -> &'static str {
        "a_init"
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let current_a = row.current_step_column_value(self.a_col);
        let ctrl = row.current_step_column_value(self.init_ctrl_col);
        (current_a - F::from(self.init_value)) * ctrl * row.z_h_inverse()
    }
}

struct BInit {
    b_col: usize,
    init_ctrl_col: usize,
    init_value: u128,
}

impl<F: PrimeField> Constraint<F> for BInit {
    fn name(&self) -> &'static str {
        "b_init"
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let current_b = row.current_step_column_value(self.b_col);
        let ctrl = row.current_step_column_value(self.init_ctrl_col);
        (current_b - F::from(self.init_value)) * ctrl * row.z_h_inverse()
    }
}

// Optional but recommended: booleanity for control columns.
// This fixes the “controls are witness, prover can cheat by setting to 0” class of issues
// *partially* (you still need constraints tying them to correct positions).
struct Booleanity {
    col: usize,
}

impl<F: PrimeField> Constraint<F> for Booleanity {
    fn name(&self) -> &'static str {
        "booleanity"
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let v = row.current_step_column_value(self.col);
        (v * (v - F::one())) * row.z_h_inverse()
    }
}
#[cfg(test)]
mod tests {
    use std::u64;

    use super::*;
    use crate::{
        air::TraceTable,
        backend::{FriOptions, Transcript},
        examples::{FibAir, calculate_fibonacci_seq},
        test_utils::{pick_coset_shift, pick_domain},
        zkvm::{ZkvmPublicParameters, prove, verify},
    };
    use ark_bn254::Fr;
    use ark_ff::{One, Zero};
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    // Since control columns are part of the witness, trace is not sound
    // Prover can set all trace control columns to be zero and pass the verification
    // in the future versions control columns will be a part of public params
    fn compute_fibonacci_trace(n: usize) -> TraceTable<Fr> {
        let fib_seq = calculate_fibonacci_seq::<Fr>(n);
        let mut a_column = fib_seq.clone().into_iter().take(n - 1).collect::<Vec<_>>();
        a_column.insert(0, Fr::zero());
        let b_column = fib_seq;
        let t_column = (1..=n).map(|i| Fr::from(i as i64)).collect();
        let columns = vec![t_column, a_column, b_column];
        let names = vec![
            TimeStep.name(),
            SequenceValuesA.name(),
            SequenceValuesB.name(),
            TransitionControl.name(),
            InitControl.name(),
            TerminationControl.name(),
        ];

        TraceTable::new(columns, names)
    }

    fn pad_column_with_random<F: PrimeField>(column: &mut Vec<F>, padding_sise: usize, seed: u64) {
        let column_size = column.len();
        let mut rng = StdRng::seed_from_u64(seed);
        for _ in column_size..padding_sise {
            column.push(F::rand(&mut rng));
        }
    }

    pub fn make_padded_fib_air<F: PrimeField>() -> FibAir<F> {
        let time = FibonacciColumns::TimeStep.idx();
        let a = FibonacciColumns::SequenceValuesA.idx();
        let b = FibonacciColumns::SequenceValuesB.idx();
        let tr = FibonacciColumns::TransitionControl.idx();
        let init = FibonacciColumns::InitControl.idx();
        let term = FibonacciColumns::TerminationControl.idx();

        FibAir {
            width: 6,
            constraints: vec![
                Box::new(TimeStepBoundary {
                    time_col: time,
                    init_ctrl_col: init,
                }),
                Box::new(TimeStepTransition {
                    time_col: time,
                    transition_ctrl_col: tr,
                }),
                Box::new(ATransition {
                    a_col: a,
                    b_col: b,
                    transition_ctrl_col: tr,
                }),
                Box::new(BTransition {
                    a_col: a,
                    b_col: b,
                    transition_ctrl_col: tr,
                }),
                Box::new(TerminationValue {
                    b_col: b,
                    termination_ctrl_col: term,
                    final_value: FIBONACCI_SEQUENCE_FINAL_VALUE,
                }),
                Box::new(AInit {
                    a_col: a,
                    init_ctrl_col: init,
                    init_value: FIBONACCI_SEQUENCE_INIT_VALUE_A,
                }),
                Box::new(BInit {
                    b_col: b,
                    init_ctrl_col: init,
                    init_value: FIBONACCI_SEQUENCE_INIT_VALUE_B,
                }),
                // booleanity constraints (recommended)
                Box::new(Booleanity { col: tr }),
                Box::new(Booleanity { col: init }),
                Box::new(Booleanity { col: term }),
            ],
        }
    }

    #[test]
    fn prove_short_fibonacci_sequence() {
        // Calculating Columns & Trace
        let fibonacci_sequence = calculate_fibonacci_seq::<Fr>(128);

        let proving_sequence_size = 17usize;
        let trace_size = proving_sequence_size.next_power_of_two();

        let proving_sequence = fibonacci_sequence
            .into_iter()
            // seq len + 1 for both columns
            .skip(128 - proving_sequence_size - 1)
            .collect::<Vec<Fr>>();

        let rng_seed = 255;
        let mut column_t = (1..=proving_sequence_size)
            .map(|t| Fr::from(t as i64))
            .collect::<Vec<Fr>>();
        pad_column_with_random(&mut column_t, trace_size, rng_seed);

        let mut column_a = proving_sequence
            .clone()
            .into_iter()
            .take(proving_sequence_size)
            .collect::<Vec<Fr>>();
        pad_column_with_random(&mut column_a, trace_size, rng_seed);

        let mut column_b = proving_sequence.into_iter().skip(1).collect::<Vec<Fr>>();
        pad_column_with_random(&mut column_b, trace_size, rng_seed);
        assert_eq!(column_a.len(), column_b.len());

        let transition_control_colum = (1..=trace_size)
            .map(|t| match t {
                1 => Fr::zero(),
                t if t > proving_sequence_size => Fr::zero(),
                _ => Fr::one(),
            })
            .collect::<Vec<Fr>>();

        let init_control_column = (1..=trace_size)
            .map(|t| match t {
                1 => Fr::one(),
                _ => Fr::zero(),
            })
            .collect::<Vec<Fr>>();

        let termination_control = (1..=trace_size)
            .map(|t| match t {
                17 => Fr::one(),
                _ => Fr::zero(),
            })
            .collect::<Vec<Fr>>();

        let columns = vec![
            column_t,
            column_a,
            column_b,
            transition_control_colum,
            init_control_column,
            termination_control,
        ];
        let names = vec![
            TimeStep.name(),
            SequenceValuesA.name(),
            SequenceValuesB.name(),
            TransitionControl.name(),
            InitControl.name(),
            TerminationControl.name(),
        ];

        let trace = TraceTable::new(columns, names);

        // Public Params
        let blowup = 16;
        let lde_size = trace_size * blowup;
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

        let air = make_padded_fib_air();
        let tx_label = b"transcript";
        let tx_seed = b"padded_fib_zkvm";
        let mut tx = Transcript::new(tx_label, tx_seed);
        let proof = prove(&trace, &air, &mut tx, &public_params).expect("should succeed");

        let mut tx = Transcript::new(tx_label, tx_seed);
        verify(&proof, &air, &mut tx, &public_params).expect("should succeed");
    }
}
