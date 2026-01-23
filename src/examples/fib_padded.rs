use crate::air::RowAccess;
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

// Constraints
fn time_step_boundary_constraint<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    let boundary = row.current_step_column_value(TimeStep.idx()) - F::one();
    boundary * row.current_step_column_value(InitControl.idx()) * row.z_h_inverse()
}

fn time_step_transition_constraint<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    let transition = row.current_step_column_value(TimeStep.idx())
        - row.previous_step_column_value(TimeStep.idx())
        - F::one();
    transition * row.current_step_column_value(TransitionControl.idx()) * row.z_h_inverse()
}

fn column_a_transition_constraint<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    // a_{i-1}
    let current_a = row.current_step_column_value(SequenceValuesA.idx());
    // a_{i-1}
    let previous_b = row.previous_step_column_value(SequenceValuesB.idx());
    let transition_control = row.current_step_column_value(TransitionControl.idx());

    (current_a - previous_b) * transition_control * row.z_h_inverse()
}

fn column_b_transition_constraint<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    // a_i
    let current_b = row.current_step_column_value(SequenceValuesB.idx());
    // a_{i-1}
    let previous_b = row.previous_step_column_value(SequenceValuesB.idx());
    // a_{i-2}
    let previous_a = row.previous_step_column_value(SequenceValuesA.idx());
    let transsition_control = row.current_step_column_value(TransitionControl.idx());

    (current_b - previous_b - previous_a) * transsition_control * row.z_h_inverse()
}

fn termination_value_constraint<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    let current_b = row.current_step_column_value(SequenceValuesB.idx());
    let termination_control = row.current_step_column_value(TerminationControl.idx());

    (current_b - F::from(FIBONACCI_SEQUENCE_FINAL_VALUE)) * termination_control * row.z_h_inverse()
}

fn column_a_init_constraint<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    let current_a = row.current_step_column_value(SequenceValuesA.idx());
    let init_control = row.current_step_column_value(InitControl.idx());

    (current_a - F::from(FIBONACCI_SEQUENCE_INIT_VALUE_A)) * init_control * row.z_h_inverse()
}

fn column_b_init_constraint<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    let current_b = row.current_step_column_value(SequenceValuesB.idx());
    let init_control = row.current_step_column_value(InitControl.idx());

    (current_b - F::from(FIBONACCI_SEQUENCE_INIT_VALUE_B)) * init_control * row.z_h_inverse()
}

#[cfg(test)]
mod tests {
    use std::u64;

    use super::*;
    use crate::{
        air::{ConstraintFunction, TraceTable, air::ZkvmPublicParameters, zkvm_prove, zkvm_verify},
        backend::{FriOptions, Transcript},
        examples::calculate_fibonacci_seq,
        test_utils::{pick_coset_shift, pick_domain},
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

        let constraints: Vec<ConstraintFunction<Fr>> = vec![
            time_step_boundary_constraint::<Fr>,
            time_step_transition_constraint::<Fr>,
            column_a_transition_constraint::<Fr>,
            column_b_transition_constraint::<Fr>,
            termination_value_constraint::<Fr>,
            column_a_init_constraint::<Fr>,
            column_b_init_constraint::<Fr>,
        ];

        let tx_label = b"transcript";
        let tx_seed = b"padded_fib_zkvm";
        let mut tx = Transcript::new(tx_label, tx_seed);
        let proof =
            zkvm_prove(&trace, &mut tx, &constraints, &public_params).expect("should succeed");

        let mut tx = Transcript::new(tx_label, tx_seed);
        zkvm_verify(&proof, &mut tx, &constraints, &public_params).expect("should succeed");
    }
}
