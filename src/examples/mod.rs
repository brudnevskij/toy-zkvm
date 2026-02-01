use ark_ff::PrimeField;

use crate::air::{Air, Constraint, RowAccess};

mod fib_basic;
mod fib_padded;

struct FibAir<F: PrimeField> {
    width: usize,
    constraints: Vec<Box<dyn Constraint<F>>>,
}

impl<F: PrimeField> Air<F> for FibAir<F> {
    fn width(&self) -> usize {
        self.width
    }

    fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    fn eval_constraint(&self, i: usize, row: &dyn RowAccess<F>) -> F {
        self.constraints[i].eval(row)
    }
}

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
