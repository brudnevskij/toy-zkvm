use ark_ff::PrimeField;

mod fib_basic;
mod fib_padded;

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
