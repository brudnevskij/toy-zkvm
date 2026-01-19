use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

pub fn pick_coset_shift<F: PrimeField>(lde_size: usize) -> F {
    for k in 2u64.. {
        let candidate = F::from(k);

        if candidate.pow([lde_size as u64]) != F::one() {
            return candidate;
        }
    }
    unreachable!()
}

pub fn pick_domain<F: PrimeField>(n: usize) -> Radix2EvaluationDomain<F> {
    Radix2EvaluationDomain::<F>::new(n).expect("expect radix 2 domain")
}
