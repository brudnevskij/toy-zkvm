use ark_ff::{FftField, PrimeField};
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

pub fn print_poly_degree_from_lde_evals<F: FftField>(
    lde_evals: &[F],
    lde_domain: &Radix2EvaluationDomain<F>,
) -> Option<usize> {
    assert_eq!(lde_evals.len(), lde_domain.size());

    // Interpolate evaluations on the LDE domain back to coefficient form.
    let mut coeffs = lde_evals.to_vec();
    lde_domain.ifft_in_place(&mut coeffs);

    // Find the highest nonzero coefficient.
    let degree = coeffs.iter().rposition(|c| !c.is_zero());

    match degree {
        Some(d) => {
            println!("Polynomial degree: {}", d);
            Some(d)
        }
        None => {
            println!("Polynomial is zero, degree is undefined");
            None
        }
    }
}
