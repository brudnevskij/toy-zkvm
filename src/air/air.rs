use crate::backend::Transcript;
use ark_ff::{FftField, Field, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Radix2EvaluationDomain};
use ark_std::iterable::Iterable;

pub struct TraceTable<F: Field> {
    n: usize,
    columns: Vec<Vec<F>>,
    names: Vec<&'static str>,
}

impl<F: Field> TraceTable<F> {
    pub fn new(columns: Vec<Vec<F>>, names: Vec<&'static str>) -> Self {
        assert!(!columns.is_empty(), "columns must have at least one column");
        let n = columns[0].len();
        assert!(n > 0, "number of columns must be greater than zero");
        for (i, column) in columns.iter().enumerate() {
            assert_eq!(
                column.len(),
                n,
                "column {i} length mismatch n = {n}, column.len() = {}",
                column.len()
            );
        }
        assert!(
            names.is_empty() || names.len() == columns.len(),
            "names mismatch"
        );
        Self { n, columns, names }
    }

    pub fn n(&self) -> usize {
        self.n
    }
    pub fn num_cols(&self) -> usize {
        self.columns.len()
    }
    pub fn col(&self, c: usize) -> &[F] {
        &self.columns[c]
    }

    pub fn get(&self, c: usize, t: usize) -> F {
        self.columns[c][t]
    }

    pub fn get_next_cyclic(&self, c: usize, t: usize) -> F {
        self.columns[c][(t + 1) % self.n]
    }
}

pub struct RowView<'a, F: Field> {
    pub t: usize,
    pub n: usize,
    pub trace: &'a TraceTable<F>,
}

impl<'a, F: Field + Copy> RowView<'a, F> {
    pub fn cur(&self, c: usize) -> F {
        self.trace.get(c, self.t)
    }
    pub fn next(&self, c: usize) -> F {
        self.trace.get(c, (self.t + 1) % self.n)
    }
    pub fn next_k(&self, c: usize, k: usize) -> F {
        self.trace.get(c, (self.t + k) % self.n)
    }
}

pub type ConstraintFunction<F> = fn(&RowView<F>) -> F;

pub fn prove<F: PrimeField + FftField>(
    trace: &TraceTable<F>,
    domain_n: GeneralEvaluationDomain<F>,
    domain_m: GeneralEvaluationDomain<F>,
    shift: F,
    tx: &mut Transcript,
    constraints: &[ConstraintFunction<F>],
) -> Vec<F> {
    let n = domain_n.size();
    assert_eq!(n, trace.n(), "trace length must be equal to domain size");

    tx.absorb_params(n, 1, 1);
    let mut alphas: Vec<F> = vec![constraints.len()];
    for i in 0..constraints.len() {
        alphas.push(tx.challenge_field::<F>(&format!("air/alpha/{i}")));
    }

    let evaluations = vec![F::zero(); n];
    let disguised_evaluations = vec![vec![]; trace.columns.len()];
    for (i, column) in trace.columns.iter().enumerate() {
        disguised_evaluations[i] = lde_extend_column(column, &domain_n, &domain_m, shift);
    }
    // TODO: commit disguised table
    // TODO: derive challenges
    // TODO: compute verification poly
    // TODO: FRI prove it

    evaluations
}

/// Generate LDE of a column, by iFFting evaluations on N to coefficients, scaling them with a shift factor
/// and finally FFTing them back on the extended domain
fn lde_extend_column<F: Field>(
    column: &[F],
    domain_n: &Radix2EvaluationDomain<F>,
    domain_m: &Radix2EvaluationDomain<F>,
    shift: F,
) -> Vec<F> {
    assert_eq!(domain_n.len(), column.len());
    assert_eq!(domain_m.size % domain_n.size, 0);

    // interpolating column over domain n
    let mut coeffs = column.to_vec();
    domain_n.ifft_in_place(&mut coeffs);

    // scaling coefficients by shift^k so LDE is f(sx)
    let mut pow = F::one();
    for c in coeffs.iter_mut() {
        *c *= pow;
        pow *= shift;
    }

    // scale and fft to the LDE domain
    coeffs.resize(domain_m.size as usize, F::zero());
    domain_m.fft_in_place(&mut coeffs);
    coeffs
}
