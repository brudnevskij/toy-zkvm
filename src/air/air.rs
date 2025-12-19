use crate::backend::Transcript;
use ark_ff::{FftField, Field, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
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

pub fn build_check_evals<F: PrimeField + FftField>(
    trace: &TraceTable<F>,
    domain: GeneralEvaluationDomain<F>,
    tx: &mut Transcript,
    constraints: &[ConstraintFunction<F>],
) -> Vec<F> {
    let n = domain.size();
    assert_eq!(n, trace.n(), "trace length must be equal to domain size");

    tx.absorb_params(n, 1, 1);
    let mut alphas: Vec<F> = vec![constraints.len()];
    for i in 0..constraints.len() {
        alphas.push(tx.challenge_field::<F>(&format!("air/alpha/{i}")));
    }

    let evaluations = vec![F::zero(); n];
    for t in 0..n {
        let rv = RowView { t, n, trace };
        let mut acc = F::zero();
        for (alpha, f) in alphas.iter().zip(constraints.iter()) {
            acc += *alpha * f(&rv);
        }
        evaluations[t] = acc;
    }
    evaluations
}
