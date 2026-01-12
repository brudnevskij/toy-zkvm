use crate::backend::{
    AuthPath, Blake3Hasher, Digest, FriOptions, FriProof, FriProofError, Hasher, MerkleError,
    MerkleTree, Transcript, fri_prove,
};
use ark_ff::{FftField, Field, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::CanonicalSerialize;
use ark_std::iterable::Iterable;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct TraceTable<F: Field> {
    n: usize,
    columns: Vec<Vec<F>>,
    names: Vec<&'static str>,
}

#[derive(Debug, Error)]
pub enum ZkvmProveError {
    #[error("trace length mismatch: trace.n={trace_n}, domain_n.size={domain_n}")]
    TraceLengthMismatch { trace_n: usize, domain_n: usize },

    #[error("bad LDE domain sizes: m must be a multiple of n (n={n}, m={m})")]
    BadLdeDomains { n: usize, m: usize },

    #[error("vanishing polynomial Z_H(x)=x^n-1 is zero at i={i} (cannot invert)")]
    VanishingPolyNotInvertible { i: usize },

    #[error("merkle error: {0}")]
    Merkle(#[from] MerkleError),

    #[error("fri error: {0}")]
    Fri(#[from] FriProofError),

    #[error("serialization error: {0}")]
    Serialization(#[from] ark_serialize::SerializationError),
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

/// API for constraint functions to access the table
#[derive(Clone, Debug)]
pub struct RowLDEView<'a, F> {
    pub i: usize,
    pub x: F,           // x in the shifted LDE cosset
    pub x0: F,          // first x in the n domain
    pub x_last: F,      // last x in the n domain
    pub cur: &'a [F],   // current row
    pub prev: &'a [F],  // previous row
    pub z_h_inverse: F, // (x^n - 1)^-1
}

pub type ConstraintFunction<F> = fn(&RowLDEView<F>) -> F;

pub struct TraceQuery<F: PrimeField> {
    pub i: usize,
    pub cur_row: Vec<F>, // at i
    pub cur_path: AuthPath,
    pub prev_row: Vec<F>, // at (i - blowup) mod m
    pub prev_path: AuthPath,
}
pub struct ZkvmProof<F: PrimeField> {
    /// Commitments
    pub trace_root: Digest, // Merkle root for LDE evaluations
    pub composition_root: Digest, // Merkle root of V_evals
    /// fri proof
    pub fri_proof: FriProof<F>,
    // openings to bind V to trace
    pub trace_queries: Vec<TraceQuery<F>>,
}

pub fn prove<F: PrimeField + FftField + CanonicalSerialize>(
    trace: &TraceTable<F>,
    trace_domain: Radix2EvaluationDomain<F>,
    lde_domain: Radix2EvaluationDomain<F>,
    shift: F,
    tx: &mut Transcript,
    constraints: &[ConstraintFunction<F>],
) -> Result<ZkvmProof<F>, ZkvmProveError> {
    let trace_domain_size = trace_domain.size();
    let lde_domain_size = lde_domain.size();
    let trace_len = trace.n();
    let num_columns = trace.num_cols();
    if trace_domain_size != trace_len {
        return Err(ZkvmProveError::TraceLengthMismatch {
            trace_n: trace_len,
            domain_n: trace_domain_size,
        });
    }
    if lde_domain_size % trace_domain_size != 0 {
        return Err(ZkvmProveError::BadLdeDomains {
            n: trace_domain_size,
            m: lde_domain_size,
        });
    }
    let blowup_factor = lde_domain_size / trace_domain_size;

    // TODO: change to absorb pub params
    tx.absorb_params(trace_domain_size, 1, 1);

    // LDE the trace
    let mut disguised_evaluations: Vec<Vec<F>> = Vec::with_capacity(num_columns);

    for column in trace.columns.iter() {
        disguised_evaluations.push(lde_extend_column(column, &trace_domain, &lde_domain, shift));
    }

    let trace_tree = {
        let mut leaf_digests = Vec::with_capacity(lde_domain_size);
        for i in 0..lde_domain_size {
            let mut buf = Vec::with_capacity(trace.columns.len() * 32);
            // mmarking the buffer
            buf.extend_from_slice(b"trace_row");
            buf.extend_from_slice(&(i as u32).to_le_bytes());
            for c in 0..trace.columns.len() {
                push_field_bytes(&disguised_evaluations[c][i], &mut buf);
            }
            leaf_digests.push(Blake3Hasher::hash_leaf(&buf));
        }
        MerkleTree::<Blake3Hasher>::from_leaf_digests(&leaf_digests)?
    };

    let trace_root = trace_tree.root();
    tx.absorb_digest("trace_root", &trace_root);

    // generating alphas for future mixing
    let alphas: Vec<F> = (0..constraints.len())
        .into_iter()
        .map(|i| tx.challenge_field::<F>(&format!("air/alpha/{i}")))
        .collect();

    // constructing V evals
    let x0 = trace_domain.element(0);
    let x_last = trace_domain.element(trace_domain_size - 1);
    let mut v_evals = vec![F::zero(); lde_domain_size];
    for i in 0..lde_domain_size {
        let previous_index = (i + lde_domain_size - blowup_factor) % lde_domain_size;

        let cur_row: Vec<F> = disguised_evaluations.iter().map(|clmn| clmn[i]).collect();
        let prev_row: Vec<F> = disguised_evaluations
            .iter()
            .map(|clmn| clmn[previous_index])
            .collect();

        let x = shift * lde_domain.element(i);
        let z_h = x.pow([trace_domain_size as u64]) - F::one();
        let z_h_inverse = z_h
            .inverse()
            .ok_or(ZkvmProveError::VanishingPolyNotInvertible { i })?;

        let row = RowLDEView {
            i,
            x,
            x0,
            x_last,
            cur: &cur_row,
            prev: &prev_row,
            z_h_inverse,
        };

        let mut acc = F::zero();
        for (alpha, c) in alphas.iter().zip(constraints.iter()) {
            acc += *alpha * c(&row);
        }
        v_evals[i] = acc;
    }

    let fri_options = FriOptions {
        max_degree: 2 * trace_domain_size,
        max_remainder_degree: 1,
    };

    // TODO handle error
    let fri_proof = fri_prove(&v_evals, lde_domain, &fri_options, tx)?;

    // open same indexes as in fri
    let mut trace_queries = Vec::with_capacity(fri_proof.queries.len());
    for q in &fri_proof.queries {
        let first_round = q
            .rounds
            .first()
            .expect("Must be at least 1 round in each query");

        let opened_index = first_round.left.path.index;
        let previous_step_index =
            (opened_index + lde_domain_size - blowup_factor) % lde_domain_size;

        let cur_row = disguised_evaluations
            .iter()
            .map(|col| col[opened_index])
            .collect();
        let cur_path = trace_tree.open(opened_index)?;
        let prev_row = disguised_evaluations
            .iter()
            .map(|col| col[previous_step_index])
            .collect();
        let prev_path = trace_tree.open(previous_step_index)?;

        trace_queries.push(TraceQuery {
            i: opened_index,
            cur_row,
            cur_path,
            prev_row,
            prev_path,
        });
    }

    Ok(ZkvmProof {
        trace_root: *trace_root,
        composition_root: fri_proof.roots[0],
        fri_proof,
        trace_queries,
    })
}

fn push_field_bytes<F: CanonicalSerialize>(x: &F, out: &mut Vec<u8>) {
    x.serialize_compressed(out).unwrap(); // compressed is fine for a field element
}

/// Generate LDE of a column, by iFFting evaluations on N to coefficients, scaling them with a shift factor
/// and finally FFTing them back on the extended domain
fn lde_extend_column<F: FftField>(
    column: &[F],
    domain_n: &Radix2EvaluationDomain<F>,
    domain_m: &Radix2EvaluationDomain<F>,
    shift: F,
) -> Vec<F> {
    let n = domain_n.size();
    let m = domain_m.size();
    assert_eq!(n, column.len());
    assert_eq!(m % n, 0);

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
    coeffs.resize(m, F::zero());
    domain_m.fft_in_place(&mut coeffs);
    coeffs
}
