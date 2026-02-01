use crate::{
    air::{Air, RowAccess, TraceTable, eval_composition},
    backend::{
        AuthPath, Blake3Hasher, Digest, FriProof, FriProofError, FriQuery, Hasher, MerkleError,
        MerkleTree, Transcript, fri_prove,
    },
    zkvm::{TranscriptLabels, ZkvmPublicParameters, generate_mixing_challenges},
};
use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::CanonicalSerialize;
use thiserror::Error;

/// API for constraint functions to access the table
#[derive(Clone, Debug)]
pub struct ProverRowLdeView<'a, F> {
    pub i: usize,
    pub previous_i: usize,
    pub x: F,                  // x in the shifted LDE cosset
    pub x0: F,                 // first x in the n domain
    pub x_last: F,             // last x in the n domain
    pub z_h_inverse: F,        // (x^n - 1)^-1
    pub columns: &'a [Vec<F>], // lde trace
}

impl<'a, F: PrimeField> RowAccess<F> for ProverRowLdeView<'a, F> {
    fn current_step_column_value(&self, column: usize) -> F {
        self.columns[column][self.i]
    }

    fn previous_step_column_value(&self, column: usize) -> F {
        self.columns[column][self.previous_i]
    }

    fn x(&self) -> F {
        self.x
    }

    fn x0(&self) -> F {
        self.x0
    }

    fn x_last(&self) -> F {
        self.x_last
    }

    fn z_h_inverse(&self) -> F {
        self.z_h_inverse
    }
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

    #[error("fri query has 0 rounds")]
    BadFriQuery,
}

#[derive(Clone, Debug)]
pub struct TraceQuery<F: PrimeField> {
    pub i: usize,
    pub current_row: Vec<F>, // at i
    pub current_row_path: AuthPath,
    pub previous_row: Vec<F>, // at (i - blowup) mod m
    pub previous_row_path: AuthPath,
}

#[derive(Clone, Debug)]
pub struct ZkvmProof<F: PrimeField> {
    /// Commitments
    pub trace_root: Digest, // Merkle root for LDE evaluations
    pub composition_root: Digest, // Merkle root of V_evals
    /// fri proof
    pub fri_proof: FriProof<F>,
    // openings to bind V to trace
    pub trace_queries: Vec<TraceQuery<F>>,
}

pub fn prove<A, F>(
    trace: &TraceTable<F>,
    air: &A,
    tx: &mut Transcript,
    public_params: &ZkvmPublicParameters<F>,
) -> Result<ZkvmProof<F>, ZkvmProveError>
where
    A: Air<F>,
    F: PrimeField + FftField + CanonicalSerialize,
{
    let ZkvmPublicParameters {
        trace_domain,
        lde_domain,
        shift: _,
        fri_options,
    } = public_params;

    let shift = public_params.shift;
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
    public_params.seed_tx(tx);

    // build shifted LDE trace and commit it
    let mut disguised_evaluations: Vec<Vec<F>> = Vec::with_capacity(num_columns);

    for column in trace.columns.iter() {
        disguised_evaluations.push(lde_extend_column(column, trace_domain, lde_domain, shift));
    }

    let trace_tree = generate_trace_tree(lde_domain_size, &disguised_evaluations)?;
    let trace_root = trace_tree.root();
    tx.absorb_digest(TranscriptLabels::TRACE_ROOT, trace_root);

    // generating alphas for future mixing
    let alphas: Vec<F> = generate_mixing_challenges(air.num_constraints(), tx);

    let verification_evaluations = build_verification_evaluations(
        air,
        shift,
        trace_domain,
        lde_domain,
        &alphas,
        &disguised_evaluations,
    )?;

    let fri_proof = fri_prove(&verification_evaluations, lde_domain, fri_options, tx)?;

    // open same indexes as in fri
    let trace_queries = generate_trace_queries(
        lde_domain_size,
        blowup_factor,
        &fri_proof.queries,
        &disguised_evaluations,
        &trace_tree,
    )?;

    Ok(ZkvmProof {
        trace_root: *trace_root,
        composition_root: fri_proof.roots[0],
        fri_proof,
        trace_queries,
    })
}

fn generate_trace_tree<F: PrimeField>(
    lde_domain_size: usize,
    disguised_evaluations: &[Vec<F>],
) -> Result<MerkleTree<Blake3Hasher>, MerkleError> {
    let mut leaf_digests = Vec::with_capacity(lde_domain_size);

    for i in 0..lde_domain_size {
        leaf_digests.push(hash_trace_row_from_columns(i, disguised_evaluations));
    }

    MerkleTree::<Blake3Hasher>::from_leaf_digests(&leaf_digests)
}

pub fn hash_trace_row_from_columns<F: CanonicalSerialize>(
    step_index: usize,
    columns: &[Vec<F>],
) -> Digest {
    hash_trace_row_iter(step_index, columns.iter().map(|column| &column[step_index]))
}

pub fn hash_trace_row_iter<'a, F, I>(step_index: usize, values: I) -> Digest
where
    F: CanonicalSerialize + 'a,
    I: IntoIterator<Item = &'a F>,
{
    let mut buffer = Vec::new();
    buffer.extend_from_slice(TranscriptLabels::TRACE_ROW_PREFIX);
    buffer.extend_from_slice(&step_index.to_le_bytes());

    for x in values {
        x.serialize_compressed(&mut buffer).unwrap();
    }

    Blake3Hasher::hash_leaf(&buffer)
}

fn generate_trace_queries<F: PrimeField>(
    lde_domain_size: usize,
    blowup_factor: usize,
    fri_queries: &[FriQuery<F>],
    disguised_evaluations: &[Vec<F>],
    trace_tree: &MerkleTree<Blake3Hasher>,
) -> Result<Vec<TraceQuery<F>>, ZkvmProveError> {
    let mut trace_queries = Vec::with_capacity(fri_queries.len());
    for query in fri_queries {
        let first_round = query.rounds.first().ok_or(ZkvmProveError::BadFriQuery)?;

        let opened_index = first_round.left.path.index;
        let previous_step_index =
            (opened_index + lde_domain_size - blowup_factor) % lde_domain_size;

        // row openings
        let current_row: Vec<F> = disguised_evaluations
            .iter()
            .map(|col| col[opened_index])
            .collect();
        let current_row_path = trace_tree.open(opened_index)?;
        let previous_row: Vec<F> = disguised_evaluations
            .iter()
            .map(|col| col[previous_step_index])
            .collect();
        let previous_row_path = trace_tree.open(previous_step_index)?;

        trace_queries.push(TraceQuery {
            i: opened_index,
            current_row,
            current_row_path,
            previous_row,
            previous_row_path,
        });
    }

    Ok(trace_queries)
}

/// Generate LDE of a column, by iFFting evaluations on N to coefficients, scaling them with a shift factor
/// and finally FFTing them back on the extended domain
fn lde_extend_column<F: FftField>(
    column: &[F],
    initial_domain: &Radix2EvaluationDomain<F>,
    lde_domain: &Radix2EvaluationDomain<F>,
    shift: F,
) -> Vec<F> {
    let n = initial_domain.size();
    let m = lde_domain.size();
    assert_eq!(n, column.len());
    assert_eq!(m % n, 0);

    // interpolating column over domain n
    let mut coeffs = column.to_vec();
    initial_domain.ifft_in_place(&mut coeffs);

    // scaling coefficients by shift^k so LDE is f(sx)
    let mut pow = F::one();
    for c in coeffs.iter_mut() {
        *c *= pow;
        pow *= shift;
    }

    // scale and fft to the LDE domain
    coeffs.resize(m, F::zero());
    lde_domain.fft_in_place(&mut coeffs);
    coeffs
}

fn build_verification_evaluations<F, A>(
    air: &A,
    shift: F,
    trace_domain: &Radix2EvaluationDomain<F>,
    lde_domain: &Radix2EvaluationDomain<F>,
    alphas: &[F],
    lde_evaluations: &[Vec<F>],
) -> Result<Vec<F>, ZkvmProveError>
where
    F: PrimeField,
    A: Air<F>,
{
    let trace_domain_size = trace_domain.size();
    let lde_domain_size = lde_domain.size();
    let blowup_factor = lde_domain_size / trace_domain_size;

    // Optional but helpful: sanity check that AIR width matches trace width
    debug_assert_eq!(air.width(), lde_evaluations.len());

    let mut out = Vec::with_capacity(lde_domain_size);

    let x0 = trace_domain.element(0);
    let x_last = trace_domain.element(trace_domain_size - 1);

    for i in 0..lde_domain_size {
        let previous_i = (i + lde_domain_size - blowup_factor) % lde_domain_size;

        let x = shift * lde_domain.element(i);
        let z_h = x.pow([trace_domain_size as u64]) - F::one();
        let z_h_inverse = z_h
            .inverse()
            .ok_or(ZkvmProveError::VanishingPolyNotInvertible { i })?;

        let row = ProverRowLdeView {
            i,
            previous_i,
            x,
            x0,
            x_last,
            columns: lde_evaluations,
            z_h_inverse,
        };

        let v = eval_composition(air, &row, alphas);
        out.push(v);
    }

    Ok(out)
}
