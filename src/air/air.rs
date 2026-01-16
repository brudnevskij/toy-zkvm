use crate::backend::{
    AuthPath, Blake3Hasher, Digest, FriOptions, FriProof, FriProofError, FriQuery,
    FriVerificationError, Hasher, MerkleError, MerkleTree, Transcript, fri_prove, fri_verify,
    verify_leaf,
};
use ark_ff::{FftField, Field, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::CanonicalSerialize;
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

    #[error("fri query has 0 rounds")]
    BadFriQuery,
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
}

pub trait RowAccess<F: PrimeField> {
    fn current_step_column_value(&self, column: usize) -> F;
    fn previous_step_column_value(&self, column: usize) -> F;

    fn x(&self) -> F;
    fn x0(&self) -> F;
    fn x_last(&self) -> F;
    fn z_h_inverse(&self) -> F;
}

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

pub type ConstraintFunction<F> = fn(&dyn RowAccess<F>) -> F;

pub struct TraceQuery<F: PrimeField> {
    pub i: usize,
    pub current_row: Vec<F>, // at i
    pub current_row_path: AuthPath,
    pub previous_row: Vec<F>, // at (i - blowup) mod m
    pub previous_row_path: AuthPath,
}

// ---- Transcript labels (single source of truth) ----

// public params
pub const TRACE_DOMAIN_SIZE_LABEL: &str = "trace_domain_size";
pub const LDE_DOMAIN_SIZE_LABEL: &str = "lde_domain_size";
pub const SHIFT_LABEL: &str = "shift";
pub const FRI_MAX_DEGREE_LABEL: &str = "fri_max_degree";
pub const FRI_MAX_REMAINDER_DEGREE_LABEL: &str = "fri_max_remainder_degree";

// commitments / roots
pub const TRACE_ROOT_LABEL: &str = "trace_root";
pub const TRACE_ROW_LABEL: &[u8] = b"trace_row";

// challenges
pub const AIR_ALPHA_PREFIX: &str = "air/alpha/";

// helper to produce "air/alpha/{i}" without repeating the string literal everywhere
#[inline]
pub fn air_alpha_label(i: usize) -> String {
    format!("{AIR_ALPHA_PREFIX}{i}")
}

#[derive(Debug, Clone, Copy)]
pub struct ZkvmPublicParameters<F: PrimeField> {
    trace_domain: Radix2EvaluationDomain<F>,
    lde_domain: Radix2EvaluationDomain<F>,
    shift: F,
    fri_max_degree: usize,
    fri_max_remainder_degree: usize,
}

// TODO: consider adding constructor with domain assertions
impl<F: PrimeField> ZkvmPublicParameters<F> {
    fn seed_tx(&self, tx: &mut Transcript) {
        tx.absorb_bytes(
            TRACE_DOMAIN_SIZE_LABEL,
            &self.trace_domain.size().to_le_bytes(),
        );
        tx.absorb_bytes(LDE_DOMAIN_SIZE_LABEL, &self.lde_domain.size().to_le_bytes());
        tx.absorb_field(SHIFT_LABEL, &self.shift);
        tx.absorb_bytes(FRI_MAX_DEGREE_LABEL, &self.fri_max_degree.to_le_bytes());
        tx.absorb_bytes(
            FRI_MAX_REMAINDER_DEGREE_LABEL,
            &self.fri_max_remainder_degree.to_le_bytes(),
        );
    }
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
    tx: &mut Transcript,
    constraints: &[ConstraintFunction<F>],
    public_params: &ZkvmPublicParameters<F>,
) -> Result<ZkvmProof<F>, ZkvmProveError> {
    let ZkvmPublicParameters {
        trace_domain,
        lde_domain,
        shift: _,
        fri_max_degree,
        fri_max_remainder_degree,
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
        disguised_evaluations.push(lde_extend_column(column, &trace_domain, &lde_domain, shift));
    }

    let trace_tree = generate_trace_tree(lde_domain_size, &disguised_evaluations)?;
    let trace_root = trace_tree.root();
    tx.absorb_digest(TRACE_ROOT_LABEL, &trace_root);

    // generating alphas for future mixing
    let alphas: Vec<F> = generate_mixing_challenges(constraints.len(), tx);

    let verification_evaluations = construct_verification_evaluations(
        shift,
        trace_domain,
        lde_domain,
        &alphas,
        &disguised_evaluations,
        constraints,
    )?;

    let fri_options = FriOptions {
        max_degree: *fri_max_degree,
        max_remainder_degree: *fri_max_remainder_degree,
    };

    let fri_proof = fri_prove(&verification_evaluations, lde_domain, &fri_options, tx)?;

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

fn hash_trace_row_from_columns<F: CanonicalSerialize>(
    step_index: usize,
    columns: &[Vec<F>],
) -> Digest {
    hash_trace_row_iter(step_index, columns.iter().map(|column| &column[step_index]))
}

fn hash_trace_row_iter<'a, F, I>(step_index: usize, values: I) -> Digest
where
    F: CanonicalSerialize + 'a,
    I: IntoIterator<Item = &'a F>,
{
    let mut buffer = Vec::new();
    buffer.extend_from_slice(TRACE_ROW_LABEL);
    buffer.extend_from_slice(&step_index.to_le_bytes());

    for x in values {
        x.serialize_compressed(&mut buffer).unwrap();
    }

    Blake3Hasher::hash_leaf(&buffer)
}

fn construct_verification_evaluations<F: PrimeField>(
    shift: F,
    trace_domain: &Radix2EvaluationDomain<F>,
    lde_domain: &Radix2EvaluationDomain<F>,
    alphas: &[F],
    lde_evaluations: &[Vec<F>],
    constraints: &[ConstraintFunction<F>],
) -> Result<Vec<F>, ZkvmProveError> {
    let trace_domain_size = trace_domain.size();
    let lde_domain_size = lde_domain.size();
    let blowup_factor = lde_domain_size / trace_domain_size;
    let mut verification_evaluations = Vec::with_capacity(lde_domain_size);
    let x0 = trace_domain.element(0);
    let x_last = trace_domain.element(trace_domain_size - 1);

    for i in 0..lde_domain_size {
        let previous_step_index = (i + lde_domain_size - blowup_factor) % lde_domain_size;
        let x = shift * lde_domain.element(i);
        let z_h = x.pow(&[trace_domain_size as u64]) - F::one();
        let z_h_inverse = z_h
            .inverse()
            .ok_or(ZkvmProveError::VanishingPolyNotInvertible { i })?;

        let row_view = ProverRowLdeView {
            i,
            previous_i: previous_step_index,
            x,
            x0,
            x_last,
            columns: lde_evaluations,
            z_h_inverse,
        };

        let mut acc = F::zero();

        // TODO: consider changing zip, as it migh drop certaints constraints if alphas.len <
        // constraints.len()
        for (&alpha, constraint) in alphas.iter().zip(constraints.iter()) {
            acc += alpha * constraint(&row_view);
        }
        verification_evaluations.push(acc);
    }

    Ok(verification_evaluations)
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

fn generate_mixing_challenges<F: PrimeField>(
    constraints_len: usize,
    tx: &mut Transcript,
) -> Vec<F> {
    (0..constraints_len)
        .map(|i| tx.challenge_field::<F>(&air_alpha_label(i)))
        .collect()
}

#[derive(Debug, Error)]
pub enum ZkvmVerifyError {
    #[error("verification failed")]
    VerificationFailed,

    #[error("bad fri proof")]
    BadFriProof,

    #[error(
        "merkle verification failed: current row verificattion: {current_row}, previous row verification {previous_row}"
    )]
    MerkleVerificationFailed {
        current_row: bool,
        previous_row: bool,
    },

    #[error("fri verification error: {0}")]
    FriVerificationError(#[from] FriVerificationError),

    #[error("vanishing polynomial Z_H(x)=x^n-1 is zero at i={i} (cannot invert)")]
    VanishingPolyNotInvertible { i: usize },
}

struct VerifierRowLdeView<'a, F: PrimeField> {
    pub i: usize,
    pub previous_i: usize,
    pub x: F,           // x in the shifted LDE cosset
    pub x0: F,          // first x in the n domain
    pub x_last: F,      // last x in the n domain
    pub z_h_inverse: F, // (x^n - 1)^-1
    pub current_row: &'a [F],
    pub previous_row: &'a [F],
}

impl<'a, F: PrimeField> RowAccess<F> for VerifierRowLdeView<'a, F> {
    fn current_step_column_value(&self, column: usize) -> F {
        self.current_row[column]
    }

    fn previous_step_column_value(&self, column: usize) -> F {
        self.previous_row[column]
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

pub fn verify<F: PrimeField>(
    proof: &ZkvmProof<F>,
    tx: &mut Transcript,
    constraints: &[ConstraintFunction<F>],
    public_params: &ZkvmPublicParameters<F>,
) -> Result<(), ZkvmVerifyError> {
    public_params.seed_tx(tx);
    tx.absorb_digest(TRACE_ROOT_LABEL, &proof.trace_root);
    let alphas = generate_mixing_challenges::<F>(constraints.len(), tx);

    // asserting length of fri and zkvm queries, as well as length of rounds > 0
    let ok = proof.trace_queries.len() == proof.fri_proof.queries.len();
    if !ok {
        return Err(ZkvmVerifyError::BadFriProof);
    }

    let trace_domain_size = public_params.trace_domain.size();
    let x0 = public_params.trace_domain.element(0);
    let x_last = public_params.trace_domain.element(trace_domain_size - 1);
    for (trace_query, fri_query) in proof
        .trace_queries
        .iter()
        .zip(proof.fri_proof.queries.iter())
    {
        let TraceQuery {
            i: _,
            current_row,
            current_row_path,
            previous_row,
            previous_row_path,
        } = trace_query;
        // TODO: consider asserting i == current_row_path.index and
        // previous_i == previous_row_path.index

        let i = trace_query.i;
        let first_round = fri_query
            .rounds
            .first()
            .ok_or(ZkvmVerifyError::BadFriProof)?;
        if i != first_round.left.path.index {
            return Err(ZkvmVerifyError::BadFriProof);
        }

        // merkle verification
        let lde_domain_size = public_params.lde_domain.size();
        let blowup_factor = lde_domain_size / trace_domain_size;
        let previous_i = (i + lde_domain_size - blowup_factor) % lde_domain_size;

        let current_row_digest = hash_trace_row_iter(i, current_row.iter());
        let current_row_merkle_verificattion =
            verify_leaf::<Blake3Hasher>(&proof.trace_root, &current_row_digest, current_row_path);
        let previous_row_digest = hash_trace_row_iter(previous_i, previous_row.iter());
        let previous_row_merkle_verification = verify_leaf::<Blake3Hasher>(
            &proof.trace_root,
            &previous_row_digest,
            &previous_row_path,
        );

        if !(current_row_merkle_verificattion && previous_row_merkle_verification) {
            return Err(ZkvmVerifyError::MerkleVerificationFailed {
                current_row: current_row_merkle_verificattion,
                previous_row: previous_row_merkle_verification,
            });
        }

        // compute verification polynomial evaluations for a given i
        let x = public_params.shift * public_params.lde_domain.element(i);
        let z_h = x.pow(&[trace_domain_size as u64]) - F::one();
        let z_h_inverse = z_h
            .inverse()
            .ok_or(ZkvmVerifyError::VanishingPolyNotInvertible { i })?;

        let row = VerifierRowLdeView {
            i,
            previous_i,
            x,
            x0,
            x_last,
            z_h_inverse,
            current_row,
            previous_row,
        };

        let mut v_evaluation_at_i = F::zero();

        for (&alpha, constraint) in alphas.iter().zip(constraints.iter()) {
            v_evaluation_at_i += alpha * constraint(&row);
        }

        if first_round.left.value != v_evaluation_at_i {
            return Err(ZkvmVerifyError::VerificationFailed);
        }
    }

    let fri_options = FriOptions {
        max_degree: public_params.fri_max_degree,
        max_remainder_degree: public_params.fri_max_remainder_degree,
    };

    fri_verify(
        &proof.fri_proof,
        &public_params.lde_domain,
        &fri_options,
        tx,
    )?;
    Ok(())
}
