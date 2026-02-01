use crate::{
    air::{Air, RowAccess, eval_composition},
    backend::{Blake3Hasher, FriVerificationError, Transcript, fri_verify, verify_leaf},
    zkvm::{
        TraceQuery, TranscriptLabels, ZkvmProof, ZkvmPublicParameters, generate_mixing_challenges,
        hash_trace_row_iter,
    },
};
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use thiserror::Error;

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

#[derive(Clone, Debug)]
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

pub fn verify<A, F>(
    proof: &ZkvmProof<F>,
    air: &A,
    tx: &mut Transcript,
    public_params: &ZkvmPublicParameters<F>,
) -> Result<(), ZkvmVerifyError>
where
    A: Air<F>,
    F: PrimeField,
{
    public_params.seed_tx(tx);
    tx.absorb_digest(TranscriptLabels::TRACE_ROOT, &proof.trace_root);
    let alphas = generate_mixing_challenges::<F>(air.num_constraints(), tx);

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
        let previous_row_merkle_verification =
            verify_leaf::<Blake3Hasher>(&proof.trace_root, &previous_row_digest, previous_row_path);

        if !(current_row_merkle_verificattion && previous_row_merkle_verification) {
            return Err(ZkvmVerifyError::MerkleVerificationFailed {
                current_row: current_row_merkle_verificattion,
                previous_row: previous_row_merkle_verification,
            });
        }

        // compute verification polynomial evaluations for a given i
        let x = public_params.shift * public_params.lde_domain.element(i);
        let z_h = x.pow([trace_domain_size as u64]) - F::one();
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

        if first_round.left.value != eval_composition(air, &row, &alphas) {
            return Err(ZkvmVerifyError::VerificationFailed);
        }
    }

    fri_verify(
        &proof.fri_proof,
        &public_params.lde_domain,
        &public_params.fri_options,
        tx,
    )?;
    Ok(())
}
