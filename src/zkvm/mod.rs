use crate::backend::Transcript;
use ark_ff::PrimeField;

mod params;
mod prover;
mod verifier;

pub use params::{TranscriptLabels, ZkvmPublicParameters};
pub use prover::{TraceQuery, ZkvmProof, ZkvmProveError, hash_trace_row_iter, prove};
pub use verifier::{ZkvmVerifyError, verify};

pub fn generate_mixing_challenges<F: PrimeField>(
    constraints_len: usize,
    tx: &mut Transcript,
) -> Vec<F> {
    (0..constraints_len)
        .map(|i| tx.challenge_field::<F>(&TranscriptLabels::air_alpha(i)))
        .collect()
}
