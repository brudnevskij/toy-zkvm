use crate::backend::{FriOptions, Transcript};
use ark_ff::PrimeField;
use ark_poly::Radix2EvaluationDomain;

pub struct TranscriptLabels;

impl TranscriptLabels {
    // --- public params ---
    pub const TRACE_DOMAIN_SIZE: &'static str = "trace_domain_size";
    pub const LDE_DOMAIN_SIZE: &'static str = "lde_domain_size";
    pub const SHIFT: &'static str = "shift";
    pub const FRI_MAX_DEGREE: &'static str = "fri_max_degree";
    pub const FRI_MAX_REMAINDER_DEGREE: &'static str = "fri_max_remainder_degree";
    pub const FRI_NUM_QUERIES: &'static str = "fri_num_queries";

    // --- commitments / roots ---
    pub const TRACE_ROOT: &'static str = "trace_root";
    pub const COMPOSITION_ROOT: &'static str = "composition_root"; // if you have one
    pub const TRACE_ROW_PREFIX: &'static [u8] = b"trace_row";

    // --- challenges ---
    pub const AIR_ALPHA_PREFIX: &'static str = "air/alpha/";

    #[inline]
    pub fn air_alpha(i: usize) -> String {
        format!("{}{i}", Self::AIR_ALPHA_PREFIX)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ZkvmPublicParameters<F: PrimeField> {
    pub trace_domain: Radix2EvaluationDomain<F>,
    pub lde_domain: Radix2EvaluationDomain<F>,
    pub shift: F,

    pub fri_options: FriOptions<F>,
}

impl<F: PrimeField> ZkvmPublicParameters<F> {
    pub(crate) fn seed_tx(&self, tx: &mut Transcript) {
        tx.absorb_bytes(
            TranscriptLabels::TRACE_DOMAIN_SIZE,
            &self.trace_domain.size().to_le_bytes(),
        );
        tx.absorb_bytes(
            TranscriptLabels::LDE_DOMAIN_SIZE,
            &self.lde_domain.size().to_le_bytes(),
        );
        tx.absorb_field(TranscriptLabels::SHIFT, &self.shift);
        tx.absorb_bytes(
            TranscriptLabels::FRI_MAX_DEGREE,
            &self.fri_options.max_degree.to_le_bytes(),
        );
        tx.absorb_bytes(
            TranscriptLabels::FRI_MAX_REMAINDER_DEGREE,
            &self.fri_options.max_remainder_degree.to_le_bytes(),
        );
        tx.absorb_bytes(
            TranscriptLabels::FRI_NUM_QUERIES,
            &self.fri_options.query_number.to_le_bytes(),
        );
    }
}
