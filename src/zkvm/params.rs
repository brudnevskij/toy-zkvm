use crate::backend::{FriOptions, Transcript};
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
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

#[derive(Debug, Clone)]
pub struct PreprocessedTraceEvals<F> {
    pub first_row_selector: Vec<F>,
    pub last_row_selector: Vec<F>,
}

#[derive(Debug, Clone, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct ZkvmPublicParameters<F: PrimeField> {
    pub trace_domain: Radix2EvaluationDomain<F>,
    pub lde_domain: Radix2EvaluationDomain<F>,
    pub shift: F,

    pub fri_options: FriOptions<F>,
}

impl<F: PrimeField> ZkvmPublicParameters<F> {
    pub fn seed_tx(&self, tx: &mut Transcript) {
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

    pub fn derive_preprocessed_trace_evals(&self) -> PreprocessedTraceEvals<F> {
        let n = self.trace_domain.size();
        let n_f = F::from(n as u64);

        let g = self.trace_domain.group_gen();
        let w = self.lde_domain.group_gen();

        let x0 = F::one();
        let x_last = g.pow([(n - 1) as u64]);

        let zh_prime_x0 = n_f * x0.pow([(n - 1) as u64]);
        let zh_prime_x_last = n_f * x_last.pow([(n - 1) as u64]);

        let inv_zh_prime_x0 = zh_prime_x0.inverse().expect("n must be invertible");
        let inv_zh_prime_x_last = zh_prime_x_last
            .inverse()
            .expect("n * x_last^(n-1) must be invertible");

        let mut first_row_selector = Vec::with_capacity(self.lde_domain.size());
        let mut last_row_selector = Vec::with_capacity(self.lde_domain.size());

        let mut x = self.shift;
        for _ in 0..self.lde_domain.size() {
            let z_h = x.pow([n as u64]) - F::one();

            let first = z_h
                * (x - x0)
                    .inverse()
                    .expect("shifted LDE coset must avoid trace domain")
                * inv_zh_prime_x0;

            let last = z_h
                * (x - x_last)
                    .inverse()
                    .expect("shifted LDE coset must avoid trace domain")
                * inv_zh_prime_x_last;

            first_row_selector.push(first);
            last_row_selector.push(last);

            x *= w;
        }

        PreprocessedTraceEvals {
            first_row_selector,
            last_row_selector,
        }
    }
}
