use crate::backend::Transcript;
use crate::backend::{AuthPath, Blake3Hasher, Digest, MerkleError, MerkleTree, verify_row};
use ark_ff::{FftField, Field, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct FriProof<F: Field> {
    // Merkle roots per FRI step
    pub roots: Vec<Digest>,
    // Queries for each step of FRI, one per index queried
    pub queries: Vec<FriQuery<F>>,
    pub final_eval: F,
}

/// FriQuery contains folds for each step of FRI
#[derive(Debug, Clone)]
pub struct FriQuery<F: Field> {
    pub rounds: Vec<FriRound<F>>,
}

/// FriRound contains left and right addend of FRI folding scheme and their auth
/// f(x), f(-x)
#[derive(Debug, Clone)]
pub struct FriRound<F: Field> {
    pub left: Opened<F>,
    pub right: Opened<F>,
}

/// Opened contains value and merkle tree auth path
#[derive(Debug, Clone)]
pub struct Opened<F: Field> {
    pub value: F,
    pub path: AuthPath,
}

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("polynomial degree is bigger then domain")]
    DegreeExceedsDomain,
    #[error("evaluations length exceeds domain")]
    EvaluationsExceedsDomain,

    #[error(transparent)]
    Merkle(#[from] MerkleError),
}

pub fn prove_from_coefficients<F: PrimeField + FftField>(
    coeffs: &[F],
    domain: GeneralEvaluationDomain<F>,
    tx: &mut Transcript,
) -> Result<FriProof<F>, ProofError> {
    let n0 = domain.size();
    if coeffs.is_empty() || coeffs.len() > n0 {
        return Err(ProofError::DegreeExceedsDomain);
    }
    let mut evals = vec![F::zero(); n0];
    evals[..coeffs.len()].copy_from_slice(coeffs);
    domain.fft_in_place(&mut evals);
    prove(&evals, domain, tx)
}
pub fn prove<F: PrimeField + FftField>(
    evals: &[F],
    domain0: GeneralEvaluationDomain<F>,
    tx: &mut Transcript,
) -> Result<FriProof<F>, ProofError> {
    let n0 = domain0.size();
    if evals.is_empty() || evals.len() != n0 {
        return Err(ProofError::EvaluationsExceedsDomain);
    }
    let g0 = domain0.group_gen();

    // TODO: make it scalable
    let num_queries = 1;
    tx.absorb_params(n0, 1, num_queries);

    let mut evaluations_layers = vec![];
    let mut roots = vec![];
    let mut trees = vec![];
    let mut domain_sizes = vec![];
    let mut n = n0;
    let mut g = g0;
    let mut evals_i = evals.to_vec();

    // calculate fold
    while n > 1 {
        let leaves_bytes = evals_to_bytes(&evals_i);
        let leaf_refs: Vec<_> = leaves_bytes.iter().map(|v| v.as_slice()).collect();
        let tree = MerkleTree::<Blake3Hasher>::from_rows(&leaf_refs)?;
        let root = tree.root();
        tx.absorb_digest("root", root);
        roots.push(*root);
        trees.push(tree);
        domain_sizes.push(n);
        evaluations_layers.push(evals_i.clone());

        // get challenge
        let beta_i: F = tx.challenge_field("fri/beta_i");
        // fold
        evals_i = fold_once(&evals_i, g, beta_i);
        // advance
        g = g.square();
        n /= 2;
    }
    let final_eval = evals_i[0];
    tx.absorb_field("fri/final_const", &final_eval);

    // query phase
    let mut queries = Vec::with_capacity(num_queries);
    for _ in 0..num_queries {
        let mut idx = tx.challenge_index("fri/query", (n0 / 2) as u64) as usize;
        let mut rounds = Vec::with_capacity(roots.len());

        for (i, tree) in trees.iter().enumerate() {
            let domain_size = domain_sizes[i];
            let half = domain_size / 2;
            let neg_idx = (idx + half) % domain_size;

            let left = evaluations_layers[i][idx];
            let right = evaluations_layers[i][neg_idx];

            let left_path = tree.open(idx)?;
            let right_path = tree.open(neg_idx)?;

            rounds.push(FriRound {
                left: Opened {
                    value: left,
                    path: left_path,
                },
                right: Opened {
                    value: right,
                    path: right_path,
                },
            });

            idx %= half;
        }
        queries.push(FriQuery { rounds })
    }

    Ok(FriProof {
        roots,
        queries,
        final_eval,
    })
}

// convert Vec<F> to slice of bytes
fn evals_to_bytes<F: PrimeField + FftField>(evals: &[F]) -> Vec<Vec<u8>> {
    let mut leaves_bytes: Vec<Vec<u8>> = Vec::with_capacity(evals.len());
    for x in evals {
        let mut buf = Vec::new();
        x.serialize_compressed(&mut buf).expect("field serialize");
        leaves_bytes.push(buf);
    }
    leaves_bytes
}

fn fold_once<F: PrimeField + FftField>(evals: &[F], g: F, beta: F) -> Vec<F> {
    let n = evals.len();
    let half = n / 2;

    let inv2 = F::from(2u64).inverse().expect("inverse");
    let ginv = g.inverse().expect("inverse");

    let mut invx = F::one();
    let mut out = Vec::with_capacity(half);
    for i in 0..half {
        let j = i + half;
        let fx = evals[i];
        let fnegx = evals[j];

        let f_even = (fx + fnegx) * inv2;
        let f_odd = (fx - fnegx) * inv2 * invx;

        out.push(f_even + beta * f_odd);

        invx = invx * ginv
    }
    out
}

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("bad init params")]
    BadProof,
    #[error("roots len != rounds")]
    RootsNEtoQueryRounds,
    #[error("domain folded to constant sooner than expected")]
    QueriesBiggerThenFolds,
    #[error("merkle authentication failed at query {query}, layer {layer}, index {index}")]
    MerkleAuthError {
        query: usize,
        layer: usize,
        index: usize,
    },
    #[error("verification failed")]
    VerificationFailed,
}

pub fn verify<F: PrimeField + FftField>(
    proof: &FriProof<F>,
    domain: GeneralEvaluationDomain<F>,
    tx: &mut Transcript,
) -> Result<(), VerificationError> {
    let n0 = domain.size();
    if n0 == 0 || proof.roots.is_empty() || proof.queries.len() == 0 {
        return Err(VerificationError::BadProof);
    }

    let num_queries = proof.queries.len();
    tx.absorb_params(n0, 1, num_queries);

    let mut betas = Vec::with_capacity(proof.roots.len());
    for root in &proof.roots {
        tx.absorb_digest("root", root);
        let beta: F = tx.challenge_field("fri/beta_i");
        betas.push(beta);
    }
    tx.absorb_field("fri/final_const", &proof.final_eval);

    for (q_i, query) in proof.queries.iter().enumerate() {
        let mut idx = tx.challenge_index("fri/query", (n0 / 2) as u64) as usize;
        let mut domain_size = n0;
        let mut g = domain.group_gen();
        let inv2 = F::from(2u64).inverse().expect("inverse");

        if query.rounds.len() != proof.roots.len() {
            return Err(VerificationError::RootsNEtoQueryRounds);
        }

        for (layer_i, round) in query.rounds.iter().enumerate() {
            let half = domain_size / 2;
            if half == 0 {
                return Err(VerificationError::QueriesBiggerThenFolds);
            }

            // index sanity checks
            if round.left.path.index != idx {
                return Err(VerificationError::MerkleAuthError {
                    query: q_i,
                    layer: layer_i,
                    index: idx,
                });
            }
            let expected_right_idx = (idx + half) % domain_size;
            if round.right.path.index != expected_right_idx {
                return Err(VerificationError::MerkleAuthError {
                    query: q_i,
                    layer: layer_i,
                    index: expected_right_idx,
                });
            }
            // verify merkle openings
            let mut left_bytes = vec![];
            round
                .left
                .value
                .serialize_compressed(&mut left_bytes)
                .unwrap();
            if !verify_row::<Blake3Hasher>(&proof.roots[layer_i], &left_bytes, &round.left.path) {
                return Err(VerificationError::MerkleAuthError {
                    query: q_i,
                    layer: layer_i,
                    index: idx,
                });
            }

            let mut right_bytes = vec![];
            round
                .right
                .value
                .serialize_compressed(&mut right_bytes)
                .unwrap();
            if !verify_row::<Blake3Hasher>(&proof.roots[layer_i], &right_bytes, &round.right.path) {
                return Err(VerificationError::MerkleAuthError {
                    query: q_i,
                    layer: layer_i,
                    index: expected_right_idx,
                });
            }

            // fold
            let left_value = round.left.value;
            let right_value = round.right.value;
            let x = g.pow([idx as u64]);

            // f_even = ( f(w) + f(-w) ) / 2
            let even = (left_value + right_value) * inv2;
            // f_odd = ( f(w) - f(-w) ) / 2x
            let odd = (left_value - right_value) * inv2 * x.inverse().unwrap();
            let y = even + betas[layer_i] * odd;

            if layer_i + 1 == query.rounds.len() {
                // terminal check against the constant
                if y != proof.final_eval {
                    return Err(VerificationError::VerificationFailed);
                }
            } else {
                // bridge check: the folded value must equal the next layer's committed value
                if y != query.rounds[layer_i + 1].left.value {
                    return Err(VerificationError::VerificationFailed);
                }
            }

            // advance
            idx %= half;
            domain_size = half;
            g = g.square();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ProofError, VerificationError, fold_once, prove_from_coefficients, verify};
    use crate::backend::Transcript;
    use ark_bn254::Fr;
    use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::{DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain};
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    // build f(x) from random coeffs of given length
    fn random_poly(deg_plus_1: usize, seed: u64) -> DensePolynomial<Fr> {
        let mut rng = StdRng::seed_from_u64(seed);
        let coeffs: Vec<Fr> = (0..deg_plus_1).map(|_| Fr::rand(&mut rng)).collect();
        DensePolynomial::from_coefficients_slice(&coeffs)
    }

    // split f(X) = g(X^2) + X h(X^2) ⇒ return (g(Y), h(Y)) as polynomials in Y
    fn even_odd_split(f: &DensePolynomial<Fr>) -> (DensePolynomial<Fr>, DensePolynomial<Fr>) {
        let coeffs = &f.coeffs;
        let mut g = Vec::new(); // even coeffs a_0, a_2, a_4 -> g_0, g_1, g_2
        let mut h = Vec::new(); // odd  coeffs a_1, a_3, a_5 -> h_0, h_1, h_2
        for (k, a) in coeffs.iter().cloned().enumerate() {
            if k % 2 == 0 {
                g.push(a);
            } else {
                h.push(a);
            }
        }
        (
            DensePolynomial::from_coefficients_vec(g),
            DensePolynomial::from_coefficients_vec(h),
        )
    }

    // evaluate polynomial p at point x using Horner
    fn eval_poly(p: &DensePolynomial<Fr>, x: Fr) -> Fr {
        p.coeffs
            .iter()
            .rev()
            .fold(Fr::zero(), |acc, &c| acc * x + c)
    }

    // pick a power-of-two N ≥ deg+1
    fn pick_domain<F: PrimeField>(n: usize) -> GeneralEvaluationDomain<F> {
        GeneralEvaluationDomain::<F>::new(n).expect("radix-2 domain")
    }
    #[test]
    fn honest_prover_verifier_ok() {
        // N = 2^15
        let n = 32768usize;
        let domain = pick_domain::<Fr>(n);
        let coeffs = random_poly(32768, 1337);

        let seed = b"fri-seed-1";
        let mut tx = Transcript::new(b"transcript", seed);
        let proof =
            prove_from_coefficients::<Fr>(&coeffs, domain, &mut tx).expect("prove should succeed");

        // verification
        let mut tx = Transcript::new(b"transcript", seed);
        verify::<Fr>(&proof, pick_domain::<Fr>(n), &mut tx).expect("verify should succeed");

        let coeffs = random_poly(16384, 2048);
        let proof =
            prove_from_coefficients::<Fr>(&coeffs, domain, &mut tx).expect("prove should succeed");
    }

    #[test]
    fn tamper_leaf_value_fails() {
        let n = 32usize;
        let domain = pick_domain::<Fr>(n);
        let coeffs = random_poly(10, 2024);

        let seed = b"fri-seed-2";
        let mut tx = Transcript::new(b"transcript", seed);
        let mut proof = prove_from_coefficients::<Fr>(&coeffs, domain, &mut tx).expect("prove ok");

        // mutate the first query's first round left value
        if let Some(q) = proof.queries.get_mut(0) {
            if let Some(r0) = q.rounds.get_mut(0) {
                r0.left.value += Fr::one();
            }
        }

        let mut tx = Transcript::new(b"transcript", seed);
        let err = verify::<Fr>(&proof, pick_domain::<Fr>(n), &mut tx).unwrap_err();
        assert!(matches!(
            err,
            VerificationError::MerkleAuthError {
                query: _,
                layer: _,
                index: _
            }
        ));
    }

    #[test]
    fn tamper_merkle_path_fails() {
        let n = 32usize;
        let domain = pick_domain::<Fr>(n);
        let coeffs = random_poly(9, 77);

        let seed = b"fri-seed-3";
        let mut tx = Transcript::new(b"transcript", seed);
        let mut proof = prove_from_coefficients::<Fr>(&coeffs, domain, &mut tx).expect("prove ok");

        // flip one byte in the first path’s first node
        if let Some(q) = proof.queries.get_mut(0) {
            if let Some(r0) = q.rounds.get_mut(0) {
                if let Some(first_node) = r0.left.path.nodes.get_mut(0) {
                    first_node[0] ^= 0x01;
                }
            }
        }

        let mut tx = Transcript::new(b"transcript", seed);
        let err = verify::<Fr>(&proof, pick_domain::<Fr>(n), &mut tx).unwrap_err();
        assert!(matches!(
            err,
            VerificationError::MerkleAuthError {
                query: _,
                layer: _,
                index: _
            }
        ));
    }

    #[test]
    fn tamper_root_fails() {
        let n = 32usize;
        let domain = pick_domain::<Fr>(n);
        let coeffs = random_poly(7, 55);

        let seed = b"fri-seed-4";
        let mut tx = Transcript::new(b"transcript", seed);
        let mut proof = prove_from_coefficients::<Fr>(&coeffs, domain, &mut tx).expect("prove ok");

        // Corrupt the first root
        if let Some(root0) = proof.roots.get_mut(0) {
            root0[0] ^= 0x42;
        }

        let mut tx = Transcript::new(b"transcript", seed);
        let err = verify::<Fr>(&proof, pick_domain::<Fr>(n), &mut tx).unwrap_err();
        assert!(matches!(
            err,
            VerificationError::MerkleAuthError {
                query: _,
                layer: _,
                index: _
            }
        ));
    }

    #[test]
    fn degree_exceeds_domain_errors() {
        let n = 16usize;
        let domain = pick_domain::<Fr>(n);

        let coeffs = random_poly(n + 1, 9999);
        let seed = b"fri-seed-5";
        println!("{}", coeffs.len());

        let mut tx = Transcript::new(b"transcript", seed);
        let err = prove_from_coefficients::<Fr>(&coeffs, domain, &mut tx).unwrap_err();
        assert!(matches!(err, ProofError::DegreeExceedsDomain));
    }

    #[test]
    fn determinism_same_seed_same_proof_shape() {
        let n = 64usize;
        let domain = pick_domain::<Fr>(n);
        let coeffs = random_poly(11, 4242);
        let seed = b"fri-seed-6";

        let mut tx1 = Transcript::new(b"transcript", seed);
        let mut tx2 = Transcript::new(b"transcript", seed);
        let p1 = prove_from_coefficients::<Fr>(&coeffs, domain, &mut tx1).expect("prove ok");
        let p2 = prove_from_coefficients::<Fr>(&coeffs, domain, &mut tx2).expect("prove ok");

        assert_eq!(p1.roots.len(), p2.roots.len());
        assert_eq!(p1.queries.len(), p2.queries.len());

        assert_eq!(p1.final_eval, p2.final_eval);
    }

    #[test]
    fn fold_matches_even_odd_combo_small() {
        let n = 16usize;
        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();

        let f = random_poly(10, 1337);
        // compute evals on D0 directly (not FFT), to be agnostic
        let g = domain.group_gen();
        let mut x = domain.element(0);
        let mut evals = Vec::with_capacity(n);
        for i in 0..n {
            if i > 0 {
                x *= g;
            }
            evals.push(eval_poly(&f, x));
        }

        // random beta
        let mut rng = StdRng::seed_from_u64(42);
        let beta = Fr::rand(&mut rng);

        let folded = fold_once(&evals, g, beta);

        // expected: u(Y) = g(Y) + beta * h(Y), evaluated at Y = x_j^2
        let (g_poly, h_poly) = even_odd_split(&f);
        let u_poly = DensePolynomial::from_coefficients_vec({
            // u = g + beta*h
            let (mut u, m) = (g_poly.clone(), h_poly.clone());
            let mut coeffs = u.coeffs;
            if coeffs.len() < m.coeffs.len() {
                coeffs.resize(m.coeffs.len(), Fr::zero());
            }
            for (k, c) in m.coeffs.iter().enumerate() {
                coeffs[k] += *c * beta;
            }
            coeffs
        });

        let half = n / 2;
        let mut xj = domain.element(0);
        let mut expected = Vec::with_capacity(half);
        for j in 0..half {
            if j > 0 {
                xj *= g;
            }
            let y = xj.square();
            expected.push(eval_poly(&u_poly, y));
        }

        assert_eq!(folded.len(), half);
        assert_eq!(expected.len(), half);
        for (a, b) in folded.iter().zip(expected.iter()) {
            assert_eq!(a, b, "mismatch at some index");
        }
    }

    #[test]
    fn fold_beta_zero_is_even_average() {
        let n = 8usize;
        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();

        // build any polynomial and eval on grid
        let f = random_poly(6, 7);
        let g = domain.group_gen();
        let mut x = domain.element(0);
        let mut evals = Vec::with_capacity(n);
        for i in 0..n {
            if i > 0 {
                x *= g;
            }
            evals.push(eval_poly(&f, x));
        }

        // beta = 0 ⇒ f* = (f(x)+f(-x))/2
        let beta = Fr::zero();
        let folded = fold_once(&evals, g, beta);

        let inv2 = Fr::from(2u64).inverse().unwrap();
        let mut expected = Vec::with_capacity(n / 2);
        for i in 0..(n / 2) {
            expected.push((evals[i] + evals[i + n / 2]) * inv2);
        }

        assert_eq!(folded, expected);
    }

    #[test]
    fn pairing_invariant_minus_x_is_shift_by_half() {
        let n = 32usize;
        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
        let g = domain.group_gen();
        let mut x = domain.element(0);

        // check that x_{i + n/2} = -x_i
        let half = n / 2;
        let mut xs: Vec<Fr> = Vec::with_capacity(n);
        for i in 0..n {
            if i > 0 {
                x *= g;
            }
            xs.push(x);
        }
        for i in 0..half {
            assert_eq!(xs[i + half], -xs[i]);
        }
    }

    #[test]
    fn tamper_path_index_fails() {
        let n = 32usize;
        let domain = pick_domain::<Fr>(n);
        let coeffs = random_poly(10, 1);
        let seed = b"fri-seed-x";

        let mut tx = Transcript::new(b"transcript", seed);
        let mut proof = prove_from_coefficients::<Fr>(&coeffs, domain, &mut tx).unwrap();

        proof.queries[0].rounds[0].left.path.index ^= 1;

        let mut txv = Transcript::new(b"transcript", seed);
        assert!(verify::<Fr>(&proof, pick_domain::<Fr>(n), &mut txv).is_err());
    }

    #[test]
    fn different_transcript_label_fails() {
        let n = 32usize;
        let domain = pick_domain::<Fr>(n);
        let coeffs = random_poly(10, 1);
        let seed = b"fri-seed";

        let mut txp = Transcript::new(b"transcript", seed);
        let proof = prove_from_coefficients::<Fr>(&coeffs, domain, &mut txp).unwrap();

        let mut txv = Transcript::new(b"transcript-DIFFERENT", seed);
        assert!(verify::<Fr>(&proof, pick_domain::<Fr>(n), &mut txv).is_err());
    }
}
