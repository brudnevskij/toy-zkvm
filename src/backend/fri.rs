use std::usize;

use crate::backend::{
    AuthPath, Blake3Hasher, Digest, MerkleError, MerkleTree, Transcript, verify_row,
};
use ark_ff::{FftField, Field, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::CanonicalSerialize;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct FriProof<F: Field> {
    // Merkle roots per FRI step
    pub roots: Vec<Digest>,
    // Queries for each step of FRI, one per index queried
    pub queries: Vec<FriQuery<F>>,
    pub final_poly: Vec<F>,
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

pub struct FriOptions<F: PrimeField> {
    pub max_degree: usize,
    pub max_remainder_degree: usize,
    pub shift: F,
}

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("polynomial degree is bigger then domain")]
    DegreeExceedsDomain,
    #[error("unexpected evaluations length got: {got}, expected: {expected}")]
    BadEvaluationsLength { got: usize, expected: usize },
    #[error("empty evaluations")]
    EmptyEvaluations,

    #[error(transparent)]
    Merkle(#[from] MerkleError),
}

pub fn prove_from_coefficients<F: PrimeField + FftField>(
    coeffs: &[F],
    domain: &Radix2EvaluationDomain<F>,
    options: &FriOptions<F>,
    tx: &mut Transcript,
) -> Result<FriProof<F>, ProofError> {
    let n0 = domain.size();
    if coeffs.is_empty() || coeffs.len() > n0 {
        return Err(ProofError::DegreeExceedsDomain);
    }

    let mut evals = vec![F::zero(); n0];
    evals[..coeffs.len()].copy_from_slice(coeffs);
    domain.fft_in_place(&mut evals);

    prove(&evals, domain, options, tx)
}

pub fn prove<F: PrimeField + FftField>(
    evals: &[F],
    initial_domain: &Radix2EvaluationDomain<F>,
    options: &FriOptions<F>,
    tx: &mut Transcript,
) -> Result<FriProof<F>, ProofError> {
    let initial_domain_size = initial_domain.size();
    // TODO: handle as errors
    assert!(initial_domain_size > 0, "empty domain");
    assert!(
        options.max_remainder_degree > 0,
        "remainder degree must be greater than 0"
    );
    assert!(
        options.max_remainder_degree < options.max_degree,
        " need r < d"
    );
    assert!(
        options.max_degree < initial_domain_size,
        "need d < N (rate < 1)"
    );
    if evals.is_empty() {
        return Err(ProofError::EmptyEvaluations);
    }
    if evals.len() != initial_domain_size {
        return Err(ProofError::BadEvaluationsLength {
            got: evals.len(),
            expected: initial_domain_size,
        });
    }

    // TODO: make num of queries scalable, move to options
    let num_queries = 1;
    tx.absorb_params(initial_domain_size, 1, num_queries);
    tx.absorb_bytes("fri/max_degree", &options.max_degree.to_le_bytes());
    tx.absorb_bytes(
        "fri/max_remainder_degree",
        &options.max_remainder_degree.to_le_bytes(),
    );

    let mut evaluations_layers = vec![];
    let mut roots = vec![];
    let mut trees = vec![];
    let mut g = initial_domain.group_gen();
    let mut shift = options.shift;
    let mut evals_i = evals.to_vec();
    let mut current_max_degree = options.max_degree;

    while current_max_degree > options.max_remainder_degree {
        let tree = commit_evals(&evals_i)?;
        let root = tree.root();
        tx.absorb_digest("root", root);

        roots.push(*root);
        trees.push(tree);
        evaluations_layers.push(evals_i);

        // get challenge
        let beta_i: F = tx.challenge_field("fri/beta_i");
        // fold
        let last = evaluations_layers.last().unwrap();
        evals_i = fold_once(last, g, beta_i, options.shift);
        // advance
        g = g.square();
        shift = shift.square();

        // halving upper bound
        current_max_degree = (current_max_degree + 1) / 2;
    }

    // interpolating final poly
    let final_domain_size = initial_domain_size >> roots.len(); // N / 2^n_folds
    assert_eq!(final_domain_size, evals_i.len());
    assert!(final_domain_size > options.max_remainder_degree);

    // TODO: handle error
    let final_domain = Radix2EvaluationDomain::new(final_domain_size).unwrap();
    assert_eq!(g, final_domain.group_gen());
    let mut final_poly = final_domain.ifft(&evals_i);
    trim_trailing_zeroes(&mut final_poly);
    assert!(
        final_poly.len() <= options.max_remainder_degree,
        "final poly degree: {0} must be less than max remainder degree: {1} \n final poly: {2:?}",
        final_poly.len(),
        options.max_remainder_degree,
        final_poly
    );

    let final_tree = commit_evals(&final_poly)?;
    tx.absorb_digest("fri/final_poly", final_tree.root());

    // query phase
    let mut queries = Vec::with_capacity(num_queries);
    for _ in 0..num_queries {
        let half = initial_domain_size >> 1;
        let idx = tx.challenge_index("fri/query", half as u64) as usize;
        let q = produce_query(idx, initial_domain_size, &evaluations_layers, &trees)?;
        queries.push(q);
    }

    Ok(FriProof {
        roots,
        queries,
        final_poly,
    })
}

fn produce_query<F: PrimeField>(
    initial_idx: usize,
    initial_domain_size: usize,
    evaluations: &[Vec<F>],
    trees: &[MerkleTree<Blake3Hasher>],
) -> Result<FriQuery<F>, MerkleError> {
    let mut rounds = Vec::with_capacity(trees.len());
    let mut idx = initial_idx;

    let mut domain_size = initial_domain_size;
    for (i, tree) in trees.iter().enumerate() {
        // negative index might be in the first half of the evals
        let half = domain_size >> 1;
        let neg_idx = (idx + half) % domain_size;
        let left_path = tree.open(idx)?;
        let right_path = tree.open(neg_idx)?;

        rounds.push(FriRound {
            left: Opened {
                value: evaluations[i][idx],
                path: left_path,
            },
            right: Opened {
                value: evaluations[i][neg_idx],
                path: right_path,
            },
        });

        domain_size >>= 1;
        idx &= half - 1;
    }

    Ok(FriQuery { rounds })
}

// convert Vec<F> to slice of bytes, and cpmmit to a tree
pub fn commit_evals<F: CanonicalSerialize>(
    evals: &[F],
) -> Result<MerkleTree<Blake3Hasher>, MerkleError> {
    let leaves_bytes: Vec<Vec<u8>> = evals
        .iter()
        .map(|x| {
            let mut buf = Vec::new();
            x.serialize_compressed(&mut buf).expect("field serialize");
            buf
        })
        .collect();

    let leaf_refs: Vec<&[u8]> = leaves_bytes.iter().map(|v| v.as_slice()).collect();

    let tree = MerkleTree::<Blake3Hasher>::from_rows(&leaf_refs)?;
    Ok(tree)
}

fn fold_once<F: PrimeField + FftField>(evals: &[F], g: F, beta: F, shift: F) -> Vec<F> {
    let n = evals.len();
    let half = n / 2;

    let inv2 = F::from(2u64).inverse().expect("inverse");
    let ginv = g.inverse().expect("inverse");

    // 1/x where x = shift g^i => invx = shift^{-1} * g^{-1}
    // starting with shift because x0 = 1
    let mut invx = shift.inverse().expect("shift inverse");
    let mut out = Vec::with_capacity(half);

    for i in 0..half {
        let j = i + half;

        // f(x)
        let fx = evals[i];
        // f(-x)
        let fnegx = evals[j];

        let f_even = (fx + fnegx) * inv2;
        let f_odd = (fx - fnegx) * inv2 * invx;

        out.push(f_even + beta * f_odd);

        invx = invx * ginv
    }
    out
}

fn trim_trailing_zeroes<F: PrimeField>(v: &mut Vec<F>) {
    while v.len() > 1 && v.last() == Some(&F::zero()) {
        v.pop();
    }
}

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("bad init params")]
    BadProof,
    #[error("final polynomial degree: {got} exceeds max remainder degree: {expected}")]
    FinalPolynomialDegreeExceedMaxRemainderDegree { got: usize, expected: usize },
    #[error(
        "final polynomial degree: {got} exceeds max claimed degree afetr {folds} folds: {expected}"
    )]
    FinalPolynomialDegreeExceedsClaimedDegreeAfterFolds {
        got: usize,
        expected: usize,
        folds: usize,
    },
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
    domain: &Radix2EvaluationDomain<F>,
    options: &FriOptions<F>,
    tx: &mut Transcript,
) -> Result<(), VerificationError> {
    let n0 = domain.size();
    if n0 == 0 || proof.roots.is_empty() || proof.queries.len() == 0 {
        return Err(VerificationError::BadProof);
    }

    let num_queries = proof.queries.len();
    tx.absorb_params(n0, 1, num_queries);
    tx.absorb_bytes("fri/max_degree", &options.max_degree.to_le_bytes());
    tx.absorb_bytes(
        "fri/max_remainder_degree",
        &options.max_remainder_degree.to_le_bytes(),
    );
    let inv2 = F::from(2u64).inverse().expect("inverse");
    let mut betas = Vec::with_capacity(proof.roots.len());
    for root in &proof.roots {
        tx.absorb_digest("root", root);
        let beta: F = tx.challenge_field("fri/beta_i");
        betas.push(beta);
    }

    // finall poly degree assertions
    let mut final_poly = proof.final_poly.clone();
    trim_trailing_zeroes(&mut final_poly);

    if final_poly.is_empty() {
        return Err(VerificationError::BadProof);
    }

    let deg = final_poly.len() - 1;

    if deg > options.max_remainder_degree {
        return Err(
            VerificationError::FinalPolynomialDegreeExceedMaxRemainderDegree {
                got: deg,
                expected: options.max_remainder_degree,
            },
        );
    }

    let folded_degree = degree_after_folds(options.max_degree, proof.roots.len());
    if deg > folded_degree {
        return Err(
            VerificationError::FinalPolynomialDegreeExceedsClaimedDegreeAfterFolds {
                got: deg,
                expected: folded_degree,
                folds: proof.roots.len(),
            },
        );
    }

    // TODO: handle error
    let final_tree = commit_evals(&final_poly).unwrap();
    tx.absorb_digest("fri/final_poly", &final_tree.root());
    let mut g = domain.group_gen();

    let final_domain_size = n0 >> proof.roots.len(); // n0 / 2^k
    if final_domain_size < options.max_remainder_degree + 1 {
        return Err(VerificationError::BadProof);
    }

    let final_domain =
        Radix2EvaluationDomain::<F>::new(final_domain_size).ok_or(VerificationError::BadProof)?;
    let final_evals = final_domain.fft(&final_poly);

    for (q_i, query) in proof.queries.iter().enumerate() {
        let mut idx = tx.challenge_index("fri/query", (n0 / 2) as u64) as usize;
        let mut domain_size = n0;
        g = domain.group_gen();

        if query.rounds.len() != proof.roots.len() {
            return Err(VerificationError::RootsNEtoQueryRounds);
        }
        let rounds = &query.rounds;
        for (layer_i, round) in rounds.iter().enumerate() {
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
            let x = options.shift * g.pow([idx as u64]);
            let y = fold_evaluation_pair(
                round.left.value,
                round.right.value,
                x.inverse().unwrap(),
                betas[layer_i],
                inv2,
            );

            if layer_i + 1 < query.rounds.len() {
                if y != query.rounds[layer_i + 1].left.value {
                    return Err(VerificationError::VerificationFailed);
                }
            } else if y != final_evals[idx % half] {
                return Err(VerificationError::VerificationFailed);
            }
            // advance
            idx %= half;
            domain_size = half;
            g = g.square();
        }
    }
    Ok(())
}

fn fold_evaluation_pair<F: Field>(left_value: F, right_value: F, x_inv: F, beta: F, inv2: F) -> F {
    // f_even = ( f(w) + f(-w) ) / 2
    let even = (left_value + right_value) * inv2;
    // f_odd = ( f(w) - f(-w) ) / 2x
    let odd = (left_value - right_value) * inv2 * x_inv;
    even + beta * odd
}

fn degree_after_folds(max_degree: usize, folds: usize) -> usize {
    let pow2 = 1 << folds;
    let num = max_degree + pow2 - 1;

    num / pow2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::Transcript,
        test_utils::{pick_coset_shift, pick_domain},
    };
    use ark_bn254::Fr;
    use ark_ff::{One, UniformRand, Zero};
    use ark_poly::DenseUVPolynomial;
    use ark_poly::univariate::DensePolynomial;
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    // build f(x) from random coeffs of given length
    fn random_poly(deggree: usize, seed: u64) -> DensePolynomial<Fr> {
        let mut rng = StdRng::seed_from_u64(seed);
        let coeffs: Vec<Fr> = (0..=deggree).map(|_| Fr::rand(&mut rng)).collect();
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

    fn make_honest_proof() -> (FriProof<Fr>, Radix2EvaluationDomain<Fr>, FriOptions<Fr>) {
        // N = 2^15
        let n = 32768usize;

        let domain = pick_domain::<Fr>(n);
        let coeffs = random_poly(1533, 1337);

        let seed = b"fri-seed-1";
        let mut tx = Transcript::new(b"transcript", seed);

        let options = FriOptions {
            max_degree: 1533,
            max_remainder_degree: 3,
            shift: Fr::one(),
        };

        let proof = prove_from_coefficients::<Fr>(&coeffs, &domain, &options, &mut tx)
            .expect("prove should succeed");

        (proof, domain, options)
    }

    #[test]
    fn honest_prover_verifier_ok() {
        // N = 2^15
        let n = 32768usize;
        let domain = pick_domain::<Fr>(n);
        let coeffs = random_poly(1533, 1337);

        let seed = b"fri-seed-1";
        let mut tx = Transcript::new(b"transcript", seed);
        let options = FriOptions {
            max_degree: 1533,
            max_remainder_degree: 1,
            shift: Fr::one(),
        };
        let proof = prove_from_coefficients::<Fr>(&coeffs, &domain, &options, &mut tx)
            .expect("prove should succeed");

        // verification
        let mut tx = Transcript::new(b"transcript", seed);
        verify::<Fr>(&proof, &domain, &options, &mut tx).expect("verify should succeed");
    }

    #[test]
    fn honest_prover_shifted_cosset_verifier_ok() {
        // N = 2^15
        let n = 32768usize;
        let domain = pick_domain::<Fr>(n);
        let coeffs = random_poly(1533, 1337);
        let shift = pick_coset_shift(n);

        let seed = b"fri-seed-1";
        let mut tx = Transcript::new(b"transcript", seed);
        let options = FriOptions {
            max_degree: 1533,
            max_remainder_degree: 1,
            shift,
        };
        let proof = prove_from_coefficients::<Fr>(&coeffs, &domain, &options, &mut tx)
            .expect("prove should succeed");

        // verification
        let mut tx = Transcript::new(b"transcript", seed);
        verify::<Fr>(&proof, &domain, &options, &mut tx).expect("verify should succeed");
    }

    #[test]
    fn reject_wrong_left_index() {
        let (mut proof, domain, options) = make_honest_proof(); // your helper
        proof.queries[0].rounds[0].left.path.index ^= 1;

        let seed = b"fri-seed-1";
        let mut tx = Transcript::new(b"transcript", seed);
        let res = verify(&proof, &domain, &options, &mut tx);
        assert!(res.is_err());
    }

    #[test]
    fn reject_wrong_next_round_value() {
        let (mut proof, domain, options) = make_honest_proof();
        // mutate a “next layer” claimed folded value
        proof.queries[0].rounds[1].left.value += Fr::one();

        let seed = b"fri-seed-1";
        let mut tx = Transcript::new(b"transcript", seed);
        let res = verify(&proof, &domain, &options, &mut tx);
        assert!(matches!(res, Err(VerificationError::VerificationFailed)));
    }

    #[test]
    fn reject_wrong_final_poly() {
        let (mut proof, domain, options) = make_honest_proof();
        proof.final_poly[0] += Fr::one();
        let seed = b"fri-seed-1";
        let mut tx = Transcript::new(b"transcript", seed);

        let res = verify(&proof, &domain, &options, &mut tx);
        assert!(matches!(
            res,
            Err(VerificationError::MerkleAuthError { .. })
        ));
    }

    #[test]
    fn higher_degree_reject() {
        // N = 2^15
        let n = 32768usize;
        let domain = pick_domain::<Fr>(n);
        let coeffs = random_poly(1533, 1337);

        let seed = b"fri-seed-1";
        let mut tx = Transcript::new(b"transcript", seed);
        let options = FriOptions {
            max_degree: 1000,
            max_remainder_degree: 100,
            shift: Fr::one(),
        };
        let proof = prove_from_coefficients::<Fr>(&coeffs, &domain, &options, &mut tx)
            .expect("should succeed");

        let mut tx = Transcript::new(b"transcript", seed);
        let res = verify(&proof, &domain, &options, &mut tx);
        assert!(matches!(
            res,
            Err(VerificationError::FinalPolynomialDegreeExceedsClaimedDegreeAfterFolds { .. })
        ));
    }
}
