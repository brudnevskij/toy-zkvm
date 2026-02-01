use std::marker::PhantomData;
use thiserror::Error;

pub type Digest = [u8; 32];

#[derive(Debug, Clone)]
pub struct AuthPath {
    pub nodes: Vec<Digest>,
    pub index: usize,
}

#[derive(Error, Debug)]
pub enum MerkleError {
    #[error("empty input")]
    Empty,
    #[error("index out of range")]
    IndexOutOfRange,
}

pub trait Hasher {
    fn hash_leaf(data: &[u8]) -> Digest;
    fn hash_node(left_node: &Digest, right_node: &Digest) -> Digest;
}

#[derive(Debug)]
pub struct Blake3Hasher;

impl Hasher for Blake3Hasher {
    fn hash_leaf(data: &[u8]) -> Digest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[0x00]);
        hasher.update(data);
        *hasher.finalize().as_bytes()
    }

    fn hash_node(left: &Digest, right: &Digest) -> Digest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[0x01]);
        hasher.update(left);
        hasher.update(right);
        *hasher.finalize().as_bytes()
    }
}

#[derive(Debug)]
pub struct MerkleTree<H: Hasher = Blake3Hasher> {
    nodes: Vec<Digest>,
    leaf_count: usize,
    leaf_cap: usize,
    _h: PhantomData<H>,
}

impl<H: Hasher> MerkleTree<H> {
    pub fn from_rows(rows: &[&[u8]]) -> Result<Self, MerkleError> {
        if rows.is_empty() {
            return Err(MerkleError::Empty);
        }
        let leaves: Vec<Digest> = rows.iter().map(|x| H::hash_leaf(x)).collect();
        Self::from_leaf_digests(&leaves)
    }

    pub fn from_leaf_digests(leaves: &[Digest]) -> Result<Self, MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::Empty);
        }
        let leaf_count = leaves.len();
        let cap = next_pow2(leaf_count);

        // since number of leaves is power of 2, cap also includes, next floors which are also powers of two
        // making the sum = 2^leaf_count + (2^leaf_count - 1) + 1 (last is unused 0th index) = 2 * 2^leaf_count
        let mut nodes = vec![[0u8; 32]; cap * 2];

        for (i, leaf) in leaves.iter().enumerate() {
            nodes[cap + i] = *leaf;
        }

        for i in leaf_count..cap {
            nodes[cap + i] = nodes[cap + leaf_count - 1];
        }

        for i in (1..cap).rev() {
            let l = nodes[2 * i];
            let r = nodes[2 * i + 1];
            nodes[i] = H::hash_node(&l, &r);
        }

        Ok(Self {
            nodes,
            leaf_count,
            leaf_cap: cap,
            _h: PhantomData,
        })
    }

    // [0, 1..powe^2-1]
    pub fn open(&self, index: usize) -> Result<AuthPath, MerkleError> {
        if index >= self.leaf_count {
            return Err(MerkleError::IndexOutOfRange);
        }

        let mut pos = self.leaf_cap + index;
        let mut nodes = Vec::with_capacity(self.height());
        while pos > 1 {
            let sib = if pos & 1 == 0 { pos + 1 } else { pos - 1 };
            nodes.push(self.nodes[sib]);
            pos >>= 1;
        }
        Ok(AuthPath { nodes, index })
    }

    pub fn root(&self) -> &Digest {
        &self.nodes[1]
    }

    /// Tree height in levels from leaves to root (log2(cap)).
    fn height(&self) -> usize {
        // For cap == 1, height == 0 (single leaf, path is empty).
        usize::BITS as usize - (self.leaf_cap.leading_zeros() as usize) - 1
    }
}

pub fn verify_leaf<H: Hasher>(root: &Digest, leaf: &Digest, auth_path: &AuthPath) -> bool {
    let mut acc = *leaf;
    let mut idx = auth_path.index;

    for sib in auth_path.nodes.iter() {
        if idx & 1 == 0 {
            acc = H::hash_node(&acc, sib);
        } else {
            acc = H::hash_node(sib, &acc);
        }
        idx >>= 1;
    }
    root == &acc
}

pub fn verify_row<H: Hasher>(root: &Digest, row: &[u8], auth_path: &AuthPath) -> bool {
    let leaf = H::hash_leaf(row);
    verify_leaf::<H>(root, &leaf, auth_path)
}

fn next_pow2(n: usize) -> usize {
    // treat n >= 1
    let mut x = n - 1;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    if usize::BITS > 32 {
        x |= x >> 32;
    }
    x + 1
}

#[cfg(test)]
mod tests {
    use crate::backend::merkle::{Blake3Hasher, MerkleError, MerkleTree, verify_row};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn rand_rows(n: usize, max_len: usize, seed: u64) -> Vec<Vec<u8>> {
        let mut rng = StdRng::seed_from_u64(seed);
        (0..n)
            .map(|_| {
                let len = rng.random_range(1..=max_len);
                (0..len).map(|_| rng.random::<u8>()).collect::<Vec<u8>>()
            })
            .collect()
    }

    #[test]
    fn determinism_same_rows_same_root() {
        let rows = rand_rows(7, 64, 42);
        let refs: Vec<&[u8]> = rows.iter().map(|v| v.as_slice()).collect();
        let t1 = MerkleTree::<Blake3Hasher>::from_rows(&refs).unwrap();
        let t2 = MerkleTree::<Blake3Hasher>::from_rows(&refs).unwrap();
        assert_eq!(t1.root(), t2.root());
        assert_eq!(t1.leaf_count, 7);
        assert_eq!(t1.leaf_cap, 8);
    }

    #[test]
    fn verify_all_leaves() {
        let rows = rand_rows(7, 64, 42);
        let refs: Vec<&[u8]> = rows.iter().map(|v| v.as_slice()).collect();
        let tree = MerkleTree::<Blake3Hasher>::from_rows(&refs).unwrap();
        for (i, row) in rows.iter().enumerate() {
            let auth = tree.open(i).unwrap();
            assert!(verify_row::<Blake3Hasher>(tree.root(), row, &auth));
        }
    }

    #[test]
    fn tamper_leaf_fails() {
        let mut rows = rand_rows(5, 40, 9);
        let refs: Vec<&[u8]> = rows.iter().map(|v| v.as_slice()).collect();
        let t = MerkleTree::<Blake3Hasher>::from_rows(&refs).unwrap();
        let i = 3usize;
        let path = t.open(i).unwrap();

        // Flip a bit in the row
        rows[i][0] ^= 0b0000_0001;
        assert!(!verify_row::<Blake3Hasher>(t.root(), &rows[i], &path));
    }

    #[test]
    fn tamper_path_fails() {
        let rows = rand_rows(6, 32, 11);
        let refs: Vec<&[u8]> = rows.iter().map(|v| v.as_slice()).collect();
        let t = MerkleTree::<Blake3Hasher>::from_rows(&refs).unwrap();
        let i = 4usize;
        let mut path = t.open(i).unwrap();
        // corrupt one auth node
        path.nodes[0][0] ^= 0xFF;
        assert!(!verify_row::<Blake3Hasher>(t.root(), &rows[i], &path));
    }

    #[test]
    fn single_leaf_has_empty_path() {
        let rows = rand_rows(1, 16, 1);
        let refs: Vec<&[u8]> = rows.iter().map(|v| v.as_slice()).collect();
        let t = MerkleTree::<Blake3Hasher>::from_rows(&refs).unwrap();
        let path = t.open(0).unwrap();
        assert!(path.nodes.is_empty());
        assert!(verify_row::<Blake3Hasher>(t.root(), &rows[0], &path));
    }

    #[test]
    fn index_out_of_range() {
        let rows = rand_rows(3, 16, 3);
        let refs: Vec<&[u8]> = rows.iter().map(|v| v.as_slice()).collect();
        let t = MerkleTree::<Blake3Hasher>::from_rows(&refs).unwrap();
        assert!(matches!(t.open(3), Err(MerkleError::IndexOutOfRange)));
    }

    #[test]
    fn empty_rejected() {
        let empty: [&[u8]; 0] = [];
        let err = MerkleTree::<Blake3Hasher>::from_rows(&empty).unwrap_err();
        assert!(matches!(err, MerkleError::Empty));
    }

    #[test]
    fn wrong_index_fails() {
        let rows = rand_rows(8, 32, 99);
        let refs: Vec<&[u8]> = rows.iter().map(|v| v.as_slice()).collect();
        let t = MerkleTree::<Blake3Hasher>::from_rows(&refs).unwrap();

        let mut path = t.open(2).unwrap();
        path.index = 3; // lie about position
        assert!(!verify_row::<Blake3Hasher>(t.root(), &rows[2], &path));
    }
}
