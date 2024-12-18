#![no_main]
sp1_zkvm::entrypoint!(main);

use rs_merkle::{Hasher, MerkleProof};

#[derive(Clone)]
struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

pub fn main() {
    let root: [u8; 32] = sp1_zkvm::io::read();
    let leaf: [u8; 32] = sp1_zkvm::io::read();
    let proof_bytes: Vec<u8> = sp1_zkvm::io::read();
    let leaf_index: usize = sp1_zkvm::io::read();
    let total_leaves: usize = sp1_zkvm::io::read();

    let proof =
        MerkleProof::<Sha256Hasher>::from_bytes(&proof_bytes).expect("Failed to parse proof");

    let is_valid = proof.verify(root, &[leaf_index], &[leaf], total_leaves);

    let mut output = Vec::new();
    output.extend_from_slice(&root);
    output.extend_from_slice(&leaf);
    output.push(is_valid as u8);

    sp1_zkvm::io::commit_slice(&output);
}
