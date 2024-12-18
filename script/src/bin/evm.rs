//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can have an
//! EVM-Compatible proof generated which can be verified on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system groth16
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system plonk
//! ```

use clap::{Parser, ValueEnum};
use rand::Rng;
use rs_merkle::{Hasher, MerkleTree};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    include_elf, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};
use std::path::PathBuf;
/// The ELF file for the Merkle Tree program
pub const MERKLE_ELF: &[u8] = include_elf!("goldinals-merkle-tree");

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

/// The arguments for the EVM command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct EVMArgs {
    #[clap(long, default_value = "40000000")]
    total_leaves: usize,
    #[clap(long, value_enum, default_value = "groth16")]
    system: ProofSystem,
}

/// Enum representing the available proof systems
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProofSystem {
    Plonk,
    Groth16,
}

/// A fixture that can be used to test the verification of SP1 zkVM proofs inside Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1MerkleProofFixture {
    root: String,
    leaf: String,
    is_valid: bool,
    vkey: String,
    public_values: String,
    proof: String,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = EVMArgs::parse();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(MERKLE_ELF);

    let leaves: Vec<[u8; 32]> = (0..args.total_leaves)
        .map(|i| {
            let mut hasher = Sha256::new();
            hasher.update(i.to_le_bytes());
            hasher.finalize().into()
        })
        .collect();

    let tree = MerkleTree::<Sha256Hasher>::from_leaves(&leaves);
    let root = tree.root().expect("Failed to get root");
    let leaf_index = rand::thread_rng().gen_range(0..args.total_leaves);
    let leaf = leaves[leaf_index];
    let proof = tree.proof(&[leaf_index]);
    let proof_bytes = proof.to_bytes();

    // Setup the inputs
    let mut stdin = SP1Stdin::new();
    stdin.write(&root);
    stdin.write(&leaf);
    stdin.write(&proof_bytes);
    stdin.write(&leaf_index);
    stdin.write(&args.total_leaves);

    println!("Total Leaves: {}", args.total_leaves);
    println!("Proof System: {:?}", args.system);

    // Generate the proof based on the selected proof system.
    let proof = match args.system {
        ProofSystem::Plonk => client.prove(&pk, stdin).plonk().run(),
        ProofSystem::Groth16 => client.prove(&pk, stdin).groth16().run(),
    }
    .expect("failed to generate proof");

    create_proof_fixture(&proof, &vk, args.system);
}

/// Create a fixture for the given proof.
fn create_proof_fixture(
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    system: ProofSystem,
) {
    let output = proof.public_values.as_slice();
    let root = &output[0..32];
    let leaf = &output[32..64];
    let is_valid = output[64] != 0;

    // Create the testing fixture
    let fixture = SP1MerkleProofFixture {
        root: format!("0x{}", hex::encode(root)),
        leaf: format!("0x{}", hex::encode(leaf)),
        is_valid,
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(output)),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };

    // Save the fixture
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    std::fs::write(
        fixture_path.join(format!("{:?}-fixture.json", system).to_lowercase()),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");

    println!("Merkle Root: {}", fixture.root);
    println!("Leaf: {}", fixture.leaf);
    println!("Is Valid: {}", fixture.is_valid);
    println!("Verification Key: {}", fixture.vkey);
    println!("Public Values: {}", fixture.public_values);
    println!("Proof Bytes: {}", fixture.proof);
}
