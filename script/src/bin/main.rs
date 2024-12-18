//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use clap::Parser;
use rand::Rng;
use rs_merkle::{Hasher, MerkleTree};
use sha2::{Digest, Sha256};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

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

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    #[clap(long, default_value = "40000000")]
    total_leaves: usize,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the inputs
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

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(MERKLE_ELF, stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output
        let root = &output.as_slice()[0..32];
        let leaf = &output.as_slice()[32..64];
        let is_valid = output.as_slice()[64] != 0;

        println!("Merkle Root: 0x{}", hex::encode(root));
        println!("Leaf: 0x{}", hex::encode(leaf));
        println!("Is Valid: {}", is_valid);
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(MERKLE_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
