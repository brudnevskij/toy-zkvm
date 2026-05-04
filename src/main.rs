use ark_bn254::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::{Parser, Subcommand};
use std::{fs, path::PathBuf};
use toy_zkvm::{
    backend::Transcript,
    run_program_to_trace, setup_public_params,
    vm::VmAir,
    zkvm::{ZkvmProof, ZkvmPublicParameters, prove, verify},
};

#[derive(Debug, Parser)]
#[command(name = "toy-zkvm")]
#[command(about = "A small STARK-style zkVM CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Prove {
        #[arg(long)]
        src: PathBuf,

        #[arg(long, default_value = "./proof.bin")]
        proof: PathBuf,

        #[arg(long, default_value = "public_params.bin")]
        params: PathBuf,
    },
    Verify {
        #[arg(long)]
        proof: PathBuf,

        #[arg(long, default_value = "public_params.bin")]
        params: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Prove {
            src,
            proof: proof_path,
            params: params_path,
        } => {
            println!("Proving source:{}", src.display());
            println!("Writing proof to: {}", proof_path.display());

            let src_str = fs::read_to_string(src)?;

            let trace = run_program_to_trace(&src_str, 256, 256);
            let air = VmAir::<Fr>::default();

            let public_params = setup_public_params(trace.n());

            let mut tx = Transcript::new(b"transcript", b"toy_zkvm_cli");

            let proof = prove(&trace, &air, &mut tx, &public_params)?;

            let mut proof_bytes = Vec::new();
            proof.serialize_compressed(&mut proof_bytes)?;
            fs::write(proof_path, proof_bytes)?;

            let mut params_bytes = Vec::new();
            public_params.serialize_compressed(&mut params_bytes)?;
            fs::write(params_path, params_bytes)?;
            Ok(())
        }
        Command::Verify {
            proof: proof_path,
            params: params_path,
        } => {
            println!("Using proof: {}", proof_path.display());

            let proof_bytes = fs::read(&proof_path)?;
            let proof = ZkvmProof::<Fr>::deserialize_compressed(&proof_bytes[..])?;

            let params_bytes = fs::read(&params_path)?;
            let public_params =
                ZkvmPublicParameters::<Fr>::deserialize_compressed(&params_bytes[..])?;

            let air = VmAir::<Fr>::default();
            let mut tx = Transcript::new(b"transcript", b"toy_zkvm_cli");

            verify(&proof, &air, &mut tx, &public_params)?;

            println!("Proof verified successfully");
            Ok(())
        }
    }
}
