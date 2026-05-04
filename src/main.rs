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

        #[arg(long)]
        timing: bool,
    },
    Verify {
        #[arg(long)]
        proof: PathBuf,

        #[arg(long, default_value = "public_params.bin")]
        params: PathBuf,

        #[arg(long)]
        timing: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Prove {
            src,
            proof: proof_path,
            params: params_path,
            timing,
        } => {
            println!("⚡ toy-zkvm — STARK-style proof generation");
            println!("Source: {}", src.display());
            println!("Proof:  {}", proof_path.display());
            println!("Params: {}", params_path.display());

            let total_start = std::time::Instant::now();

            println!("[1/5] Reading source file...");
            let read_start = std::time::Instant::now();
            let src_str = fs::read_to_string(&src)?;
            let read_duration = read_start.elapsed();

            println!("[2/5] Running VM and building execution trace...");
            let trace_start = std::time::Instant::now();
            let trace = run_program_to_trace(&src_str, 256, 256);
            let trace_duration = trace_start.elapsed();

            println!("[3/5] Setting up public parameters...");
            let params_start = std::time::Instant::now();
            let air = VmAir::<Fr>::default();
            let public_params = setup_public_params(trace.n());
            let params_duration = params_start.elapsed();

            println!("[4/5] Generating proof...");
            let prove_start = std::time::Instant::now();
            let mut tx = Transcript::new(b"transcript", b"toy_zkvm_cli");
            let proof = prove(&trace, &air, &mut tx, &public_params)?;
            let prove_duration = prove_start.elapsed();

            println!("[5/5] Writing artifacts...");
            let write_start = std::time::Instant::now();

            let mut proof_bytes = Vec::new();
            proof.serialize_compressed(&mut proof_bytes)?;
            fs::write(&proof_path, proof_bytes)?;

            let mut params_bytes = Vec::new();
            public_params.serialize_compressed(&mut params_bytes)?;
            fs::write(&params_path, params_bytes)?;

            let write_duration = write_start.elapsed();
            let total_duration = total_start.elapsed();

            println!("✔ Proof generated successfully");

            if timing {
                println!();
                println!("Timings");
                println!("  Read source:        {:?}", read_duration);
                println!("  Trace generation:   {:?}", trace_duration);
                println!("  Params setup:       {:?}", params_duration);
                println!("  Proof generation:   {:?}", prove_duration);
                println!("  Artifact writing:   {:?}", write_duration);
                println!("  Total:              {:?}", total_duration);
            }

            Ok(())
        }
        Command::Verify {
            proof: proof_path,
            params: params_path,
            timing,
        } => {
            println!("⚡ toy-zkvm — STARK-style proof verification");
            println!("Proof:  {}", proof_path.display());
            println!("Params: {}", params_path.display());

            let total_start = std::time::Instant::now();

            println!("[1/3] Reading proof and public parameters...");
            let read_start = std::time::Instant::now();

            let proof_bytes = fs::read(&proof_path)?;
            let proof = ZkvmProof::<Fr>::deserialize_compressed(&proof_bytes[..])?;

            let params_bytes = fs::read(&params_path)?;
            let public_params =
                ZkvmPublicParameters::<Fr>::deserialize_compressed(&params_bytes[..])?;

            let read_duration = read_start.elapsed();

            println!("[2/3] Initializing verifier...");
            let setup_start = std::time::Instant::now();
            let air = VmAir::<Fr>::default();
            let mut tx = Transcript::new(b"transcript", b"toy_zkvm_cli");
            let setup_duration = setup_start.elapsed();

            println!("[3/3] Verifying proof...");
            let verify_start = std::time::Instant::now();
            verify(&proof, &air, &mut tx, &public_params)?;
            let verify_duration = verify_start.elapsed();

            let total_duration = total_start.elapsed();

            println!("✔ Proof verified successfully");

            if timing {
                println!();
                println!("Timings");
                println!("  Read artifacts:     {:?}", read_duration);
                println!("  Verifier setup:     {:?}", setup_duration);
                println!("  Verification:       {:?}", verify_duration);
                println!("  Total:              {:?}", total_duration);
            }

            Ok(())
        }
    }
}
