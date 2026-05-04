use std::path::PathBuf;

use clap::{Parser, Subcommand};

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

        #[arg(long, default_value = "./proof.json")]
        proof: PathBuf,
    },
    Verify {
        #[arg(long)]
        src: PathBuf,

        #[arg(long)]
        proof: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Prove { src, proof } => {
            println!("Proving source:{}", src.display());
            println!("Writing proof to: {}", proof.display());
        }
        Command::Verify { src, proof } => {
            println!("Verifying source:{}", src.display());
            println!("Using proof: {}", proof.display());
        }
    }
}
