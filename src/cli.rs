use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[clap(
    author = "Stepan Kolesnikov",
    version = "0.1.0",
    about = "CS-Cipher encrypt/decrypt cli tool",
)]
pub struct Cli {
    /// Subcommand to run
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt files or directories
    Encrypt(EncryptArgs),
    /// Decrypt files or directories
    Decrypt(DecryptArgs),
}

#[derive(Args)]
pub struct EncryptArgs {
    /// Input file or directory
    #[clap(short, long)]
    pub input: PathBuf,
    /// Output file or directory
    #[clap(short, long)]
    pub output: PathBuf,
    /// Path to file with key. If empty or does not exist, it will be generated
    #[clap(short, long)]
    pub key_path: Option<PathBuf>,
}

#[derive(Args)]
pub struct DecryptArgs {
    /// Input file or directory
    #[clap(short, long)]
    pub input: PathBuf,
    /// Output file or directory
    #[clap(short, long)]
    pub output: PathBuf,
    /// Path to file with key
    #[clap(short, long)]
    pub key_path: PathBuf,
}
