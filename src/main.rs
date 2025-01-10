use crate::cli::{Cli, Commands};
use clap::Parser;
use crate::cipher::Cipher;

mod cli;
mod cipher;
mod errors;

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Encrypt(encrypt_args) => {
            Cipher::build(
                &encrypt_args.input,
                true,
                &encrypt_args.key_path,
                &encrypt_args.output,
            ).unwrap();
        }
        Commands::Decrypt(decrypt_args) => {}
    }
}
