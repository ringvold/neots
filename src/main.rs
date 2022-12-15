
use rpassword::read_password;
use clap::{Parser, Subcommand};
use std::io::{Write};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce, Error
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = Some("Encrypts a secret and makes it available for sharing via one-time URL.

The secret is stored encrypted for a specified duration which can range
from 5 minutes to 7 days (default is 24 hours). The secret gets deleted
from the server upon retrieval therefore can only be viewed once.

"))]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    // Configuration file
    #[arg(short, long, default_value = "~/ots.yaml")]
    config: Option<String>,
}

#[derive(Subcommand)]
#[derive(Debug)]
enum Commands {
    /// Create end-to-end encrypted secret
    New {
        /// The duration of the secret after which it will be deleted from the server. Supported units: s,m,h (default 24h0m0s)
        #[arg(short, value_name = "x", long, value_name = "DURATION", default_value = "14h")]
        expiration: Option<String>
    },
}

fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::New { expiration } => new(expiration),
    }

}


fn new(_expiration: Option<String>) {
    println!("");
    println!("Enter your secret:");
    std::io::stdout().flush().unwrap();
    let secret = read_password().unwrap();
    println!("Secret: {}", secret);
    println!("Encrypting..");
    println!("Sike! Must implement first");
}

fn encrypt(secret: String) -> Result<Vec<u8>, Error> {
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
    return cipher.encrypt(&nonce, b"plaintext message".as_ref());
}
